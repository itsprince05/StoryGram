import base64
import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager

import bcrypt
import jwt
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from config import settings

_pool: ConnectionPool | None = None


def init_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        if not settings.DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not set")
        _pool = ConnectionPool(settings.DATABASE_URL, min_size=1, max_size=8, open=False,
                               kwargs={"row_factory": dict_row, "prepare_threshold": None, "autocommit": True})
        _pool.open(wait=True, timeout=30)
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


def now() -> int:
    return int(time.time())


@contextmanager
def conn():
    with init_pool().connection() as c:
        yield c


@contextmanager
def tx():
    with init_pool().connection() as c:
        with c.transaction():
            yield c


def one(c, sql: str, params=()):
    return c.execute(sql, params).fetchone()


def all_(c, sql: str, params=()):
    return c.execute(sql, params).fetchall()


def ensure_seed() -> None:
    with conn() as c:
        # first run only: with several versions that can each be switched on / off, a deleted row must stay deleted
        c.execute("insert into app (version, status, username, created) select '1','active','index_guide',%s "
                  "where not exists (select 1 from app)", (now(),))
        if one(c, "select count(*) as n from admins")["n"] == 0 and settings.OWNER_PASSWORD:
            h = bcrypt.hashpw(settings.OWNER_PASSWORD.encode(), bcrypt.gensalt()).decode()
            c.execute("insert into admins (name, username, password, role, status, created) values (%s,%s,%s,'owner','active',%s)",
                      (settings.OWNER_NAME, settings.OWNER_USERNAME, h, now()))


SESSION_COOKIE = "storyloot_session"


def require_api_key(request: Request) -> None:
    provided = ""
    for k, v in request.headers.items():
        if k.lower() in ("x-api-key", "x_api_key", "api-key"):
            provided = v.strip()
            break
    if not provided:
        provided = request.query_params.get("api_key", "").strip()
    expected = settings.API_SECRET_KEY
    if not expected or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized API request")


def issue_session(uid: str, email: str, name: str = "", photo: str = "", device: str = "") -> str:
    t = int(time.time())
    return jwt.encode({"sub": uid or email, "uid": uid, "email": email, "name": name, "photo": photo, "dev": device, "iat": t,
                       "exp": t + settings.SESSION_DAYS * 86400, "typ": "app"}, settings.SESSION_SECRET, algorithm="HS256")


def read_session(request: Request) -> dict | None:
    token = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if not token:
        token = request.cookies.get(SESSION_COOKIE)
    if not token or not settings.SESSION_SECRET:
        return None
    try:
        data = jwt.decode(token, settings.SESSION_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if data.get("typ") != "app":
        return None
    bound, sent = data.get("dev") or "", clean(request.headers.get("x-device-id"))
    if bound and sent and bound != sent:   # a stolen session token does not work from another phone
        return None
    return data


def verify_firebase_token(id_token: str) -> dict:
    from google.auth.transport import requests as g_requests
    from google.oauth2 import id_token as g_id_token

    return g_id_token.verify_firebase_token(id_token, g_requests.Request(), audience=settings.FIREBASE_PROJECT_ID)


_seen_nonces: dict[str, float] = {}


def transport_enabled() -> bool:
    return bool(settings.SIGN_KEY)


def _aes():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(hashlib.sha256(settings.SIGN_KEY.encode()).digest())


def _unb64(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/").strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def decrypt_payload(packed: str) -> str | None:
    try:
        iv, tag, enc = packed.strip().split(".")
        return _aes().decrypt(_unb64(iv), _unb64(enc) + _unb64(tag), None).decode()
    except Exception:
        return None


def encrypt_payload(plain: str) -> str:
    iv = os.urandom(12)
    out = _aes().encrypt(iv, plain.encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return f"{b(iv)}.{b(out[-16:])}.{b(out[:-16])}"


_bad: dict[str, list[float]] = {}
_blocked: dict[str, float] = {}
_hits: dict[str, list[float]] = {}


def too_many(key: str, limit: int, window: int) -> bool:
    """Sliding-window counter: True once `key` has made more than `limit` calls in the last `window` seconds."""
    t = time.time()
    if len(_hits) > 20000:
        for k in [k for k, v in _hits.items() if not v or v[-1] < t - 3600]:
            _hits.pop(k, None)
    arr = [x for x in _hits.get(key, []) if x > t - window]
    arr.append(t)
    _hits[key] = arr
    return len(arr) > limit


def _reject(request: Request, why: str) -> None:
    """Every failed signature looks the same from outside; 15 failures in 10 minutes block the address for 15 minutes."""
    ip = client_ip(request)
    t = time.time()
    if len(_bad) > 20000:
        _bad.clear()
    hits = [x for x in _bad.get(ip, []) if x > t - 600] + [t]
    _bad[ip] = hits
    if len(hits) >= 15:
        _blocked[ip] = t + 900
    print("rejected request:", why, request.method, request.url.path, ip)
    raise HTTPException(status_code=401, detail="Unauthorized")


async def check_signature(request: Request) -> None:
    """Only the app can pass: HMAC over method, path, time, nonce, sha256(body) and device id, a fresh nonce, and an encrypted body."""
    if not transport_enabled():
        return
    if _blocked.get(client_ip(request), 0) > time.time():
        raise HTTPException(status_code=429, detail="Too many requests")
    t = request.headers.get("x-sl-t", "")
    nonce = request.headers.get("x-sl-n", "")
    sig = request.headers.get("x-sl-s", "")
    if not (t.isdigit() and 8 <= len(nonce) <= 64 and sig):
        _reject(request, "missing signature")
    if abs(time.time() * 1000 - int(t)) > 5 * 60 * 1000:
        _reject(request, "stale")
    body = await request.body()
    if body and request.headers.get("x-sl-req-enc") != "1":
        _reject(request, "plain body")
    path = "/" + "/".join(p for p in request.url.path.split("/") if p) if request.url.path.strip("/") else "/"
    device = clean(request.headers.get("x-device-id"))
    msg = f"{request.method.upper()}:{path}:{t}:{nonce}:{hashlib.sha256(body).hexdigest()}:{device}"
    expect = hmac.new(settings.SIGN_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        _reject(request, "bad signature")
    cutoff = time.time() - 600
    if len(_seen_nonces) > 5000:
        for k in [k for k, v in _seen_nonces.items() if v < cutoff]:
            _seen_nonces.pop(k, None)
    if nonce in _seen_nonces and _seen_nonces[nonce] >= cutoff:
        _reject(request, "replay")
    _seen_nonces[nonce] = time.time()


async def read_payload(request: Request) -> dict:
    raw = (await request.body()).decode("utf-8", "ignore").strip()
    data = None
    if raw:
        if request.headers.get("x-sl-req-enc") == "1":
            raw = decrypt_payload(raw) or ""
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
    if data is None:
        try:
            data = dict(await request.form())
        except Exception:
            data = {}
    return data if isinstance(data, (dict, list)) else {}


def respond(request: Request, data: dict, status: int = 200) -> Response:
    if transport_enabled() and "1" in (request.headers.get("x-sl-req-enc"), request.headers.get("x-sl-res-enc")):
        return Response(encrypt_payload(json.dumps(data, ensure_ascii=False)), status_code=status,
                        media_type="text/plain", headers={"x-sl-encrypted": "1"})
    return JSONResponse(data, status_code=status)


def clean(v) -> str:
    return str(v).strip() if v is not None else ""


def first(d: dict, *keys, default=""):
    for k in keys:
        if k in d and d[k] is not None and clean(d[k]) != "":
            return clean(d[k])
    return default


def client_ip(request) -> str:
    h = request.headers
    raw = h.get("cf-connecting-ip") or h.get("x-forwarded-for") or h.get("client-ip") or (request.client.host if request.client else "")
    return raw.split(",")[0].strip()


def device_info(request, d: dict) -> dict:
    h = request.headers

    def pick(*keys, header=None):
        return first(d, *keys) or (clean(h.get(header)) if header else "")
    return {
        "device": pick("device", "deviceId", "device_id", header="x-device-id"),
        "manufacturer": pick("manufacturer", "device_manufacturer", header="x-app-manufacturer") or None,
        "brand": pick("brand", "device_brand", header="x-app-brand") or None,
        "model": pick("model", "device_model", header="x-app-model") or None,
        "version": pick("version", "app_version", header="x-app-version"),
    }


def find_buyer(c, uid: str, email: str):
    if email and uid:
        return one(c, "select * from buyers where email = %s or uid = %s limit 1", (email, uid))
    if email:
        return one(c, "select * from buyers where email = %s limit 1", (email,))
    if uid:
        return one(c, "select * from buyers where uid = %s limit 1", (uid,))
    return None


def record_entry(c, e: dict, status: str, t: int) -> None:
    """One row per app open (no de-duplication), so the admin sees every visit and its result."""
    sql = ("insert into entries (uid, name, email, photo, device, manufacturer, brand, model, ip, status, created) "
           "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)")
    row = [e["uid"], e["name"], e["email"], e["photo"], e["device"], e["manufacturer"], e["brand"], e["model"], e["ip"], status, t]
    try:
        c.execute(sql, row)
    except Exception as exc:
        print("entries log failed:", exc)
        if status == "login":   # the table still has the old status list (run supabase.sql): keep the visit as "active"
            try:
                row[9] = "active"
                c.execute(sql, row)
            except Exception as exc2:
                print("entries log retry failed:", exc2)


def known_photo(c, uid: str, email: str) -> str:
    """Last non-empty photo url stored for this user (buyers first, then earlier entries)."""
    for table in ("buyers", "entries"):
        for col, val in (("email", email), ("uid", uid)):
            if not val:
                continue
            r = one(c, f"select photo from {table} where {col} = %s and coalesce(photo, '') <> '' order by id desc limit 1", (val,))
            if r and r["photo"]:
                return r["photo"]
    return ""


def _user(b: dict | None, e: dict, status: str, language="hindi", validity=0) -> dict:
    out = {"uid": e["uid"], "name": e["name"], "email": e["email"], "photo": e["photo"], "device": e["device"],
           "status": status, "validity": validity}
    if b:
        out.update({"id": b["id"], "uid": b["uid"] or e["uid"], "email": b["email"] or e["email"],
                    "device": b["device"], "language": language})
    return out


def has_access(c, uid: str, email: str, device: str) -> bool:
    b = find_buyer(c, uid, email)
    if not b or b["status"] != "active":
        return False
    validity = int(b["validity"] or 0)
    if validity > 0 and now() > validity:
        return False
    real_device = bool(device) and not device.startswith("UNKNOWN_DEVICE_")
    return not (b["device"] and real_device and b["device"] != device)


def admin_username(raw) -> str:
    """Contact-admin name shown in the app. Empty / null / NULL (any case) => "" => the app hides the admin section."""
    name = clean(raw).lstrip("@").strip()
    return "" if name.lower() in ("", "null", "none") else name


def app_gate(c, version: str):
    """(row that governs this app build, newest enabled row, update needed). Every row in `app` is an app version that can
    be enabled or disabled on its own: a build runs only while its own version is enabled. A build that sends no version
    (or an empty table) is let through, and then the newest enabled row supplies the admin name."""
    rows = all_(c, "select version, status, username from app order by id desc")
    enabled = [r for r in rows if r["status"] == "active"]
    latest = enabled[0] if enabled else None
    if not rows or not version:
        return latest, latest, False
    mine = next((r for r in enabled if clean(r["version"]) == version), None)
    return mine, latest, mine is None


def evaluate(c, d: dict, dev: dict, ip: str, source: str = "open") -> tuple[dict, int]:
    """source: "open" = the user opened / signed in to the app (every outcome is logged; a clean open is recorded as "login"),
    "periodic" = the 5-minute re-check (logged only when access is denied), "none" = never logged."""
    t = now()
    uid = first(d, "uid", "userId", "user_id", "google_id")
    email = first(d, "email")
    name = first(d, "name", default="User")
    photo = first(d, "photo", "photoUrl", "photo_url")
    if not email and not uid:
        return {"success": False, "status": "invalid_request", "error": "User ID or Email is required"}, 400

    if not photo:
        photo = known_photo(c, uid, email)
    device = dev["device"] or ("UNKNOWN_DEVICE_" + hashlib.md5((uid or email).encode()).hexdigest()[:12])
    e = {"uid": uid, "name": name, "email": email, "photo": photo, "device": device, "ip": ip,
         "manufacturer": dev["manufacturer"], "brand": dev["brand"], "model": dev["model"]}

    app, latest, outdated = app_gate(c, dev["version"])
    username = admin_username(app["username"]) if app else ""
    if outdated:
        # this build's version is disabled (or unknown): the user has to update
        return {"success": False, "status": "update_required", "message": "Update App",
                "db_version": clean(latest["version"]) if latest else "", "app_version": dev["version"],
                "username": admin_username(latest["username"]) if latest else "",
                "user": {"uid": uid, "name": name, "email": email, "photo": photo, "device": device,
                         "status": "blocked", "validity": 0}}, 200

    def log(status):
        if source != "none":
            record_entry(c, e, status, t)

    b = find_buyer(c, uid, email)
    if not b:
        log("pending")
        return {"success": False, "status": "pending", "message": "No Access", "username": username,
                "user": _user(None, e, "pending")}, 200

    e["uid"] = b["uid"] or uid
    e["email"] = b["email"] or email
    e["name"] = name if (name and name != "User") else (b["name"] or name)
    e["photo"] = photo or b["photo"] or ""
    if e["photo"] and e["photo"] != (b["photo"] or ""):
        try:
            c.execute("update buyers set photo=%s where id=%s", (e["photo"], b["id"]))
        except Exception:
            pass
    language = (b["language"] or "hindi").lower().strip()
    validity = int(b["validity"] or 0)
    registered = b["device"]

    def deny(status, message, **extra):
        log(status)
        user_status = extra.pop("user_status", status)
        return {"success": False, "status": status, "message": message, "username": username, **extra,
                "user": _user(b, e, user_status, language, validity)}, 200

    if b["status"] == "blocked":
        return deny("blocked", "Access Blocked")

    real_device = bool(device) and not device.startswith("UNKNOWN_DEVICE_")
    if registered and real_device and registered != device:
        return deny("multiple", "Device Not Matched", registered_device=registered, current_device=device)

    if not registered and real_device:
        try:
            c.execute("update buyers set device=%s, manufacturer=%s, brand=%s, model=%s, updated=%s where id=%s",
                      (device, dev["manufacturer"], dev["brand"], dev["model"], t, b["id"]))
            b = {**b, "device": device}
        except Exception:
            pass

    if b["status"] == "expired" or (validity > 0 and t > validity):
        return deny("expired", "Validity Expired", validity=validity)

    if b["status"] != "active":
        return deny("pending", "No Access", user_status=b["status"])

    final_lang = first(d, "language").lower() or language
    try:
        c.execute("update buyers set uid=%s, name=%s, photo=%s, language=%s, updated=%s where id=%s",
                  (uid or b["uid"], e["name"], e["photo"], final_lang, t, b["id"]))
        language = final_lang
    except Exception:
        pass
    if source == "open":
        log("login")
    return {"success": True, "status": "active", "message": "Access granted successfully.", "username": username,
            "language": language, "validity": validity, "user": _user(b, e, "active", language, validity)}, 200
