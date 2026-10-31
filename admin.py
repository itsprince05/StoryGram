import time
from pathlib import Path

import bcrypt
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

import core
from config import settings
from core import read_payload

router = APIRouter()
COOKIE = "storygram_admin"
HERE = Path(__file__).resolve().parent

VALIDITY = {"1_hour": 3600, "1_day": 86400, "1_week": 7 * 86400, "1_month": 30 * 86400,
            "3_months": 90 * 86400, "6_months": 180 * 86400}


def _check_password(plain: str, stored: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), stored.replace("$2y$", "$2b$", 1).encode())
    except ValueError:
        return False


def _issue(admin: dict) -> str:
    now = int(time.time())
    return jwt.encode({"sub": str(admin["id"]), "name": admin["name"] or "Admin", "username": admin["username"],
                       "role": admin["role"], "iat": now, "exp": now + settings.ADMIN_SESSION_SECONDS, "typ": "admin"},
                      settings.ADMIN_JWT_SECRET, algorithm="HS256")


def _current_admin(request: Request, c) -> dict | None:
    token = request.cookies.get(COOKIE)
    if not token or not settings.ADMIN_JWT_SECRET:
        return None
    try:
        p = jwt.decode(token, settings.ADMIN_JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if p.get("typ") != "admin":
        return None
    row = core.one(c, "select id, name, username, role, status from admins where id=%s", (int(p["sub"]),))
    if not row or row["status"] == "blocked":
        return None
    return row


def _stats(c, t: int) -> dict:
    hide = settings.HIDDEN_UIDS
    ex = " and (uid is null or not (uid = any(%s)))" if hide else ""
    a = (hide,) if hide else ()
    def n(sql, *p):
        return core.one(c, sql, p)["n"]
    return {
        "entries": n(f"select count(*) n from entries where true{ex}", *a),
        "entries_pending": n(f"select count(*) n from entries where status='pending'{ex}", *a),
        "entries_expired": n(f"select count(*) n from entries where status='expired'{ex}", *a),
        "entries_multiple": n(f"select count(*) n from entries where status='multiple'{ex}", *a),
        "entries_blocked": n(f"select count(*) n from entries where status='blocked'{ex}", *a),
        "buyers": n(f"select count(*) n from buyers where true{ex}", *a),
        "active": n(f"select count(*) n from buyers where status='active' and (validity=0 or validity>=%s){ex}", t, *a),
        "expired": n(f"select count(*) n from buyers where status='active' and validity>0 and validity<%s{ex}", t, *a),
        "blocked": n(f"select count(*) n from buyers where status='blocked'{ex}", *a),
    }


def _admins(c):
    return core.all_(c, "select id, name, username, role, status, created from admins where role <> 'owner' order by id desc")


def _apps(c):
    return core.all_(c, "select * from app order by id desc")


def _latest_device_info(c, email: str, uid: str):
    return core.one(
        c, "select manufacturer, brand, model from entries where (email=%s or uid=%s) and "
           "(manufacturer is not null or brand is not null or model is not null) order by id desc limit 1", (email, uid))


@router.get("/admin")
async def admin_page():
    return FileResponse(HERE / "admin.html", headers={"Cache-Control": "no-store"})


@router.post("/admin/login")
async def login(request: Request):
    d = await read_payload(request)
    user = core.clean(d.get("username")).lower().lstrip("@")
    pw = d.get("password") or ""
    with core.conn() as c:
        row = core.one(c, "select * from admins where username=%s", (user,)) if user and pw else None
        if row and row["status"] == "blocked":
            return JSONResponse({"success": False, "message": "Your access is blocked"}, 403)
        if not row or not _check_password(pw, row["password"]):
            return JSONResponse({"success": False, "message": "Invalid username or password"}, 401)
    r = JSONResponse({"success": True, "name": row["name"], "role": row["role"]})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    r.set_cookie(COOKIE, _issue(row), max_age=settings.ADMIN_SESSION_SECONDS, httponly=True, secure=https,
                 samesite="strict", path="/admin")
    return r


@router.post("/admin/logout")
async def logout():
    r = JSONResponse({"success": True})
    r.delete_cookie(COOKIE, path="/admin")
    return r


@router.api_route("/admin/api", methods=["GET", "POST"])
async def api(request: Request):
    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        return JSONResponse({"success": False, "error": "Forbidden"}, 403)
    d = await read_payload(request)
    d = {**dict(request.query_params), **(d if isinstance(d, dict) else {})}
    action = core.clean(d.get("api") or d.get("action"))
    t = core.now()

    with core.conn() as c:
        me = _current_admin(request, c)
        if not me:
            return JSONResponse({"success": False, "error": "Session expired. Please log in again.", "logout": True}, 401)
        owner = me["role"] == "owner"
        hide = settings.HIDDEN_UIDS
        ex = " where (uid is null or not (uid = any(%s)))" if hide else ""
        a = (hide,) if hide else ()

        if action == "get_data":
            out = {"success": True, "currentTime": t, "stats": _stats(c, t),
                   "me": {"id": me["id"], "name": me["name"], "username": me["username"], "role": me["role"]},
                   "entries": core.all_(c, f"select * from entries{ex} order by id desc limit 200", a),
                   "buyers": core.all_(c, f"select * from buyers{ex} order by updated desc, id desc limit 200", a),
                   "apps": _apps(c)}
            if owner:
                out["admins"] = _admins(c)
            return out

        if action == "add_admin":
            if not owner:
                return {"success": False, "message": "Only Owner can add new admins!"}
            name, username, pw = core.clean(d.get("name")), core.clean(d.get("username")).lower().lstrip("@"), core.clean(d.get("password"))
            if not name: return {"success": False, "message": "Admin name is required"}
            if not username: return {"success": False, "message": "Username is required"}
            if not pw: return {"success": False, "message": "Password is required"}
            if core.one(c, "select id from admins where username=%s", (username,)):
                return {"success": False, "message": f"Username '@{username}' is already taken!"}
            c.execute("insert into admins (name, username, password, role, status, created) values (%s,%s,%s,'admin','active',%s)",
                      (name, username, bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(), t))
            return {"success": True, "message": f"Admin '{name}' (@{username}) added successfully!", "admins": _admins(c)}

        if action == "toggle_admin_status":
            if not owner:
                return {"success": False, "message": "Only Owner can allow or block admin access!"}
            aid = int(d.get("admin_id") or 0)
            target = core.clean(d.get("target_status")).lower()
            target = target if target in ("active", "blocked") else "active"
            if aid <= 0: return {"success": False, "message": "Invalid Admin ID"}
            if aid == me["id"] and target == "blocked":
                return {"success": False, "message": "You cannot block your own logged-in account!"}
            row = core.one(c, "select * from admins where id=%s", (aid,))
            if not row: return {"success": False, "message": "Admin account not found!"}
            if row["role"] == "owner" and target == "blocked":
                if core.one(c, "select count(*) n from admins where role='owner' and status='active'")["n"] <= 1:
                    return {"success": False, "message": "Cannot block the only active Owner account!"}
            c.execute("update admins set status=%s where id=%s", (target, aid))
            return {"success": True, "message": f"Admin '{row['name']}' is now " + ("Allowed (Active)" if target == "active" else "Blocked") + "!",
                    "admins": _admins(c)}

        if action == "delete_admin":
            if not owner:
                return {"success": False, "message": "Only Owner can delete admin accounts!"}
            aid = int(d.get("admin_id") or 0)
            if aid <= 0: return {"success": False, "message": "Invalid Admin ID"}
            if aid == me["id"]: return {"success": False, "message": "You cannot delete your own logged-in account!"}
            row = core.one(c, "select * from admins where id=%s", (aid,))
            if not row: return {"success": False, "message": "Admin account not found!"}
            if row["role"] == "owner" and core.one(c, "select count(*) n from admins where role='owner'")["n"] <= 1:
                return {"success": False, "message": "Cannot delete the only remaining Owner account!"}
            c.execute("delete from admins where id=%s", (aid,))
            return {"success": True, "message": "Admin account deleted successfully!", "admins": _admins(c)}

        if action == "add_app_version":
            version = core.clean(d.get("version"))
            username = core.clean(d.get("username") or "index_guide").lstrip("@").strip() or "index_guide"
            status = core.clean(d.get("status") or "active")
            status = status if status in ("active", "blocked") else "active"
            if not version: return {"success": False, "message": "Version Code is required"}
            if status == "active":
                c.execute("update app set status='blocked'")
            c.execute("insert into app (version, status, username, created) values (%s,%s,%s,%s) "
                      "on conflict (version) do update set status=excluded.status, username=excluded.username",
                      (version, status, username, t))
            return {"success": True, "message": f"Version Code {version} enabled successfully! (Previous active version disabled)",
                    "apps": _apps(c)}

        if action in ("toggle_app_status", "toggle_app_version"):
            app_id = int(d.get("app_id") or 0)
            cur = core.clean(d.get("current_status") or "active")
            target = core.clean(d.get("target_status")) or ("blocked" if cur == "active" else "active")
            version = core.clean(d.get("version"))
            if target == "active":
                c.execute("update app set status='blocked'")
            c.execute("update app set status=%s where " + ("id=%s" if app_id > 0 else "version=%s"),
                      (target, app_id if app_id > 0 else version))
            return {"success": True, "message": "Version status updated to " + ("ENABLED" if target == "active" else "DISABLED"),
                    "target_status": target, "apps": _apps(c)}

        if action == "delete_app_version":
            if not owner:
                return {"success": False, "message": "Only Owner can delete app versions!"}
            app_id = int(d.get("app_id") or 0)
            if app_id > 0:
                c.execute("delete from app where id=%s", (app_id,))
            return {"success": True, "message": "Version deleted successfully!", "apps": _apps(c)}

        if action in ("approve_buyer", "approve_device"):
            email, uid = core.clean(d.get("email")), core.clean(d.get("uid"))
            name, photo, device = core.clean(d.get("name")), core.clean(d.get("photo")), core.clean(d.get("device"))
            mfg, brand, model = (core.clean(d.get(k)) or None for k in ("manufacturer", "brand", "model"))
            existing = core.find_buyer(c, uid, email)
            if action == "approve_buyer":
                secs = VALIDITY.get(core.clean(d.get("duration")) or "1_month", 30 * 86400)
                cur_v = int(d.get("current_validity") or 0)
                validity = (cur_v if cur_v > t else t) + secs
            if existing:
                f_mfg, f_brand, f_model = (mfg or existing["manufacturer"], brand or existing["brand"], model or existing["model"])
                if not (f_mfg or f_brand or f_model):
                    e = _latest_device_info(c, email or existing["email"], uid or existing["uid"] or "")
                    if e: f_mfg, f_brand, f_model = e["manufacturer"], e["brand"], e["model"]
                if action == "approve_buyer":
                    c.execute("update buyers set uid=%s, name=%s, email=%s, photo=%s, device=%s, manufacturer=%s, brand=%s, model=%s, "
                              "status='active', language='hindi', validity=%s, updated=%s where id=%s",
                              (uid or existing["uid"], name or existing["name"], email or existing["email"],
                               photo or existing["photo"], device or existing["device"], f_mfg, f_brand, f_model, validity, t, existing["id"]))
                else:
                    c.execute("update buyers set device=%s, manufacturer=%s, brand=%s, model=%s, uid=%s, name=%s, photo=%s, "
                              "status='active', updated=%s where id=%s",
                              (device or existing["device"], f_mfg, f_brand, f_model, uid or existing["uid"],
                               name or existing["name"], photo or existing["photo"], t, existing["id"]))
            elif email or uid:
                if not (mfg or brand or model):
                    e = _latest_device_info(c, email, uid)
                    if e: mfg, brand, model = e["manufacturer"], e["brand"], e["model"]
                if action == "approve_device":
                    validity = t + 30 * 86400
                c.execute("insert into buyers (uid, name, email, photo, device, manufacturer, brand, model, status, language, validity, created, updated) "
                          "values (%s,%s,%s,%s,%s,%s,%s,%s,'active','hindi',%s,%s,%s)",
                          (uid, name or "User", email, photo, device, mfg, brand, model, validity, t, t))
            msg = f"User {email} approved successfully!" if action == "approve_buyer" else f"Device approved successfully for {email}!"
            out = {"success": True, "message": msg, "email": email, "stats": _stats(c, t)}
            if action == "approve_buyer": out["validity"] = validity
            else: out["device"] = device
            return out

        if action == "unblock_user":
            email, uid = core.clean(d.get("email")), core.clean(d.get("uid"))
            if email or uid:
                c.execute("update buyers set status='active', updated=%s where email=%s or uid=%s", (t, email or None, uid or None))
            return {"success": True, "message": f"User {email} unblocked successfully!", "email": email, "stats": _stats(c, t)}

        if action == "toggle_status":
            bid = int(d.get("buyer_id") or 0)
            new = "blocked" if d.get("current_status") == "active" else "active"
            c.execute("update buyers set status=%s, updated=%s where id=%s", (new, t, bid))
            return {"success": True, "message": f"Buyer status changed to {new}", "buyer_id": bid, "new_status": new, "stats": _stats(c, t)}

        if action == "delete_buyer":
            if not owner:
                return {"success": False, "message": "Only Owner can delete VIP buyers!"}
            bid = int(d.get("buyer_id") or 0)
            c.execute("delete from buyers where id=%s", (bid,))
            return {"success": True, "message": "Buyer deleted successfully!", "buyer_id": bid, "stats": _stats(c, t)}

    return JSONResponse({"success": False, "message": "Unknown action"}, 400)
