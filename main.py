import os
import time
import base64
import hmac
import hashlib
import json
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
import bcrypt
from dotenv import load_dotenv

from config import (
    PORT,
    UPSTREAM_API_URL,
    UPSTREAM_WEB_URL,
    UPSTREAM_HOST,
    UPSTREAM_APP_NAME,
    WORKER_PROXY_URL,
    WORKER_ORIGIN,
    WORKER_REFERER,
    APP_USER_AGENT,
    WEB_USER_AGENT,
    DEFAULT_ADMIN_PASSWORD,
    LEGACY_ADMIN_PASSWORD,
    OWNER_UID,
    ADMIN_JWT_SECRET,
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    SUPABASE_ANON_KEY,
    is_supabase_configured,
)

BASE_DIR = Path(__file__).resolve().parent
ADMIN_HTML_PATH = BASE_DIR / "admin.html"

# Decoy 404 response
NGINX_404_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>404 Not Found</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#fff;color:#222;padding:40px 20px;max-width:600px;margin:0 auto;line-height:1.6;}h1{font-size:24px;font-weight:600;color:#111;margin-bottom:8px;border-bottom:1px solid #eaeaea;padding-bottom:12px;}p{font-size:14px;color:#555;margin-bottom:20px;}hr{border:none;border-top:1px solid #eaeaea;margin:20px 0;}address{font-size:12px;color:#888;font-style:normal;}</style></head><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>nginx / 1.24.0</address></body></html>"""

app = FastAPI(title="StoryGram API", version="2.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory caches
user_access_cache: Dict[str, Dict[str, Any]] = {}
user_app_version_cache: Dict[str, str] = {}
rate_limit_map: Dict[str, Dict[str, Any]] = {}
used_nonces: Dict[str, int] = {}
show_metadata_cache: Dict[str, Dict[str, Any]] = {}

cached_cookies = ""
cached_token = ""
last_fetch_date = ""
is_refreshing_cookies = False

def is_supabase_configured() -> bool:
    return bool(SUPABASE_URL and (SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY))

# --------------------------------------------------------------------
# 1. Cryptography & Security Helpers
# --------------------------------------------------------------------
def decrypt_drm_blob(client_ts: int, device_id: str, cipher_base64: str) -> str:
    raw_data = f"{device_id}:{client_ts}".encode("utf-8")
    encoded = base64.b64encode(raw_data).decode("utf-8")
    chars = list(encoded)
    for i in range(0, len(chars) - 1, 2):
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    key_string = "".join(chars)

    cipher_bytes = base64.b64decode(cipher_base64)
    if len(cipher_bytes) < 28:
        raise ValueError(f"Invalid cipher payload length: {len(cipher_bytes)}")

    salt = cipher_bytes[:16]
    iv = cipher_bytes[16:28]
    tag = cipher_bytes[-16:]
    ciphertext = cipher_bytes[28:-16]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
    )
    derived_key = kdf.derive(key_string.encode("utf-8"))

    aesgcm = AESGCM(derived_key)
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext + tag, None)
    return decrypted_bytes.decode("utf-8")

def format_plays_display(val: Any) -> str:
    if val is None or val == "":
        return ""
    if isinstance(val, (int, float)):
        if val <= 0:
            return ""
        if val >= 1e9:
            return f"{val / 1e9:.1f}".rstrip("0").rstrip(".") + "B"
        if val >= 1e6:
            return f"{val / 1e6:.1f}".rstrip("0").rstrip(".") + "M"
        if val >= 1e3:
            return f"{val / 1e3:.1f}".rstrip("0").rstrip(".") + "K"
        return str(val)
    s = str(val).strip()
    if not s:
        return ""
    try:
        num = float(s)
        return format_plays_display(num)
    except ValueError:
        pass
    s = s.replace("plays", "").replace("play", "").replace("Plays", "").strip()
    return "".join(s.split())

def extract_first_header(val: Any) -> str:
    if not val:
        return ""
    if isinstance(val, list):
        val = str(val[0])
    s = str(val).strip()
    if "," in s:
        return s.split(",")[0].strip()
    return s

def get_req_device_id(request: Request, body_data: Optional[dict] = None) -> str:
    h = request.headers
    return extract_first_header(
        h.get("device-id") or h.get("deviceid") or h.get("x-app-device-id") or h.get("device_id") or
        (body_data and (body_data.get("deviceId") or body_data.get("device_id"))) or
        request.query_params.get("deviceId") or ""
    )

def get_req_user_id(request: Request, body_data: Optional[dict] = None) -> str:
    h = request.headers
    return extract_first_header(
        h.get("user-id") or h.get("userid") or h.get("x-app-user-id") or h.get("uid") or h.get("user_id") or
        (body_data and (body_data.get("userId") or body_data.get("user_id") or body_data.get("uid"))) or
        request.query_params.get("userId") or request.query_params.get("uid") or ""
    )

def get_req_email(request: Request, body_data: Optional[dict] = None) -> str:
    h = request.headers
    return extract_first_header(
        h.get("email") or h.get("user-email") or h.get("x-app-user-email") or h.get("useremail") or h.get("user_email") or
        (body_data and body_data.get("email")) or
        request.query_params.get("email") or ""
    ).lower()

def verify_dynamic_signature(request: Request) -> bool:
    # Open mode: allow all requests and curl calls directly
    return True

# --------------------------------------------------------------------
# 2. Supabase PostgREST Direct Async Client
# --------------------------------------------------------------------
def get_supabase_headers() -> Dict[str, str]:
    key = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

async def supabase_query(method: str, path: str, params: Optional[dict] = None, json_data: Optional[Any] = None, prefer: Optional[str] = None):
    if not is_supabase_configured():
        return None
    url = f"{SUPABASE_URL}/rest/v1/{path.lstrip('/')}"
    headers = get_supabase_headers()
    if prefer:
        headers["Prefer"] = prefer

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            res = await client.request(method, url, params=params, json=json_data, headers=headers)
            if res.status_code in (200, 201, 204, 206):
                if res.status_code == 204:
                    return []
                return res.json()
            else:
                print(f"[SUPABASE] Error {res.status_code}: {res.text}")
                return None
        except Exception as e:
            print(f"[SUPABASE] Request exception on {path}: {str(e)}")
            return None

# --------------------------------------------------------------------
# 3. User Entitlement State Machine (Native Python Implementation)
# --------------------------------------------------------------------
async def record_audit_entry(uid: str, name: str, email: str, photo: str, device: str, manufacturer: str, brand: str, model: str, ip: str, status: str):
    if not is_supabase_configured():
        return
    now = int(time.time())
    entry_payload = {
        "uid": uid or None,
        "name": name or "User",
        "email": email,
        "photo": photo or None,
        "device": device,
        "manufacturer": manufacturer or None,
        "brand": brand or None,
        "model": model or None,
        "ip": ip or None,
        "status": status,
        "created": now
    }
    # Insert entry into entries table
    await supabase_query("POST", "entries", json_data=entry_payload)

async def check_user_verification(user_id: str, device_id: str, email: str, request_or_version: Any = None) -> Dict[str, Any]:
    clean_user = (user_id or "").strip()
    clean_email = (email or "").strip().lower()
    clean_device = (device_id or "").strip()

    if not is_supabase_configured():
        return {
            "success": True,
            "access_denied": False,
            "status": "active",
            "message": "Access granted",
            "username": "index_guide",
            "language": "hindi",
            "validity": 0,
            "user": {
                "id": 1,
                "uid": clean_user or "user_default",
                "name": "Active User",
                "email": clean_email or "user@storygram.com",
                "device": clean_device or "device_default",
                "status": "active",
                "language": "hindi",
                "validity": 0
            }
        }

    if not clean_user and not clean_email:
        return {
            "success": False,
            "access_denied": True,
            "status": "pending",
            "message": "No Access",
            "user": {"uid": clean_user, "email": clean_email, "device": clean_device, "status": "pending", "validity": 0}
        }

    now = int(time.time())
    email_cache_key = f"{clean_email}:{clean_device}" if clean_email else None
    user_cache_key = f"{clean_user}:{clean_device}" if clean_user else None

    # Check Memory Cache
    if email_cache_key and email_cache_key in user_access_cache:
        cached = user_access_cache[email_cache_key]
        if cached["expires_at"] > now:
            return cached["result"]

    if user_cache_key and user_cache_key in user_access_cache:
        cached = user_access_cache[user_cache_key]
        if cached["expires_at"] > now:
            return cached["result"]

    # Version Extraction
    req_version = ""
    req_mfg = ""
    req_brand = ""
    req_model = ""

    if isinstance(request_or_version, str):
        req_version = request_or_version.strip()
    elif isinstance(request_or_version, Request):
        h = request_or_version.headers
        req_version = h.get("x-app-version") or h.get("appversion") or h.get("app_version") or ""
        req_mfg = h.get("x-app-manufacturer") or h.get("manufacturer") or ""
        req_brand = h.get("x-app-brand") or h.get("brand") or ""
        req_model = h.get("x-app-model") or h.get("model") or ""

    if not req_version:
        req_version = user_app_version_cache.get(clean_email) or user_app_version_cache.get(clean_device) or user_app_version_cache.get(clean_user) or ""

    if not clean_device:
        clean_device = "UNKNOWN_DEVICE_" + (clean_user or clean_email)[:12]

    # Default App Version & Handle
    app_username = "index_guide"
    if is_supabase_configured():
        app_rows = await supabase_query("GET", "app", params={"status": "eq.active", "order": "id.desc", "limit": 1})
        if app_rows and len(app_rows) > 0:
            app_item = app_rows[0]
            db_version = (app_item.get("version") or "").strip()
            if app_item.get("username"):
                app_username = app_item.get("username").lstrip("@").strip() or "index_guide"

            if db_version and req_version and req_version != db_version:
                return {
                    "success": False,
                    "status": "update_required",
                    "message": "Update App",
                    "db_version": db_version,
                    "app_version": req_version,
                    "username": app_username,
                    "user": {"uid": clean_user, "email": clean_email, "device": clean_device, "status": "blocked", "validity": 0}
                }

    # Query Buyers Table
    buyer = None
    if is_supabase_configured():
        if clean_email and clean_user:
            res = await supabase_query("GET", "buyers", params={"or": f"(email.eq.{clean_email},uid.eq.{clean_user})", "limit": 1})
        elif clean_email:
            res = await supabase_query("GET", "buyers", params={"email": f"eq.{clean_email}", "limit": 1})
        else:
            res = await supabase_query("GET", "buyers", params={"uid": f"eq.{clean_user}", "limit": 1})

        if res and len(res) > 0:
            buyer = res[0]

    # Buyer Not Found -> Pending Status
    if not buyer:
        await record_audit_entry(clean_user, "User", clean_email, "", clean_device, req_mfg, req_brand, req_model, "", "pending")
        result = {
            "success": False,
            "access_denied": True,
            "status": "pending",
            "message": "No Access",
            "username": app_username,
            "user": {"uid": clean_user, "email": clean_email, "device": clean_device, "status": "pending", "validity": 0}
        }
        exp = now + 5
        if email_cache_key: user_access_cache[email_cache_key] = {"result": result, "expires_at": exp}
        return result

    buyer_id = buyer.get("id")
    buyer_uid = buyer.get("uid") or clean_user
    buyer_email = buyer.get("email") or clean_email
    buyer_name = buyer.get("name") or "User"
    buyer_photo = buyer.get("photo") or ""
    buyer_device = buyer.get("device")
    buyer_status = buyer.get("status") or "active"
    buyer_lang = (buyer.get("language") or "hindi").lower().strip()
    buyer_validity = int(buyer.get("validity") or 0)

    # Status: Blocked
    if buyer_status == "blocked":
        await record_audit_entry(buyer_uid, buyer_name, buyer_email, buyer_photo, clean_device, req_mfg, req_brand, req_model, "", "blocked")
        result = {
            "success": False,
            "access_denied": True,
            "status": "blocked",
            "message": "Access Blocked",
            "username": app_username,
            "user": {"id": buyer_id, "uid": buyer_uid, "name": buyer_name, "email": buyer_email, "photo": buyer_photo, "device": buyer_device, "status": "blocked", "language": buyer_lang, "validity": buyer_validity}
        }
        exp = now + 5
        if email_cache_key: user_access_cache[email_cache_key] = {"result": result, "expires_at": exp}
        return result

    is_real_device = clean_device and not clean_device.startswith("UNKNOWN_DEVICE_")

    # Status: Multiple Device Lock
    if buyer_device and is_real_device and buyer_device != clean_device:
        await record_audit_entry(buyer_uid, buyer_name, buyer_email, buyer_photo, clean_device, req_mfg, req_brand, req_model, "", "multiple")
        result = {
            "success": False,
            "access_denied": True,
            "status": "multiple",
            "message": "Device Not Matched",
            "username": app_username,
            "registered_device": buyer_device,
            "current_device": clean_device,
            "user": {"id": buyer_id, "uid": buyer_uid, "name": buyer_name, "email": buyer_email, "photo": buyer_photo, "device": buyer_device, "status": "multiple", "language": buyer_lang, "validity": buyer_validity}
        }
        exp = now + 5
        if email_cache_key: user_access_cache[email_cache_key] = {"result": result, "expires_at": exp}
        return result

    # Auto-bind first device
    if not buyer_device and is_real_device:
        await supabase_query("PATCH", f"buyers?id=eq.{buyer_id}", json_data={
            "device": clean_device,
            "manufacturer": req_mfg or None,
            "brand": req_brand or None,
            "model": req_model or None,
            "updated": now
        })
        buyer_device = clean_device

    # Status: Validity Expired
    if buyer_status == "expired" or (buyer_validity > 0 and now > buyer_validity):
        await record_audit_entry(buyer_uid, buyer_name, buyer_email, buyer_photo, clean_device, req_mfg, req_brand, req_model, "", "expired")
        result = {
            "success": False,
            "access_denied": True,
            "status": "expired",
            "message": "Validity Expired",
            "username": app_username,
            "validity": buyer_validity,
            "user": {"id": buyer_id, "uid": buyer_uid, "name": buyer_name, "email": buyer_email, "photo": buyer_photo, "device": buyer_device, "status": "expired", "language": buyer_lang, "validity": buyer_validity}
        }
        exp = now + 5
        if email_cache_key: user_access_cache[email_cache_key] = {"result": result, "expires_at": exp}
        return result

    # Active Entitlement Granted!
    result = {
        "success": True,
        "access_denied": False,
        "status": "active",
        "message": "Access granted successfully.",
        "username": app_username,
        "language": buyer_lang,
        "validity": buyer_validity,
        "user": {
            "id": buyer_id,
            "uid": buyer_uid,
            "name": buyer_name,
            "email": buyer_email,
            "photo": buyer_photo,
            "device": buyer_device,
            "status": "active",
            "language": buyer_lang,
            "validity": buyer_validity
        }
    }
    exp = now + 120  # 2 minute cache for active users
    if email_cache_key: user_access_cache[email_cache_key] = {"result": result, "expires_at": exp}
    if user_cache_key: user_access_cache[user_cache_key] = {"result": result, "expires_at": exp}
    return result

# --------------------------------------------------------------------
# 4. Upstream Gateway Token & Relay Helper
# --------------------------------------------------------------------
async def fetch_daily_cookies_from_website():
    global cached_cookies, cached_token
    headers = {
        "User-Agent": WEB_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,hi;q=0.8"
    }
    proxy_payload = {
        "url": UPSTREAM_WEB_URL,
        "method": "GET",
        "headers": headers
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            res = await client.post(
                WORKER_PROXY_URL,
                json=proxy_payload,
                headers={
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "Origin": WORKER_ORIGIN,
                    "Referer": WORKER_REFERER,
                    "User-Agent": WEB_USER_AGENT
                }
            )
            data = res.json()
            res_headers = data.get("headers") or {}
            raw_cookie = res_headers.get("set-cookie") or res_headers.get("Set-Cookie") or ""
            body = data.get("body") if data.get("body") is not None else data

            if isinstance(raw_cookie, list):
                cookie_list = [c.split(";")[0].strip() for c in raw_cookie]
            elif isinstance(raw_cookie, str) and raw_cookie:
                cookie_list = [c.split(";")[0].strip() for c in raw_cookie.split(",")]
            else:
                cookie_list = []

            if cookie_list:
                cached_cookies = "; ".join(cookie_list)

            # Extract JWT token
            body_str = body if isinstance(body, str) else json.dumps(body)
            import re
            m = re.search(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}", body_str)
            if m:
                cached_token = m.group(0)
        except Exception as e:
            print(f"[GATEWAY] Failed to fetch daily session: {str(e)}")

async def ensure_daily_session(force: bool = False):
    global last_fetch_date, is_refreshing_cookies
    today = time.strftime("%Y-%m-%d")
    if force or last_fetch_date != today or not cached_token:
        if not is_refreshing_cookies:
            is_refreshing_cookies = True
            try:
                await fetch_daily_cookies_from_website()
                if cached_token:
                    last_fetch_date = today
            finally:
                is_refreshing_cookies = False

def build_upstream_headers(request: Request) -> Dict[str, str]:
    h = request.headers
    token = h.get("authorization") or h.get("auth") or h.get("x-auth-token") or cached_token or ""
    if token and not token.lower().startswith("bearer "):
        token = f"Bearer {token.strip()}"

    lang = h.get("language") or h.get("selected_language") or request.query_params.get("language") or "hindi"

    headers = {
        "Host": UPSTREAM_HOST or "api.media-stream.internal",
        "app-name": UPSTREAM_APP_NAME or "audio_media",
        "platform": "android",
        "content-type": "application/json;charset=utf-8",
        "accept": "application/json",
        "version-name": "9.1.3",
        "platform-version": "29",
        "app-version": "2013",
        "language": lang,
        "authorization": token,
        "accept-encoding": "gzip",
        "User-Agent": APP_USER_AGENT,
        "device-id": "mobile-web",
        "device_id": "mobile-web"
    }
    if cached_cookies:
        headers["Cookie"] = cached_cookies
    return headers

async def fetch_via_worker_proxy(target_url: str, headers: dict, method: str = "GET", body: Any = None):
    proxy_payload = {
        "url": target_url,
        "method": method.upper(),
        "headers": headers
    }
    if method.upper() in ["POST", "PUT", "PATCH"] and body:
        proxy_payload["body"] = body if isinstance(body, str) else json.dumps(body)

    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.post(
            WORKER_PROXY_URL,
            json=proxy_payload,
            headers={
                "Accept": "*/*",
                "Content-Type": "application/json",
                "Origin": WORKER_ORIGIN,
                "Referer": WORKER_REFERER,
                "User-Agent": WEB_USER_AGENT
            }
        )
        data = res.json()
        status_code = data.get("status") or res.status_code or 200
        body_data = data.get("body") if data.get("body") is not None else data
        if isinstance(body_data, str):
            try:
                body_data = json.loads(body_data)
            except Exception:
                pass
        return status_code, body_data

# --------------------------------------------------------------------
# 5. Core Application Endpoints (For Android Native App)
# --------------------------------------------------------------------
@app.get("/health")
@app.get("/ping")
async def health_check():
    return {
        "status": "ok",
        "language": "python",
        "framework": "fastapi",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "supabase_configured": is_supabase_configured()
    }

@app.api_route("/api/user/verify", methods=["GET", "POST"])
@app.api_route("/user/verify", methods=["GET", "POST"])
@app.api_route("/api/user", methods=["GET", "POST"])
@app.api_route("/user", methods=["GET", "POST"])
async def user_verify_endpoint(request: Request):
    body_data = {}
    if request.method == "POST":
        try:
            body_data = await request.json()
        except Exception:
            body_data = {}

    user_id = get_req_user_id(request, body_data)
    device_id = get_req_device_id(request, body_data)
    email = get_req_email(request, body_data)

    h = request.headers
    action = h.get("action") or body_data.get("action") or request.query_params.get("action")
    if action in ["update_language", "language"]:
        new_lang = (h.get("language") or body_data.get("language") or request.query_params.get("language") or "hindi").lower()
        if is_supabase_configured():
            await supabase_query("PATCH", f"buyers?email=eq.{email}", json_data={"language": new_lang, "updated": int(time.time())})
        return {"success": True, "message": "Language updated successfully", "language": new_lang}

    result = await check_user_verification(user_id, device_id, email, request)
    return JSONResponse(status_code=200, content=result)

@app.api_route("/home", methods=["GET", "POST"])
@app.api_route("/feed", methods=["GET", "POST"])
@app.api_route("/api/feed", methods=["GET", "POST"])
async def home_feed(request: Request):
    await ensure_daily_session()
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    headers = build_upstream_headers(request)
    h = request.headers
    lang = h.get("language") or h.get("selected_language") or h.get("selected-language") or request.query_params.get("language") or "hindi"
    api_type = h.get("api-type") or h.get("api_type") or request.query_params.get("api_type") or "explore_v2"

    url = f"{UPSTREAM_API_URL}/v2/feed_api/get_feed_data?api_type={api_type}&selected_language={lang}"
    status_code, data = await fetch_via_worker_proxy(url, headers, "GET")

    if not isinstance(data, dict):
        return Response(content=str(data), status_code=status_code)

    raw_modules = data.get("result") or []
    filtered = []
    if isinstance(raw_modules, list):
        for mod in raw_modules:
            if not isinstance(mod, dict): continue
            raw_entities = mod.get("entities") or []
            entities = []
            for ent in raw_entities:
                if not isinstance(ent, dict) or not ent.get("value"): continue
                val = ent["value"]
                info = val.get("show_info") or val
                show_id = val.get("show_id") or info.get("show_id") or info.get("entity_id") or ""
                show_title = info.get("show_title") or info.get("title") or ""
                img_url = info.get("image_url") or info.get("cover_url") or info.get("gift_url") or ""
                rank = info.get("show_category_rank") or info.get("rank")
                stats = info.get("stats") or {}

                if show_title or show_id:
                    entities.append({
                        "value": {
                            "show_title": show_title,
                            "image_url": img_url,
                            "show_category_rank": rank,
                            "show_id": show_id,
                            "stats": {
                                "avg_rating": stats.get("avg_rating") or stats.get("rating"),
                                "total_plays_display": format_plays_display(stats.get("total_plays_display") or stats.get("total_plays") or "")
                            }
                        }
                    })
            if entities or mod.get("module_name"):
                filtered.append({
                    "module_name": mod.get("module_name") or "",
                    "entities": entities
                })

    return {
        "status": data.get("status", 1),
        "message": data.get("message", "Home feed details"),
        "result": filtered
    }

@app.api_route("/search", methods=["GET", "POST"])
@app.api_route("/api/search", methods=["GET", "POST"])
async def search_shows(request: Request):
    await ensure_daily_session()
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    headers = build_upstream_headers(request)
    h = request.headers
    q = h.get("query") or h.get("q") or h.get("search-query") or request.query_params.get("query") or request.query_params.get("q") or ""
    genre = h.get("genre") or request.query_params.get("genre") or ""
    lang = h.get("language") or h.get("selected_language") or h.get("selected-language") or request.query_params.get("language") or "hindi"

    from urllib.parse import urlencode
    params = urlencode({"query": q, "genre": genre, "selected_language": lang, "language": lang})
    url = f"{UPSTREAM_API_URL}/v3/search/universal.search?{params}"
    status_code, data = await fetch_via_worker_proxy(url, headers, "GET")

    if isinstance(data, dict) and data.get("result") and isinstance(data["result"].get("shows"), list):
        formatted = []
        for show in data["result"]["shows"]:
            show_id = show.get("show_id") or show.get("entity_id") or ""
            stats = show.get("stats") or {}
            formatted.append({
                "show_id": show_id,
                "title": show.get("title") or show.get("show_title") or "",
                "plays": format_plays_display(show.get("plays") or stats.get("total_plays_display") or stats.get("total_plays") or ""),
                "avg_rating": show.get("avg_rating") or stats.get("avg_rating"),
                "image_url": show.get("image_url") or show.get("cover_url") or ""
            })
        return {
            "status": data.get("status", 1),
            "message": data.get("message", "successfully fetched shows"),
            "result": {"shows": formatted}
        }
    return Response(content=json.dumps(data), status_code=status_code, media_type="application/json")

@app.api_route("/show", methods=["GET", "POST"])
@app.api_route("/show/{show_id}", methods=["GET", "POST"])
@app.api_route("/api/show", methods=["GET", "POST"])
@app.api_route("/api/show/{show_id}", methods=["GET", "POST"])
async def show_details(request: Request, show_id: Optional[str] = None):
    await ensure_daily_session()
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    h = request.headers
    sid = h.get("show-id") or h.get("show_id") or h.get("showId") or show_id or request.query_params.get("show_id") or ""
    if not sid:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id (pass 'show-id' in headers)"})

    headers = build_upstream_headers(request)
    start_ptr = int(h.get("curr-ptr") or h.get("curr_ptr") or request.query_params.get("curr_ptr") or 0)
    batch_size = min(max(int(h.get("limit") or request.query_params.get("limit") or 20), 1), 50)

    from urllib.parse import urlencode
    params = urlencode({"show_id": sid, "curr_ptr": str(start_ptr), "info_level": str(start_ptr), "page_source": "show_detail"})
    url = f"{UPSTREAM_API_URL}/v2/content_api/show.get_details?{params}"
    status_code, data = await fetch_via_worker_proxy(url, headers, "GET")

    if not isinstance(data, dict):
        return Response(content=str(data), status_code=status_code)

    return JSONResponse(status_code=status_code, content=data)

@app.api_route("/license", methods=["GET", "POST"])
@app.api_route("/api/license", methods=["GET", "POST"])
@app.api_route("/api/get_license", methods=["GET", "POST"])
async def drm_license(request: Request):
    await ensure_daily_session()
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    h = request.headers
    show_id = h.get("show-id") or h.get("show_id") or h.get("showId") or request.query_params.get("show_id") or ""
    if not show_id:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id (pass 'show-id' in headers)"})

    headers = build_upstream_headers(request)
    headers["platform"] = "android"
    headers["version-name"] = "9.1.3"
    headers["platform-version"] = "29"
    headers["app-version"] = "2013"
    headers["device-id"] = "mobile-web"
    headers["device_id"] = "mobile-web"
    headers["client-ts"] = "1770000000"

    url = f"{UPSTREAM_API_URL}/v2/content_api/show.play_details?show_id={show_id}"
    status_code, data = await fetch_via_worker_proxy(url, headers, "GET")

    if not isinstance(data, dict):
        return JSONResponse(status_code=status_code, content={"success": False, "error": "Invalid response from upstream audio server"})

    blob = data.get("blob")
    if not blob:
        return JSONResponse(status_code=400, content={"success": False, "error": "No DRM blob found in response", "data": data})

    try:
        license_url = decrypt_drm_blob(1770000000, "mobile-web", blob)
        return {"success": True, "license_url": license_url}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": f"Failed to decrypt DRM: {str(e)}"})

@app.post("/widevine-license")
@app.post("/api/widevine-license")
async def widevine_license(request: Request):
    h = request.headers
    target_url = h.get("license-url") or h.get("license_url") or h.get("target-url") or h.get("url") or request.query_params.get("url") or ""
    if not target_url:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing license URL (pass 'license-url' in headers)"})

    body = await request.body()
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post(
            target_url,
            content=body,
            headers={
                "Content-Type": request.headers.get("content-type") or "application/octet-stream",
                "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Mobile Safari/537.36"
            }
        )
        return Response(content=res.content, status_code=res.status_code, media_type="application/octet-stream")

@app.api_route("/api/library", methods=["GET", "POST", "DELETE", "PUT"])
@app.api_route("/library", methods=["GET", "POST", "DELETE", "PUT"])
async def library_sync(request: Request):
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    h = request.headers
    body = {}
    if request.method in ["POST", "PUT", "DELETE"]:
        try:
            body = await request.json()
        except Exception:
            body = {}

    req_action = h.get("req-action") or h.get("req_action") or h.get("type") or body.get("req_action") or body.get("type") or request.query_params.get("req_action")
    action = h.get("action") or body.get("action") or request.query_params.get("action") or "history"
    show_id = h.get("show-id") or h.get("show_id") or body.get("show_id") or ""
    show_name = h.get("show-name") or h.get("show_name") or body.get("show_name") or ""
    show_url = h.get("show-url") or h.get("show_url") or body.get("show_url") or None
    uid = (h.get("uid") or h.get("user-id") or body.get("uid") or user_id or email or "").strip()

    if not req_action and show_id:
        req_action = "record"
    elif not req_action:
        req_action = "list"

    if not uid:
        return JSONResponse(status_code=400, content={"success": False, "error": "uid is required (pass 'user-id' in headers)"})

    if is_supabase_configured():
        now = int(time.time())
        if req_action in ["record", "save"]:
            # Deduplicate
            await supabase_query("DELETE", f"library?uid=eq.{uid}&action=eq.{action}&show_id=eq.{show_id}")
            # Insert
            await supabase_query("POST", "library", json_data={
                "uid": uid,
                "action": action,
                "show_id": show_id,
                "show_name": show_name,
                "show_url": show_url,
                "created": now
            })
            return {"success": True, "message": f"Show recorded to {action} successfully"}

        elif req_action == "list":
            params = {"uid": f"eq.{uid}", "order": "created.desc", "limit": 90}
            if action in ["history", "saved"]:
                params["action"] = f"eq.{action}"
            items = await supabase_query("GET", "library", params=params)
            return {"success": True, "items": items or []}

        elif req_action in ["remove", "delete"]:
            await supabase_query("DELETE", f"library?uid=eq.{uid}&action=eq.{action}&show_id=eq.{show_id}")
            return {"success": True, "message": f"Item removed from {action}"}

        elif req_action in ["clear", "clear_history"]:
            await supabase_query("DELETE", f"library?uid=eq.{uid}&action=eq.{action}")
            return {"success": True, "message": f"All items cleared from {action}"}

    return {"success": True, "items": []}

@app.api_route("/api/resolve_episodes", methods=["GET", "POST"])
@app.api_route("/resolve_episodes", methods=["GET", "POST"])
async def resolve_episodes_endpoint(request: Request):
    user_id = get_req_user_id(request)
    device_id = get_req_device_id(request)
    email = get_req_email(request)

    verify_res = await check_user_verification(user_id, device_id, email, request)
    if not verify_res.get("success"):
        return JSONResponse(status_code=200, content=verify_res)

    h = request.headers
    body = {}
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}

    raw_ids = h.get("story-ids") or h.get("story_ids") or ""
    header_ids = [s.strip() for s in raw_ids.split(",") if s.strip()] if raw_ids else []
    story_ids = header_ids or body.get("story_ids") or (request.query_params.get("story_id") and [request.query_params.get("story_id")]) or []
    out = {}
    if is_supabase_configured() and story_ids:
        # Check cached episodes
        ids_param = ",".join(story_ids)
        cached = await supabase_query("GET", "episodes", params={"story_id": f"in.({ids_param})"})
        if cached:
            for item in cached:
                if item.get("story_id") and item.get("url"):
                    out[item["story_id"]] = item["url"]

    return {
        "success": True,
        "resolved_count": len(out),
        "urls": out
    }

@app.api_route("/unlock", methods=["GET", "POST"])
@app.api_route("/api/unlock", methods=["GET", "POST"])
async def unlock_episode_endpoint(request: Request):
    h = request.headers
    body = {}
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}

    sid = h.get("show-id") or h.get("show_id") or body.get("show_id") or request.query_params.get("show_id") or ""
    ep_id = h.get("episode-id") or h.get("episode_id") or body.get("episode_id") or request.query_params.get("episode_id") or ""
    ep_num = int(h.get("episode-number") or h.get("episode_number") or body.get("episode_number") or request.query_params.get("episode_number") or 1)

    if not sid:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id (pass 'show-id' in headers)"})

    return {
        "success": True,
        "message": "Episode unlocked successfully",
        "show_id": sid,
        "episode_id": ep_id or f"ep_{ep_num}",
        "episode_number": ep_num,
        "stream_url": f"https://stream.audio-cdn.com/audio/{sid}/ep_{ep_num}.m4a",
        "duration": 780
    }

@app.api_route("/unlocked", methods=["GET", "POST"])
@app.api_route("/api/unlocked", methods=["GET", "POST"])
async def unlocked_episodes_endpoint(request: Request):
    h = request.headers
    sid = h.get("show-id") or h.get("show_id") or request.query_params.get("show_id") or ""
    if not sid:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id (pass 'show-id' in headers)"})
    return {
        "success": True,
        "show_id": sid,
        "unlocked_episodes": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    }

@app.api_route("/api/proxy", methods=["GET", "HEAD"])
@app.api_route("/api/proxy/{full_path:path}", methods=["GET", "HEAD"])
async def media_stream_proxy(request: Request, full_path: Optional[str] = None):
    h = request.headers
    target_url = h.get("target-url") or h.get("target_url") or request.query_params.get("url") or full_path or ""
    if not target_url:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing target URL (pass 'target-url' in headers)"})

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    req_headers = {"User-Agent": WEB_USER_AGENT}
    if h.get("range"):
        req_headers["Range"] = h.get("range")

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            upstream_res = await client.get(target_url, headers=req_headers)
            res_headers = {}
            for k in ["content-type", "content-length", "content-range", "accept-ranges"]:
                if k in upstream_res.headers:
                    res_headers[k] = upstream_res.headers[k]
            return Response(
                content=upstream_res.content,
                status_code=upstream_res.status_code,
                headers=res_headers
            )
        except Exception as e:
            return JSONResponse(status_code=502, content={"success": False, "error": f"Proxy request failed: {str(e)}"})

# --------------------------------------------------------------------
# 6. Admin Portal & API Endpoints
# --------------------------------------------------------------------
@app.get("/admin")
@app.get("/admin.php")
async def admin_portal_view(request: Request):
    if not ADMIN_HTML_PATH.exists():
        return JSONResponse({"status": "ok", "message": "Admin & Database managed externally"})
    with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

def verify_admin_jwt(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        return None

@app.post("/admin/login")
async def admin_login(request: Request):
    body = {}
    try:
        body = await request.json()
    except Exception:
        form = await request.form()
        body = dict(form)

    u = (body.get("admin_username") or body.get("username") or "").strip().lower().lstrip("@")
    p = (body.get("admin_password") or body.get("password") or "").strip()

    if not p:
        return JSONResponse(status_code=400, content={"success": False, "message": "Password is required"})

    authenticated = None
    if is_supabase_configured():
        if u:
            rows = await supabase_query("GET", "admins", params={"username": f"eq.{u}", "limit": 1})
            if rows and len(rows) > 0:
                adm = rows[0]
                if adm.get("status") == "blocked":
                    return JSONResponse(status_code=403, content={"success": False, "message": "Your access is blocked"})

                db_pass = adm.get("password") or ""
                is_match = False
                if db_pass.startswith("$2a$") or db_pass.startswith("$2b$"):
                    is_match = bcrypt.checkpw(p.encode("utf-8"), db_pass.encode("utf-8"))
                else:
                    is_match = (db_pass == p)
                if not is_match and adm.get("role") == "owner" and (p in [DEFAULT_ADMIN_PASSWORD, LEGACY_ADMIN_PASSWORD]):
                    is_match = True
                if is_match:
                    authenticated = adm

        if not authenticated and (p in [DEFAULT_ADMIN_PASSWORD, LEGACY_ADMIN_PASSWORD]):
            owner_rows = await supabase_query("GET", "admins", params={"role": "eq.owner", "limit": 1})
            if owner_rows and len(owner_rows) > 0:
                authenticated = owner_rows[0]
            else:
                authenticated = {"id": 1, "name": "Owner", "username": "owner", "role": "owner", "status": "active"}
    else:
        if p in [DEFAULT_ADMIN_PASSWORD, LEGACY_ADMIN_PASSWORD]:
            authenticated = {"id": 1, "name": "Owner", "username": "owner", "role": "owner", "status": "active"}

    if not authenticated:
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid username or password"})

    token_payload = {
        "sub": authenticated["id"],
        "name": authenticated.get("name") or "Admin",
        "username": authenticated.get("username") or "admin",
        "role": authenticated.get("role") or "admin",
        "exp": int(time.time()) + 3600
    }
    token = jwt.encode(token_payload, ADMIN_JWT_SECRET, algorithm="HS256")

    response = JSONResponse(content={
        "success": True,
        "token": token,
        "admin": token_payload
    })
    response.set_cookie("admin_jwt", token, max_age=3600, httponly=False, samesite="lax")
    return response

@app.api_route("/admin/logout", methods=["GET", "POST"])
async def admin_logout(response: Response):
    response.delete_cookie("admin_jwt")
    return {"success": True, "message": "Logged out successfully"}

@app.get("/admin/session")
async def admin_session(request: Request):
    token = request.cookies.get("admin_jwt") or request.headers.get("x-admin-token") or ""
    auth_header = request.headers.get("authorization") or ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    payload = verify_admin_jwt(token)
    if not payload:
        return JSONResponse(status_code=401, content={"success": False, "loggedIn": False})
    return {"success": True, "loggedIn": True, "admin": payload}

@app.api_route("/admin/api", methods=["GET", "POST"])
@app.post("/admin.php")
async def admin_api_dispatch(request: Request):
    token = request.cookies.get("admin_jwt") or request.headers.get("x-admin-token") or ""
    auth_header = request.headers.get("authorization") or ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

    payload = verify_admin_jwt(token)
    if not payload:
        return JSONResponse(status_code=401, content={"success": False, "error": "JWT Token Expired or Invalid", "logout": True})

    is_owner = (payload.get("role") == "owner")

    # Parse body
    body = {}
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            form = await request.form()
            body = dict(form)

    action = body.get("api") or request.query_params.get("api")
    now = int(time.time())

    if action == "get_data":
        entries = await supabase_query("GET", "entries", params={"uid": f"neq.{OWNER_UID}", "order": "id.desc", "limit": 200}) or []
        buyers = await supabase_query("GET", "buyers", params={"uid": f"neq.{OWNER_UID}", "order": "updated.desc", "limit": 200}) or []
        apps = await supabase_query("GET", "app", params={"order": "id.desc"}) or []
        admins = []
        if is_owner:
            admins = await supabase_query("GET", "admins", params={"role": "neq.owner", "order": "id.desc"}) or []

        stats = {
            "entries": len(entries),
            "entries_pending": len([e for e in entries if e.get("status") == "pending"]),
            "entries_expired": len([e for e in entries if e.get("status") == "expired"]),
            "entries_multiple": len([e for e in entries if e.get("status") == "multiple"]),
            "entries_blocked": len([e for e in entries if e.get("status") == "blocked"]),
            "buyers": len(buyers),
            "active": len([b for b in buyers if b.get("status") == "active" and (int(b.get("validity") or 0) == 0 or int(b.get("validity") or 0) >= now)]),
            "expired": len([b for b in buyers if b.get("status") == "active" and int(b.get("validity") or 0) > 0 and int(b.get("validity") or 0) < now]),
            "blocked": len([b for b in buyers if b.get("status") == "blocked"])
        }

        return {
            "success": True,
            "currentTime": now,
            "stats": stats,
            "entries": entries,
            "buyers": buyers,
            "apps": apps,
            "admins": admins if is_owner else []
        }

    elif action == "approve_buyer":
        email = (body.get("email") or "").strip().lower()
        uid = (body.get("uid") or "").strip()
        name = (body.get("name") or "User").strip()
        device = body.get("device")
        validity_opt = body.get("validity_option") or "1_month"
        curr_val = int(body.get("current_validity") or 0)

        duration_map = {
            "1_hour": 3600,
            "1_day": 86400,
            "1_week": 7 * 86400,
            "1_month": 30 * 86400,
            "3_months": 90 * 86400,
            "6_months": 180 * 86400,
            "lifetime": 0
        }
        add_sec = duration_map.get(validity_opt, 30 * 86400)
        new_val = 0
        if add_sec > 0:
            base_t = curr_val if curr_val > now else now
            new_val = base_t + add_sec

        # Upsert buyer
        existing = await supabase_query("GET", "buyers", params={"email": f"eq.{email}", "limit": 1})
        if existing and len(existing) > 0:
            b_id = existing[0]["id"]
            await supabase_query("PATCH", f"buyers?id=eq.{b_id}", json_data={
                "uid": uid or existing[0].get("uid"),
                "name": name if name != "User" else existing[0].get("name"),
                "device": device or existing[0].get("device"),
                "status": "active",
                "validity": new_val,
                "updated": now
            })
        else:
            await supabase_query("POST", "buyers", json_data={
                "uid": uid or None,
                "name": name,
                "email": email,
                "device": device,
                "status": "active",
                "language": "hindi",
                "validity": new_val,
                "created": now,
                "updated": now
            })

        # Update entries to active
        await supabase_query("PATCH", f"entries?email=eq.{email}", json_data={"status": "active"})
        return {"success": True, "message": "Buyer approved and validity updated successfully"}

    elif action == "approve_device":
        bid = body.get("buyer_id") or body.get("id")
        dev = body.get("device")
        await supabase_query("PATCH", f"buyers?id=eq.{bid}", json_data={"device": dev, "updated": now})
        return {"success": True, "message": "Device approved successfully"}

    elif action == "toggle_status":
        bid = body.get("buyer_id") or body.get("id")
        t_status = body.get("target_status")
        if not t_status:
            b_rows = await supabase_query("GET", "buyers", params={"id": f"eq.{bid}", "limit": 1})
            curr_s = b_rows[0].get("status") if b_rows else "active"
            t_status = "blocked" if curr_s == "active" else "active"
        await supabase_query("PATCH", f"buyers?id=eq.{bid}", json_data={"status": t_status, "updated": now})
        return {"success": True, "status": t_status, "message": f"Buyer status updated to {t_status}"}

    elif action == "delete_buyer":
        bid = body.get("buyer_id") or body.get("id")
        await supabase_query("DELETE", f"buyers?id=eq.{bid}")
        return {"success": True, "message": "Buyer removed from database"}

    elif action == "unblock_user":
        target_id = body.get("id")
        target_type = body.get("type") or "entry"
        if target_type == "buyer":
            await supabase_query("PATCH", f"buyers?id=eq.{target_id}", json_data={"status": "active", "updated": now})
        else:
            await supabase_query("PATCH", f"entries?id=eq.{target_id}", json_data={"status": "active"})
        return {"success": True, "message": "User unblocked successfully"}

    elif action == "add_admin":
        if not is_owner:
            return JSONResponse(status_code=403, content={"success": False, "message": "Only Owner can add admins"})
        adm_name = body.get("name", "").strip()
        adm_user = body.get("username", "").strip().lower().lstrip("@")
        adm_pass = body.get("password", "").strip()
        pass_hash = bcrypt.hashpw(adm_pass.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        await supabase_query("POST", "admins", json_data={
            "name": adm_name,
            "username": adm_user,
            "password": pass_hash,
            "role": "admin",
            "status": "active",
            "created": now
        })
        admins = await supabase_query("GET", "admins", params={"role": "neq.owner", "order": "id.desc"}) or []
        return {"success": True, "message": f"Admin '{adm_name}' added successfully!", "admins": admins}

    elif action == "toggle_admin_status":
        if not is_owner:
            return JSONResponse(status_code=403, content={"success": False, "message": "Only Owner can toggle admin status"})
        aid = body.get("admin_id") or body.get("id")
        a_rows = await supabase_query("GET", "admins", params={"id": f"eq.{aid}", "limit": 1})
        new_s = "blocked" if (a_rows and a_rows[0].get("status") == "active") else "active"
        await supabase_query("PATCH", f"admins?id=eq.{aid}", json_data={"status": new_s})
        admins = await supabase_query("GET", "admins", params={"role": "neq.owner", "order": "id.desc"}) or []
        return {"success": True, "status": new_s, "admins": admins}

    elif action == "delete_admin":
        if not is_owner:
            return JSONResponse(status_code=403, content={"success": False, "message": "Only Owner can delete admins"})
        aid = body.get("admin_id") or body.get("id")
        await supabase_query("DELETE", f"admins?id=eq.{aid}")
        admins = await supabase_query("GET", "admins", params={"role": "neq.owner", "order": "id.desc"}) or []
        return {"success": True, "message": "Admin deleted", "admins": admins}

    elif action == "add_app_version":
        v = (body.get("version") or "").strip()
        u = (body.get("username") or "index_guide").strip().lstrip("@")
        existing = await supabase_query("GET", "app", params={"version": f"eq.{v}", "limit": 1})
        if existing and len(existing) > 0:
            await supabase_query("PATCH", f"app?id=eq.{existing[0]['id']}", json_data={"status": "active", "username": u})
        else:
            await supabase_query("POST", "app", json_data={"version": v, "status": "active", "username": u, "created": now})
        apps = await supabase_query("GET", "app", params={"order": "id.desc"}) or []
        return {"success": True, "message": f"App version {v} saved!", "apps": apps}

    elif action == "toggle_app_status":
        appid = body.get("app_id") or body.get("id")
        app_rows = await supabase_query("GET", "app", params={"id": f"eq.{appid}", "limit": 1})
        new_s = "blocked" if (app_rows and app_rows[0].get("status") == "active") else "active"
        await supabase_query("PATCH", f"app?id=eq.{appid}", json_data={"status": new_s})
        apps = await supabase_query("GET", "app", params={"order": "id.desc"}) or []
        return {"success": True, "status": new_s, "apps": apps}

    elif action == "delete_app_version":
        appid = body.get("app_id") or body.get("id")
        await supabase_query("DELETE", f"app?id=eq.{appid}")
        apps = await supabase_query("GET", "app", params={"order": "id.desc"}) or []
        return {"success": True, "message": "App version deleted", "apps": apps}

    return JSONResponse(status_code=400, content={"success": False, "error": f"Unknown action: {action}"})

# --------------------------------------------------------------------
# 7. Fallback & Decoy Handlers
# --------------------------------------------------------------------
@app.get("/")
async def root_status(request: Request):
    return {
        "status": "online",
        "service": "StoryGram API Gateway",
        "version": "2.0.0",
        "framework": "FastAPI (Python)"
    }

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all_handler(request: Request, path_name: str):
    return JSONResponse(status_code=404, content={"success": False, "error": f"Endpoint /{path_name} not found"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
