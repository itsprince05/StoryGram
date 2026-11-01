import os
import asyncio
import time
import json
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    PORT,
    UPSTREAM_API_URL,
    UPSTREAM_WEB_URL,
    UPSTREAM_HOST,
    UPSTREAM_APP_NAME,
    APP_USER_AGENT,
    DATABASE_URL,
    LICENSE_SERVER_URL,
)

try:
    import asyncpg
except ImportError:
    asyncpg = None

app = FastAPI(title="StoryGram API Gateway", version="2.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_pool: Any = None

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

def is_supabase_configured() -> bool:
    return bool(DATABASE_URL)

async def init_db_pool():
    global db_pool
    if not DATABASE_URL or not asyncpg:
        return
    try:
        db_pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=1,
            max_size=10,
            ssl="require",
            command_timeout=15.0
        )
        print("[DATABASE] Supabase PostgreSQL connection pool initialized successfully.")
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
    except Exception as e:
        print(f"[DATABASE] Supabase connection warning: {str(e)}")

unlocked_memory_cache: Dict[str, Dict[str, Optional[str]]] = {}

async def get_episodes_from_db(story_ids: List[str]) -> Dict[str, Dict[str, Optional[str]]]:
    results: Dict[str, Dict[str, Optional[str]]] = {}
    missing_from_cache: List[str] = []
    for sid in story_ids:
        if sid in unlocked_memory_cache:
            results[sid] = unlocked_memory_cache[sid]
        else:
            missing_from_cache.append(sid)

    if missing_from_cache and db_pool:
        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT story_id, media_url, video_url, number FROM episodes WHERE story_id = ANY($1::text[])",
                    missing_from_cache
                )
                for r in rows:
                    data = {
                        "media_url": r["media_url"] or "",
                        "video_url": r["video_url"],
                        "number": r["number"]
                    }
                    results[r["story_id"]] = data
                    unlocked_memory_cache[r["story_id"]] = data
        except Exception as e:
            print(f"[DATABASE] Query error from episodes table: {e}")

    return results

def save_episodes_to_db_background(episodes_to_save: List[Dict[str, Any]]):
    episodes_to_save = [item for item in episodes_to_save if (item.get("number") or 0) >= 3000]
    if not episodes_to_save:
        return

    for item in episodes_to_save:
        sid = item["story_id"]
        unlocked_memory_cache[sid] = {
            "media_url": item.get("media_url") or "",
            "video_url": item.get("video_url"),
            "number": item.get("number")
        }

    if not db_pool:
        return

    async def _persist():
        try:
            created_ts = int(time.time())
            async with db_pool.acquire() as conn:
                for item in episodes_to_save:
                    nat_seq = item.get("number") or 0
                    updated = await conn.execute(
                        """
                        UPDATE episodes
                        SET media_url = $2, video_url = $3, number = $4
                        WHERE story_id = $1
                        """,
                        item["story_id"],
                        item.get("media_url", ""),
                        item.get("video_url"),
                        nat_seq
                    )
                    if updated == "UPDATE 0":
                        await conn.execute(
                            """
                            INSERT INTO episodes (story_id, number, created, media_url, video_url)
                            VALUES ($1, $2, $3, $4, $5)
                            """,
                            item["story_id"],
                            nat_seq,
                            created_ts,
                            item.get("media_url", ""),
                            item.get("video_url")
                        )
        except Exception as e:
            print(f"[DATABASE] Error saving to episodes table: {e}")

    asyncio.create_task(_persist())

async def unlock_and_fetch_saved_stories(show_id: str, missing_story_ids: List[str], headers: dict) -> Dict[str, Dict[str, Optional[str]]]:
    if not missing_story_ids:
        return {}

    async def subscribe_single(sid: str):
        payload = {
            "action": "subscribe_story",
            "entity_id": show_id,
            "entity_type": "show",
            "progress_action": "",
            "source": "player",
            "story_id": sid
        }
        target_url = f"{UPSTREAM_API_URL}/v2/user_api/user_action.update"
        return await fetch_from_upstream(target_url, headers, method="POST", body=payload)

    sub_tasks = [subscribe_single(sid) for sid in missing_story_ids]
    await asyncio.gather(*sub_tasks)

    feed_url = f"{UPSTREAM_API_URL}/v2/feed_api/get_saved_stories?show_ids={show_id}"
    saved_stories_map: Dict[str, Dict[str, Optional[str]]] = {}

    for attempt in range(3):
        code, res = await fetch_from_upstream(feed_url, headers, method="GET")
        if isinstance(res, dict) and isinstance(res.get("result"), dict):
            st_list = res["result"].get("stories") or []
            if isinstance(st_list, list) and len(st_list) > 0:
                for st in st_list:
                    if isinstance(st, dict) and st.get("story_id"):
                        v_url = st.get("video_url")
                        if not v_url and isinstance(st.get("video_info"), dict):
                            web_info = st["video_info"].get("web")
                            if isinstance(web_info, dict):
                                v_url = web_info.get("video_url")

                        saved_stories_map[st["story_id"]] = {
                            "media_url": st.get("media_url_enc") or st.get("media_url") or "",
                            "video_url": v_url or None
                        }
                if any(sid in saved_stories_map for sid in missing_story_ids):
                    break
        if attempt < 2:
            await asyncio.sleep(0.5)

    return saved_stories_map

@app.on_event("startup")
async def startup_event():
    await init_db_pool()

@app.on_event("shutdown")
async def shutdown_event():
    global db_pool
    if db_pool:
        await db_pool.close()

cached_cookies = ""
cached_token = ""
last_fetch_date = ""
is_refreshing_cookies = False

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

async def fetch_daily_cookies_from_website():
    global cached_cookies, cached_token
    target_urls = [
        UPSTREAM_WEB_URL,
        UPSTREAM_WEB_URL.replace("://", "://www.") if "://" in UPSTREAM_WEB_URL else UPSTREAM_WEB_URL
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,hi;q=0.8"
    }
    for target_url in target_urls:
        if not target_url:
            continue
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                res = await client.get(target_url, headers=headers)
                raw_cookies = res.headers.get_list("set-cookie")
                cookie_list = [c.split(";")[0].strip() for c in raw_cookies if c]

                if cookie_list:
                    cached_cookies = "; ".join(cookie_list)

                for cookie_item in cookie_list:
                    parts = cookie_item.split("=")
                    if len(parts) >= 2:
                        key = parts[0].strip().lower()
                        val = "=".join(parts[1:]).strip()
                        if key in ["auth-token", "auth_token", "token"] or (val.startswith("eyJ") and "." in val):
                            cached_token = val

                body_str = res.text
                import re
                m = re.search(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}", body_str)
                if m:
                    cached_token = m.group(0)

                if cached_token:
                    break
        except Exception as e:
            print(f"[GATEWAY] Failed to fetch daily session from {target_url}: {str(e)}")

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
    raw_token = h.get("authorization") or h.get("auth-token") or h.get("auth") or h.get("x-auth-token") or cached_token or ""
    if raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

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
        "accept-encoding": "gzip",
        "User-Agent": APP_USER_AGENT,
        "device-id": "mobile-web",
        "device_id": "mobile-web",
        "client-ts": "1770000000"
    }
    if raw_token:
        headers["authorization"] = f"Bearer {raw_token}"
        headers["auth-token"] = raw_token
    if cached_cookies:
        headers["Cookie"] = cached_cookies
    return headers

async def fetch_from_upstream(target_url: str, headers: dict, method: str = "GET", body: Any = None):
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            if method.upper() == "GET":
                res = await client.get(target_url, headers=headers)
            elif method.upper() == "POST":
                res = await client.post(
                    target_url,
                    headers=headers,
                    json=body if isinstance(body, dict) else None,
                    content=body if isinstance(body, str) else None
                )
            else:
                res = await client.request(method.upper(), target_url, headers=headers)

            try:
                body_data = res.json()
            except Exception:
                body_data = res.text
            return res.status_code, body_data
        except Exception as e:
            return 502, {"status": 0, "message": f"Upstream connection failed: {str(e)}"}

@app.get("/health")
@app.get("/ping")
@app.get("/supabase/health")
@app.get("/api/supabase/status")
async def health_check():
    return {
        "status": "online",
        "service": "running"
    }

@app.api_route("/home", methods=["GET", "POST"])
@app.api_route("/feed", methods=["GET", "POST"])
@app.api_route("/api/feed", methods=["GET", "POST"])
async def home_feed(request: Request):
    await ensure_daily_session()
    headers = build_upstream_headers(request)
    if not headers.get("authorization"):
        return JSONResponse(status_code=401, content={
            "status": 0,
            "message": "Missing Upstream Authorization token. Pass header 'authorization: Bearer <token>' (or 'auth')",
            "result": []
        })
    h = request.headers
    lang = h.get("language") or h.get("selected_language") or h.get("selected-language") or request.query_params.get("language") or "hindi"
    api_type = h.get("api-type") or h.get("api_type") or request.query_params.get("api_type") or "explore_v2"

    url = f"{UPSTREAM_API_URL}/v2/feed_api/get_feed_data?api_type={api_type}&selected_language={lang}"
    status_code, data = await fetch_from_upstream(url, headers, "GET")

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
                            "show_id": show_id,
                            "show_title": show_title,
                            "show_category_rank": rank,
                            "avg_rating": stats.get("avg_rating") or stats.get("rating"),
                            "total_plays_display": format_plays_display(stats.get("total_plays_display") or stats.get("total_plays") or ""),
                            "image_url": img_url
                        }
                    })

            if entities:
                filtered.append({
                    "module_name": mod.get("module_name") or mod.get("title") or "Featured Audio",
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
    headers = build_upstream_headers(request)
    if not headers.get("authorization"):
        return JSONResponse(status_code=401, content={
            "status": 0,
            "message": "Missing Upstream Authorization token. Pass header 'authorization: Bearer <token>' (or 'auth')",
            "result": {"shows": []}
        })
    h = request.headers
    q = h.get("query") or h.get("q") or h.get("search-query") or request.query_params.get("query") or request.query_params.get("q") or ""
    genre = h.get("genre") or request.query_params.get("genre") or ""
    lang = h.get("language") or h.get("selected_language") or h.get("selected-language") or request.query_params.get("language") or "hindi"

    from urllib.parse import urlencode
    params = urlencode({"query": q, "genre": genre, "selected_language": lang, "language": lang})
    url = f"{UPSTREAM_API_URL}/v3/search/universal.search?{params}"
    status_code, data = await fetch_from_upstream(url, headers, "GET")

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
    h = request.headers
    sid = h.get("show-id") or h.get("show_id") or h.get("showId") or show_id or request.query_params.get("show_id") or ""

    body_data = {}
    if request.method in ["POST", "PUT"]:
        try:
            body_data = await request.json()
        except Exception:
            body_data = {}

    if not sid and isinstance(body_data, dict):
        sid = body_data.get("show_id") or body_data.get("showId") or ""

    if not sid:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id (pass 'show-id' in headers)"})

    headers = build_upstream_headers(request)
    if not headers.get("authorization"):
        return JSONResponse(status_code=401, content={
            "status": 0,
            "message": "Missing Upstream Authorization token. Pass header 'authorization: Bearer <token>' (or 'auth')",
            "result": {}
        })

    raw_ptr = (
        h.get("curr-ptr")
        or h.get("curr_ptr")
        or h.get("currptr")
        or (body_data.get("curr_ptr") if isinstance(body_data, dict) else None)
        or (body_data.get("start_ptr") if isinstance(body_data, dict) else None)
        or request.query_params.get("curr_ptr")
        or request.query_params.get("start_ptr")
        or 0
    )
    try:
        start_ptr = int(raw_ptr)
    except (ValueError, TypeError):
        start_ptr = 0

    from urllib.parse import urlencode

    async def fetch_single_pointer(ptr: int):
        params = urlencode({"show_id": sid, "curr_ptr": str(ptr), "info_level": str(ptr), "page_source": "show_detail"})
        target_url = f"{UPSTREAM_API_URL}/v2/content_api/show.get_details?{params}"
        code, res = await fetch_from_upstream(target_url, headers, "GET")
        return ptr, code, res

    tasks = [fetch_single_pointer(p) for p in range(start_ptr, start_ptr + 10)]
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda x: x[0])

    base_data = None
    status_code = 200
    for ptr, code, res in results:
        if isinstance(res, dict) and res.get("result"):
            base_data = json.loads(json.dumps(res))
            status_code = code
            break

    if not base_data:
        first_code, first_res = results[0][1], results[0][2]
        if isinstance(first_res, dict):
            return JSONResponse(status_code=first_code, content=first_res)
        return Response(content=str(first_res), status_code=first_code)

    primary_show = None
    if isinstance(base_data.get("result"), list) and len(base_data["result"]) > 0 and isinstance(base_data["result"][0], dict):
        primary_show = base_data["result"][0]
    elif isinstance(base_data.get("result"), dict):
        primary_show = base_data["result"]
    elif isinstance(base_data, dict):
        primary_show = base_data

    total_episodes = 0
    if primary_show:
        try:
            total_episodes = int(primary_show.get("episodes_count") or primary_show.get("total_episodes") or 0)
        except (ValueError, TypeError):
            total_episodes = 0

    candidates = ["stories", "episodes", "messages", "items", "episode_list", "track_list"]
    ep_key = None
    if primary_show is not None:
        for cand in candidates:
            if cand in primary_show and isinstance(primary_show[cand], list):
                ep_key = cand
                break
        if not ep_key:
            for k, v in primary_show.items():
                if isinstance(v, list) and k not in ["show_source", "source_show_genre", "show_tropes_v2", "hash_tags"]:
                    ep_key = k
                    break

    all_episodes = []
    seen_ids = set()
    if ep_key:
        for ptr, code, res in results:
            if not isinstance(res, dict):
                continue

            if total_episodes > 0 and ptr >= total_episodes:
                continue

            curr_show = None
            if isinstance(res.get("result"), list) and len(res["result"]) > 0 and isinstance(res["result"][0], dict):
                curr_show = res["result"][0]
            elif isinstance(res.get("result"), dict):
                curr_show = res["result"]
            elif isinstance(res, dict):
                curr_show = res

            if not curr_show:
                continue

            ep_list = curr_show.get(ep_key) or []
            if isinstance(ep_list, list):
                for ep in ep_list:
                    if not isinstance(ep, dict):
                        continue

                    try:
                        seq = int(ep.get("natural_sequence_number") or ep.get("seq_number") or 0)
                    except (ValueError, TypeError):
                        seq = 0

                    if start_ptr > 0 and seq == 1:
                        continue
                    if total_episodes > 0 and seq > total_episodes:
                        continue

                    ep_id = ep.get("story_id") or ep.get("episode_id") or ep.get("id") or ep.get("message_id")
                    if ep_id:
                        if ep_id not in seen_ids:
                            seen_ids.add(ep_id)
                            all_episodes.append(ep)
                    else:
                        all_episodes.append(ep)

    needs_lookup_ids = []
    for ep in all_episodes:
        if not isinstance(ep, dict):
            continue
        seq = ep.get("natural_sequence_number") or ep.get("seq_number") or 0
        ep_id = ep.get("story_id") or ep.get("id") or ep.get("episode_id")
        if ep_id and seq >= 3000:
            needs_lookup_ids.append(ep_id)

    cached_data: Dict[str, Dict[str, Optional[str]]] = {}
    if needs_lookup_ids:
        cached_data = await get_episodes_from_db(needs_lookup_ids)
        still_missing = [
            st_id for st_id in needs_lookup_ids
            if st_id not in cached_data or not cached_data[st_id].get("media_url")
        ]

        story_number_map = {
            (ep.get("story_id") or ep.get("id") or ep.get("episode_id")): (ep.get("natural_sequence_number") or ep.get("seq_number") or 0)
            for ep in all_episodes if isinstance(ep, dict)
        }

        to_save = []
        if still_missing:
            unlocked_data = await unlock_and_fetch_saved_stories(sid, still_missing, headers)
            for st_id, val in unlocked_data.items():
                cached_data[st_id] = val
                if val.get("media_url") or val.get("video_url"):
                    to_save.append({
                        "story_id": st_id,
                        "number": int(story_number_map.get(st_id, 0)),
                        "media_url": val.get("media_url") or "",
                        "video_url": val.get("video_url")
                    })

        saved_ids = {x["story_id"] for x in to_save}
        for st_id in needs_lookup_ids:
            if st_id in cached_data and st_id not in saved_ids:
                curr_nat_seq = int(story_number_map.get(st_id, 0))
                db_num = cached_data[st_id].get("number")
                if curr_nat_seq and (db_num is None or db_num == 0 or db_num != curr_nat_seq):
                    to_save.append({
                        "story_id": st_id,
                        "number": curr_nat_seq,
                        "media_url": cached_data[st_id].get("media_url") or "",
                        "video_url": cached_data[st_id].get("video_url")
                    })

        if to_save:
            save_episodes_to_db_background(to_save)

    formatted_stories = []
    for ep in all_episodes:
        if not isinstance(ep, dict):
            continue

        ep_id = ep.get("story_id") or ep.get("id") or ep.get("episode_id") or ""
        try:
            seq = int(ep.get("natural_sequence_number") or ep.get("seq_number") or 0)
        except (ValueError, TypeError):
            seq = 0
        if not seq:
            seq = 1

        if start_ptr > 0 and seq == 1:
            continue

        if ep_id in cached_data and cached_data[ep_id].get("media_url"):
            media_url = cached_data[ep_id]["media_url"]
            video_url = cached_data[ep_id].get("video_url")
            audio_url = None
        else:
            raw_video_info = ep.get("video_info")
            web_video_url = None
            if isinstance(raw_video_info, dict):
                web_info = raw_video_info.get("web")
                if isinstance(web_info, dict):
                    web_video_url = web_info.get("video_url")

            old_video_url = ep.get("video_url")
            audio_url = None
            if old_video_url:
                if "vp9_output.mpd" in old_video_url:
                    audio_url = old_video_url.replace("vp9_output.mpd", "audio.mp4")
                elif "/" in old_video_url:
                    url_without_query = old_video_url.split("?")[0]
                    base_dir = url_without_query.rsplit("/", 1)[0]
                    query_part = f"?{old_video_url.split('?', 1)[1]}" if "?" in old_video_url else ""
                    audio_url = f"{base_dir}/audio.mp4{query_part}"
                else:
                    audio_url = old_video_url

            video_url = web_video_url if web_video_url else None
            media_url = ep.get("media_url_enc") or ep.get("media_url") or ""

        item = {
            "duration": ep.get("duration", 0),
            "sequence": seq,
            "story_id": ep_id,
            "story_title": ep.get("story_title") or ep.get("title") or "",
            "video_url": video_url,
            "audio_url": audio_url,
            "media_url": media_url,
        }

        formatted_stories.append(item)

    raw_stats = primary_show.get("stats") if (primary_show and isinstance(primary_show.get("stats"), dict)) else {}

    clean_show = {
        "rank": primary_show.get("show_category_rank", 0) if primary_show else 0,
        "plays": raw_stats.get("total_plays", 0),
        "rating": raw_stats.get("avg_rating", 0),
        "episodes": total_episodes if total_episodes > 0 else (len(formatted_stories) if primary_show else len(formatted_stories)),
        "show_title": primary_show.get("show_title") or primary_show.get("title") or "" if primary_show else "",
        "show_id": primary_show.get("show_id") or sid if primary_show else sid,
        "image_url": primary_show.get("image_url") or primary_show.get("cover_url") or "" if primary_show else "",
        "stories": formatted_stories
    }

    return JSONResponse(status_code=status_code, content={
        "status": 1,
        "message": base_data.get("message") or "Result for show details page",
        "result": [clean_show]
    })

show_license_cache: Dict[str, Dict[str, str]] = {}

async def get_or_resolve_upstream_license_url(show_id: str, request: Request) -> Optional[Dict[str, Any]]:
    if show_id in show_license_cache:
        return show_license_cache[show_id]

    headers = build_upstream_headers(request)
    headers["platform"] = "android"
    headers["version-name"] = "9.1.3"
    headers["platform-version"] = "29"
    headers["app-version"] = "2013"
    headers["device-id"] = "mobile-web"
    headers["device_id"] = "mobile-web"
    headers["client-ts"] = "1770000000"
    headers["content-type"] = "application/json;charset=utf-8"

    from urllib.parse import quote
    target_url = f"{UPSTREAM_API_URL}/v2/content_api/show.play_details?show_id={quote(show_id)}"
    status_code, data = await fetch_from_upstream(target_url, headers, "GET")

    if not isinstance(data, dict):
        return None

    blob = data.get("blob") or (data.get("result", {}) if isinstance(data.get("result"), dict) else {}).get("blob") or ""
    message = data.get("message") or "Blob Data"
    ts = data.get("ts")

    license_url = None
    if blob:
        try:
            license_url = decrypt_drm_blob(1770000000, "mobile-web", blob)
        except Exception as e:
            print(f"[LICENSE] Decryption warning for {show_id}: {str(e)}")
            license_url = None
    else:
        license_url = data.get("license_url") or (data.get("result", {}) if isinstance(data.get("result"), dict) else {}).get("license_url")

    if blob or license_url:
        result = {
            "license_url": license_url or "",
            "blob": blob or "",
            "message": message,
            "ts": ts
        }
        show_license_cache[show_id] = result
        return result
    return None

@app.api_route("/license", methods=["GET", "POST"])
@app.api_route("/license/{show_id}", methods=["GET", "POST"])
@app.api_route("/api/license", methods=["GET", "POST"])
@app.api_route("/api/license/{show_id}", methods=["GET", "POST"])
@app.api_route("/widevine-license", methods=["POST"])
@app.api_route("/widevine-license/{show_id}", methods=["POST"])
@app.api_route("/api/widevine-license", methods=["POST"])
@app.api_route("/api/widevine-license/{show_id}", methods=["POST"])
async def handle_widevine_license(request: Request, show_id: Optional[str] = None):
    await ensure_daily_session()
    h = request.headers
    sid = show_id or h.get("show-id") or h.get("show_id") or request.query_params.get("show_id") or ""

    body_data = {}
    if request.method in ["POST", "PUT"]:
        try:
            body_data = await request.json()
        except Exception:
            body_data = {}

    if not sid and isinstance(body_data, dict):
        sid = body_data.get("show_id") or body_data.get("showId") or ""

    if not sid:
        sid = h.get("show-id") or h.get("show_id") or h.get("showid") or request.query_params.get("show_id") or ""
    sid = sid.strip()

    is_raw_widevine_post = (request.method == "POST" and (h.get("content-type") == "application/octet-stream" or request.url.path.endswith("widevine-license")))

    if not is_raw_widevine_post:
        if not sid:
            return JSONResponse(status_code=400, content={"status": 0, "success": False, "message": "Missing show_id"})

        account_id = os.getenv("GUMLET_ACCOUNT_ID", os.getenv("GUMLET_COLLECTION_ID", "")).strip()
        gumlet_secret = os.getenv("GUMLET_SECRET", "").strip()

        license_url = None
        if account_id and gumlet_secret:
            now_ms = int(time.time() * 1000)
            expires = now_ms + (2 * 3600 * 1000)
            rental_duration = 777600
            try:
                secret_bytes = base64.b64decode(gumlet_secret)
            except Exception:
                secret_bytes = gumlet_secret.encode("utf-8")
            string_for_token = f"/{account_id}/{sid}?expires={expires}&rental_duration={rental_duration}"
            token = hmac.new(secret_bytes, string_for_token.encode("utf-8"), hashlib.sha1).hexdigest()
            license_url = f"https://widevine.gumlet.com/licence/{account_id}/{sid}?expires={expires}&rental_duration={rental_duration}&token={token}"
        elif LICENSE_SERVER_URL:
            license_url = LICENSE_SERVER_URL.replace("{show_id}", sid)
        else:
            info = await get_or_resolve_upstream_license_url(sid, request)
            if info and info.get("license_url"):
                license_url = info["license_url"]

        if not license_url:
            return JSONResponse(status_code=404, content={"status": 0, "success": False, "message": "License not available"})

        return JSONResponse(status_code=200, content={
            "status": 1,
            "success": True,
            "message": "License server",
            "license_url": license_url
        })

    target_license_url = h.get("license-url") or h.get("license_url") or request.query_params.get("url")
    if not target_license_url:
        if not sid:
            return JSONResponse(status_code=400, content={"success": False, "error": "Missing show_id or license_url"})
        info = await get_or_resolve_upstream_license_url(sid, request)
        target_license_url = info.get("license_url") if info else None

    if not target_license_url:
        return Response(content="Could not scrape upstream license for show", status_code=404)

    body_bytes = await request.body()
    req_headers = {
        "Content-Type": h.get("content-type") or "application/octet-stream",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    }

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        try:
            upstream_res = await client.post(target_license_url, content=body_bytes, headers=req_headers)
            return Response(
                content=upstream_res.content,
                status_code=upstream_res.status_code,
                media_type=upstream_res.headers.get("content-type", "application/octet-stream"),
                headers={"Access-Control-Allow-Origin": "*"}
            )
        except Exception as e:
            return Response(content=f"Widevine proxy error: {str(e)}", status_code=500)

@app.get("/")
async def root_status(request: Request):
    return {
        "status": "online",
        "service": "running"
    }

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all_handler(request: Request, path_name: str):
    return JSONResponse(status_code=404, content={"success": False, "error": f"Endpoint /{path_name} not found"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
