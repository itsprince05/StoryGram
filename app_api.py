import asyncio

from fastapi import APIRouter, HTTPException, Request

import core
from core import (SESSION_COOKIE, check_signature, issue_session, read_payload, read_session, require_api_key,
                  respond, verify_firebase_token)

router = APIRouter()


@router.post("/api/verify")
async def verify(request: Request):
    check_signature(request)
    d = await read_payload(request)
    id_token = core.clean(d.get("idToken"))
    if not id_token:
        return respond(request, {"success": False, "error": "idToken is required"}, 400)
    try:
        claims = await asyncio.to_thread(verify_firebase_token, id_token)
    except Exception as exc:
        print("firebase verify failed:", exc)
        return respond(request, {"success": False, "error": "Google sign-in could not be verified. Please try again."}, 401)

    uid = claims.get("user_id") or claims.get("sub") or ""
    email = (claims.get("email") or "").lower()
    if not email:
        return respond(request, {"success": False, "error": "Your Google account has no email address"}, 400)
    name = core.clean(d.get("name")) or claims.get("name") or "User"
    photo = core.clean(d.get("photoUrl")) or claims.get("picture") or ""

    payload = {"uid": uid, "email": email, "name": name, "photo": photo, "language": ""}
    with core.conn() as c:
        res, _ = core.evaluate(c, payload, core.device_info(request, d), core.client_ip(request))
    status = res.get("status", "pending")
    user = {"uid": uid, "name": res.get("user", {}).get("name") or name, "email": email,
            "photoUrl": photo, "status": status}
    token = issue_session(uid, email, user["name"])
    return respond(request, {"success": True, "status": status, "token": token, "user": user})


@router.get("/api/user/status")
async def user_status(request: Request):
    check_signature(request)
    s = read_session(request)
    if not s:
        return respond(request, {"success": False, "status": "unauthorized", "error": "Not signed in"}, 401)
    payload = {"uid": s.get("uid", ""), "email": s.get("email", ""), "name": s.get("name", "")}
    with core.conn() as c:
        res, _ = core.evaluate(c, payload, core.device_info(request, {}), core.client_ip(request))
    if res.get("success"):
        u = res["user"]
        res["user"] = {**u, "photo": u.get("photo", "")}
        return respond(request, res, 200)
    return respond(request, res, 403)


@router.post("/api/user/language")
async def set_language(request: Request):
    check_signature(request)
    s = read_session(request)
    if not s:
        return respond(request, {"success": False, "error": "Not signed in"}, 401)
    d = await read_payload(request)
    lang = core.first(d, "language", default="hindi").lower()
    with core.conn() as c:
        c.execute("update buyers set language=%s, updated=%s where uid=%s or email=%s",
                  (lang, core.now(), s.get("uid", ""), s.get("email", "")))
    return respond(request, {"success": True, "message": "Language updated successfully", "language": lang})


@router.post("/api/session/logout")
async def logout(request: Request):
    r = respond(request, {"success": True})
    r.delete_cookie(SESSION_COOKIE)
    return r


@router.post("/api/session/record_entry")
async def record_visit(request: Request):
    return respond(request, {"success": True})


def _caller(request: Request) -> tuple[str | None, bool]:
    try:
        require_api_key(request)
        return None, True
    except HTTPException:
        check_signature(request)
        s = read_session(request)
        if not s:
            raise HTTPException(status_code=401, detail="Not signed in")
        return (s.get("uid") or s.get("email") or ""), False


@router.api_route("/library", methods=["GET", "POST"])
@router.api_route("/api/database/library", methods=["GET", "POST"])
async def library(request: Request):
    forced_uid, trusted = _caller(request)
    d = await read_payload(request)
    d = {**dict(request.query_params), **(d if isinstance(d, dict) else {})}
    method = request.method
    req_action = d.get("req_action") or d.get("type") or ("list" if not core.clean(d.get("show_id")) else "record")
    uid = forced_uid if forced_uid is not None else core.clean(d.get("uid"))
    show_id = core.clean(d.get("show_id"))

    with core.conn() as c:
        if method == "POST" and req_action in ("record", "save"):
            action = core.clean(d.get("action")) or "history"
            if not uid or not show_id:
                return respond(request, {"success": False, "error": "uid and show_id are required"}, 400)
            if action not in ("history", "saved"):
                action = "history"
            name, url, t = core.clean(d.get("show_name")), core.clean(d.get("show_url")), core.now()
            c.execute(
                "insert into library (uid, action, show_id, show_name, show_url, created) values (%s,%s,%s,%s,%s,%s) "
                "on conflict (uid, action, show_id) do update set show_name=excluded.show_name, "
                "show_url=excluded.show_url, created=excluded.created",
                (uid, action, show_id, name, url, t),
            )
            return respond(request, {"success": True, "message": f"Show recorded to {action} successfully",
                                     "data": {"uid": uid, "action": action, "show_id": show_id, "show_name": name,
                                              "show_url": url, "created": t}})
        if method == "GET" or req_action == "list":
            if not uid:
                return respond(request, {"success": False, "error": "uid is required"}, 400)
            action = core.clean(d.get("action"))
            if action in ("history", "saved"):
                rows = core.all_(c, "select * from library where uid=%s and action=%s order by created desc limit 90", (uid, action))
            else:
                rows = core.all_(c, "select * from library where uid=%s order by created desc limit 90", (uid,))
            return respond(request, {"success": True, "items": rows})
        if req_action in ("remove", "delete"):
            action = core.clean(d.get("action")) or "saved"
            if not uid or not show_id:
                return respond(request, {"success": False, "error": "uid and show_id are required"}, 400)
            c.execute("delete from library where uid=%s and action=%s and show_id=%s", (uid, action, show_id))
            return respond(request, {"success": True, "message": f"Item removed from {action}"})
        if req_action in ("clear", "clear_history"):
            action = core.clean(d.get("action")) or "history"
            if not uid:
                return respond(request, {"success": False, "error": "uid is required"}, 400)
            c.execute("delete from library where uid=%s and action=%s", (uid, action))
            return respond(request, {"success": True, "message": f"Cleared all {action} items"})
    return respond(request, {"success": False, "error": "Invalid request"}, 400)


def _id_list(v) -> list[str]:
    items = v if isinstance(v, list) else str(v or "").split(",")
    seen, out = set(), []
    for x in items:
        x = core.clean(x)
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _ep_urls(it: dict) -> tuple[str, str]:
    return core.clean(it.get("media_url") or it.get("url")), core.clean(it.get("video_url"))


@router.post("/episodes")
@router.post("/api/resolve_episodes")
async def episodes(request: Request):
    trusted = True
    try:
        require_api_key(request)
    except HTTPException:
        trusted = False
        check_signature(request)
        if not read_session(request):
            raise HTTPException(status_code=401, detail="Not signed in")
    d = await read_payload(request)
    t = core.now()

    save_list: list[dict] = []
    if isinstance(d, list) and d and isinstance(d[0], dict):
        save_list = d
    elif isinstance(d, dict) and isinstance(d.get("episodes"), list):
        common = core.clean(d.get("story_id"))
        for ep in d["episodes"]:
            sid = core.clean(ep.get("story_id")) or common
            if sid and any(_ep_urls(ep)):
                save_list.append({**ep, "story_id": sid})
    elif isinstance(d, dict) and any(_ep_urls(d)):
        sid = core.clean(d.get("story_id"))
        if not sid:
            return respond(request, {"success": False, "error": "story_id and url are required"}, 400)
        save_list = [d]
    if save_list:
        if not trusted:
            raise HTTPException(status_code=403, detail="Saving episodes requires the server API key")
        n = 0
        with core.tx() as c:
            for it in save_list:
                sid = core.clean(it.get("story_id"))
                media, video = _ep_urls(it)
                try:
                    num = max(1, int(it.get("number") or 1))
                except (TypeError, ValueError):
                    num = 1
                if sid and (media or video):
                    c.execute(
                        "insert into episodes (story_id, number, media_url, video_url, created) values (%s,%s,%s,%s,%s) "
                        "on conflict (story_id, number) do update set media_url=excluded.media_url, "
                        "video_url=excluded.video_url, created=excluded.created",
                        (sid, num, media, video, t))
                    n += 1
        return respond(request, {"success": True, "message": f"Successfully saved {n} episodes", "count": n})

    d = d if isinstance(d, dict) else {}
    ids = _id_list(d.get("story_ids")) if d.get("story_ids") else []
    if not ids and "," in core.clean(d.get("story_id")):
        ids = _id_list(d.get("story_id"))
    with core.conn() as c:
        if ids:
            rows = core.all_(c, "select story_id, media_url, video_url from episodes where story_id = any(%s) order by id asc", (ids,))
            data = [{"story_id": r["story_id"], "url": r["media_url"] or r["video_url"],
                     "media_url": r["media_url"], "video_url": r["video_url"]} for r in rows]
            first_by_story: dict[str, dict] = {}
            for r in rows:
                first_by_story.setdefault(r["story_id"], r)
            stories = [{"story_id": k, "media_url_enc": r["media_url"], "audio_url": r["media_url"], "video_url": r["video_url"]}
                       for k, r in first_by_story.items()]
            return respond(request, {"success": True, "total": len(data), "data": data, "stories": stories})
        sid = core.clean(d.get("story_id"))
        if not sid:
            return respond(request, {"success": False, "error": "story_id or story_ids is required"}, 400)
        rows = core.all_(c, "select story_id, media_url, video_url from episodes where story_id=%s order by id asc", (sid,))
    if not rows:
        return respond(request, {"success": False, "error": "Story ID not found"}, 404)
    first = rows[0]
    body = {"success": True, "story_id": first["story_id"], "url": first["media_url"] or first["video_url"],
            "media_url": first["media_url"], "video_url": first["video_url"]}
    if len(rows) > 1:
        body["story_id"] = sid
        body["urls"] = [r["media_url"] or r["video_url"] for r in rows]
    return respond(request, body)
