from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import admin
import app_api
import core
import main as content_api
from config import settings

_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(transport=httpx.ASGITransport(app=content_api.app), base_url="http://content.internal",
                                    timeout=settings.CONTENT_TIMEOUT, headers={"Accept": "application/json"})
    return _client


@asynccontextmanager
async def lifespan(_: FastAPI):
    core.init_pool()
    core.ensure_seed()
    async with content_api.app.router.lifespan_context(content_api.app):
        yield
    if _client is not None:
        await _client.aclose()
    core.close_pool()


app = FastAPI(title="Story Gram API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])


@app.exception_handler(HTTPException)
async def http_error(_, exc: HTTPException):
    return JSONResponse({"success": False, "error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled(_, exc: Exception):
    print("unhandled error:", repr(exc))
    return JSONResponse({"success": False, "error": "Internal server error"}, status_code=500)


@app.get("/")
@app.get("/health")
async def health():
    try:
        with core.conn() as c:
            core.one(c, "select 1 as ok")
        return {"status": "online", "service": "running"}
    except Exception as exc:
        print("health: db check failed:", repr(exc)[:200])
        return JSONResponse({"status": "offline", "service": "down"}, status_code=503)


def _pick(d: dict, header: str, request: Request, *keys: str, default: str = "") -> str:
    return core.first(d, *keys) or core.clean(request.headers.get(header)) or default


async def _forward(request: Request, path: str, params: dict[str, str]):
    core.check_signature(request)
    s = core.read_session(request)
    if not s:
        return core.respond(request, {"success": False, "status": "unauthorized", "error": "Not signed in"}, 401)
    with core.conn() as c:
        allowed = core.has_access(c, s.get("uid", ""), s.get("email", ""), core.device_info(request, {})["device"])
    if not allowed:
        return core.respond(request, {"success": False, "status": "restricted", "error": "No active access"}, 403)
    try:
        up = await _http().get(path, headers={k: v for k, v in params.items() if v != ""})
        data = up.json()
    except (httpx.HTTPError, ValueError) as exc:
        print(f"content api {path} failed:", repr(exc))
        return core.respond(request, {"success": False, "error": "Content service is unavailable. Please try again."}, 502)
    if not isinstance(data, dict):
        return core.respond(request, {"success": False, "error": "Content service returned an unexpected response"}, 502)
    if up.status_code >= 400:
        return core.respond(request, {"success": False, "error": data.get("message") or f"Content service error {up.status_code}"},
                            502 if up.status_code >= 500 else up.status_code)
    data.setdefault("success", data.get("status") in (1, "1", True))
    return core.respond(request, data)


@app.post("/home")
async def home(request: Request):
    d = await core.read_payload(request)
    lang = _pick(d, "language", request, "language", default="hindi").lower()
    return await _forward(request, "/home", {"language": lang, "api-type": "explore_v2"})


@app.post("/search")
async def search(request: Request):
    d = await core.read_payload(request)
    lang = _pick(d, "language", request, "language", default="hindi").lower()
    return await _forward(request, "/search", {"query": _pick(d, "query", request, "query"), "language": lang})


@app.post("/show")
async def show(request: Request):
    d = await core.read_payload(request)
    lang = _pick(d, "language", request, "language", default="hindi").lower()
    return await _forward(request, "/show", {
        "show-id": _pick(d, "show_id", request, "show_id", "showId"),
        "curr-ptr": _pick(d, "curr_ptr", request, "curr_ptr", "currPtr", "start_ptr", default="0"),
        "language": lang,
    })


@app.post("/license")
async def license_(request: Request):
    d = await core.read_payload(request)
    return await _forward(request, "/license", {"show-id": _pick(d, "show_id", request, "show_id", "showId")})


app.include_router(app_api.router)
app.include_router(admin.router)
