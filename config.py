"""Settings from environment variables (a local .env is read too). Constants feed main.py, `settings` feeds the gateway."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

# Server Settings
PORT: int = int(os.getenv("PORT", 3000))

# Upstream Audio Stream Settings (Loaded strictly from .env)
UPSTREAM_API_URL: str = os.getenv("UPSTREAM_API_URL", "").rstrip("/")
UPSTREAM_WEB_URL: str = os.getenv("UPSTREAM_WEB_URL", "")
UPSTREAM_HOST: str = os.getenv("UPSTREAM_HOST", "")
UPSTREAM_APP_NAME: str = os.getenv("UPSTREAM_APP_NAME", "")

# App User Agent
APP_USER_AGENT: str = os.getenv("APP_USER_AGENT", "")

# Database (Supabase Session pooler URI)
DATABASE_URL: str = os.getenv("DATABASE_URL", "")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


class Settings:
    DATABASE_URL = _env("DATABASE_URL")

    # seconds a content request may take
    CONTENT_TIMEOUT = float(_env("CONTENT_TIMEOUT", "60"))

    # server-to-server key (/episodes saving, /library with uid); empty = disabled
    API_SECRET_KEY = _env("API_SECRET_KEY")

    # signs the app session token and the admin cookie
    SESSION_SECRET = _env("SESSION_SECRET")
    ADMIN_JWT_SECRET = _env("ADMIN_JWT_SECRET") or _env("SESSION_SECRET")
    SESSION_DAYS = int(_env("SESSION_DAYS", "30"))
    ADMIN_SESSION_SECONDS = 3600

    # Firebase project whose ID tokens are accepted
    FIREBASE_PROJECT_ID = _env("FIREBASE_PROJECT_ID", "story-gram-ce767")

    # request signing / encryption key shared with the app (storygram.signKey); empty = off
    SIGN_KEY = _env("SIGN_KEY")

    # first owner account, created once
    OWNER_NAME = _env("OWNER_NAME", "Owner")
    OWNER_USERNAME = _env("OWNER_USERNAME", "owner").lower()
    OWNER_PASSWORD = _env("OWNER_PASSWORD")

    # uids hidden from admin lists
    HIDDEN_UIDS = [u for u in _env("HIDDEN_UIDS").split(",") if u]

    CORS_ORIGINS = [o for o in _env("CORS_ORIGINS", "*").split(",") if o]


settings = Settings()
