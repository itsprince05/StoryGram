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

# Upstream Audio Stream & Worker Proxy Settings (Loaded strictly from .env)
UPSTREAM_API_URL: str = os.getenv("UPSTREAM_API_URL", "").rstrip("/")
UPSTREAM_WEB_URL: str = os.getenv("UPSTREAM_WEB_URL", "")
UPSTREAM_HOST: str = os.getenv("UPSTREAM_HOST", "")
UPSTREAM_APP_NAME: str = os.getenv("UPSTREAM_APP_NAME", "")
WORKER_PROXY_URL: str = os.getenv("WORKER_PROXY_URL", "")
WORKER_ORIGIN: str = os.getenv("WORKER_ORIGIN", "")
WORKER_REFERER: str = os.getenv("WORKER_REFERER", "")

# App & Web User Agents
APP_USER_AGENT: str = os.getenv("APP_USER_AGENT", "")
WEB_USER_AGENT: str = os.getenv("WEB_USER_AGENT", "")

# Admin Credentials & Secrets (Loaded strictly from .env)
DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "")
LEGACY_ADMIN_PASSWORD: str = os.getenv("LEGACY_ADMIN_PASSWORD", "")
OWNER_UID: str = os.getenv("OWNER_UID", "")
ADMIN_JWT_SECRET: str = os.getenv("ADMIN_JWT_SECRET", "")

# Database (Supabase) Settings
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")

def is_supabase_configured() -> bool:
    return bool(SUPABASE_URL and (SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY))
