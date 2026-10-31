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

# Database Settings (Supabase PostgreSQL)
DATABASE_URL: str = os.getenv("DATABASE_URL", "")
