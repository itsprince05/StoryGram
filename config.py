import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

PORT: int = int(os.getenv("PORT", 3000))

UPSTREAM_API_URL: str = os.getenv("UPSTREAM_API_URL", "").rstrip("/")
UPSTREAM_WEB_URL: str = os.getenv("UPSTREAM_WEB_URL", "")
UPSTREAM_HOST: str = os.getenv("UPSTREAM_HOST", "")
UPSTREAM_APP_NAME: str = os.getenv("UPSTREAM_APP_NAME", "")

APP_USER_AGENT: str = os.getenv("APP_USER_AGENT", "")

DATABASE_URL: str = os.getenv("DATABASE_URL", "")

CONTENT_API_URL: str = os.getenv("CONTENT_API_URL", "")
FIREBASE_PROJECT_ID: str = os.getenv("FIREBASE_PROJECT_ID", "")

SESSION_SECRET: str = os.getenv("SESSION_SECRET", "")
ADMIN_JWT_SECRET: str = os.getenv("ADMIN_JWT_SECRET", "")
API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "")

OWNER_NAME: str = os.getenv("OWNER_NAME", "Owner")
OWNER_USERNAME: str = os.getenv("OWNER_USERNAME", "owner")
OWNER_PASSWORD: str = os.getenv("OWNER_PASSWORD", "")

SIGN_KEY: str = os.getenv("SIGN_KEY", "")

LICENSE_SERVER_URL: str = os.getenv("LICENSE_SERVER_URL", "")
