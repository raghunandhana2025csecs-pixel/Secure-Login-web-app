import os
import os
from datetime import timedelta

from database import DATABASE_PATH as DEFAULT_DATABASE_PATH


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    DATABASE_PATH = DEFAULT_DATABASE_PATH
    WTF_CSRF_ENABLED = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get(
        "SESSION_COOKIE_SECURE",
        "false",
    ).strip().lower() in {"1", "true", "yes"}
    RATELIMIT_STORAGE_URI = os.environ.get(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )