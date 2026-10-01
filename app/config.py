"""Central configuration.

Every tunable lives here and is read from the environment exactly once, so the
rest of the code never touches ``os.environ`` directly and nothing is
hard-coded at a call site.
"""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _csv(name: str, default: str = "") -> set[str]:
    raw = os.environ.get(name, default) or ""
    return {part.strip().lower().lstrip(".") for part in raw.split(",") if part.strip()}


def _limits(name: str, default: str) -> list[str]:
    """Flask-Limiter accepts a list of limit strings; we join them with ';'."""
    raw = os.environ.get(name) or default
    return [part.strip() for part in raw.split(";") if part.strip()]


class Config:
    """Base configuration shared by every environment."""

    # -- Flask core --------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY") or ""
    ENV_NAME = os.environ.get("FLASK_ENV", "production")

    # -- Database ----------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'instance' / 'qrshare.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {"pool_pre_ping": True}

    # -- Storage -----------------------------------------------------------
    STORAGE_PATH = Path(os.environ.get("STORAGE_PATH") or (BASE_DIR / "storage")).resolve()

    # -- Encryption --------------------------------------------------------
    MASTER_ENCRYPTION_KEY = os.environ.get("MASTER_ENCRYPTION_KEY") or ""
    #: plaintext bytes encrypted per AES-GCM frame (1 MiB)
    ENCRYPTION_CHUNK_SIZE = 1024 * 1024

    # -- Uploads -----------------------------------------------------------
    MAX_FILE_SIZE_MB = _int("MAX_FILE_SIZE_MB", 100)
    #: Werkzeug aborts the request with 413 past this many bytes.
    MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024
    ALLOWED_EXTENSIONS = _csv("ALLOWED_EXTENSIONS")
    BLOCKED_EXTENSIONS = _csv(
        "BLOCKED_EXTENSIONS",
        "exe,com,scr,bat,cmd,msi,cpl,jar,vbs,vbe,js,jse,ws,wsf,wsh,ps1,psm1,"
        "hta,lnk,scf,reg,dll,sys,pif,gadget,apk,app",
    )

    # -- Share lifetime ----------------------------------------------------
    DEFAULT_EXPIRY_MINUTES = _int("DEFAULT_EXPIRY_MINUTES", 60)
    MAX_EXPIRY_MINUTES = _int("MAX_EXPIRY_MINUTES", 1440)
    MIN_EXPIRY_MINUTES = 1
    CLEANUP_GRACE_MINUTES = _int("CLEANUP_GRACE_MINUTES", 10)
    CLEANUP_INTERVAL_SECONDS = _int("CLEANUP_INTERVAL_SECONDS", 300)
    #: lifetime of the signed ticket handed out after a correct password
    DOWNLOAD_TICKET_TTL_SECONDS = _int("DOWNLOAD_TICKET_TTL_SECONDS", 300)

    # -- Rate limiting -----------------------------------------------------
    RATE_LIMIT_DEFAULT = _limits("RATE_LIMIT_DEFAULT", "200 per hour")
    RATE_LIMIT_UPLOAD = _limits("RATE_LIMIT_UPLOAD", "10 per hour;3 per minute")
    RATE_LIMIT_DOWNLOAD = _limits("RATE_LIMIT_DOWNLOAD", "60 per hour")
    RATE_LIMIT_PASSWORD = _limits("RATE_LIMIT_PASSWORD", "10 per hour;5 per minute")
    RATE_LIMIT_STATUS = _limits("RATE_LIMIT_STATUS", "120 per hour")
    RATE_LIMIT_STORAGE_URI = os.environ.get("RATE_LIMIT_STORAGE_URI") or "memory://"
    RATE_LIMIT_ENABLED = True

    # -- Public URL --------------------------------------------------------
    PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")

    # -- Cookies / transport ----------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    ENABLE_HSTS = _bool("ENABLE_HSTS", False)

    # -- CSRF --------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tokens live as long as the session

    TESTING = False
    DEBUG = False

    @staticmethod
    def master_key_bytes(raw: str) -> bytes:
        """Decode and validate the base64 master key."""
        try:
            key = base64.urlsafe_b64decode(raw.encode() + b"=" * (-len(raw) % 4))
        except Exception as exc:  # noqa: BLE001 - surfaced as a startup error
            raise ValueError("MASTER_ENCRYPTION_KEY is not valid base64") from exc
        if len(key) != 32:
            raise ValueError("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes")
        return key


class DevelopmentConfig(Config):
    DEBUG = True
    ENV_NAME = "development"


class TestingConfig(Config):
    TESTING = True
    ENV_NAME = "testing"
    SECRET_KEY = "testing-secret-key-not-for-production"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATE_LIMIT_ENABLED = False
    CLEANUP_INTERVAL_SECONDS = 0
    MASTER_ENCRYPTION_KEY = base64.urlsafe_b64encode(b"\x01" * 32).decode()
    MAX_FILE_SIZE_MB = 5
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024


class ProductionConfig(Config):
    ENV_NAME = "production"


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None) -> type[Config]:
    name = (name or os.environ.get("FLASK_ENV") or "production").lower()
    return CONFIGS.get(name, ProductionConfig)


def generate_master_key() -> str:
    """Helper used by the CLI to mint a fresh master key."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
