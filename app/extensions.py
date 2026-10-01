"""Flask extension singletons.

Kept in their own module so models/services can import them without creating
a circular dependency on the application factory.
"""
from __future__ import annotations

from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for every model."""


db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, connection_record) -> None:
    """Turn on the SQLite behaviour the schema actually depends on.

    SQLite ships with foreign keys *disabled*, so without this the
    ``ON DELETE CASCADE`` declared on shares and audit rows would silently do
    nothing and deleting a share would leave its audit trail orphaned. WAL
    mode lets a download read while another request writes, which is what the
    one-time consumption test exercises.
    """
    if type(dbapi_connection).__module__.split(".")[0] != "sqlite3":
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def rate_limit_key() -> str:
    """Rate-limit bucket key.

    Uses the remote address. Behind a proxy, run the app under Werkzeug's
    ProxyFix (see ``run.py``) so this reflects the real client rather than the
    proxy, otherwise every visitor shares one bucket.
    """
    return get_remote_address() or request.environ.get("REMOTE_ADDR", "unknown")


limiter = Limiter(key_func=rate_limit_key)
