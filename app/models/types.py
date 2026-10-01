"""Custom column types."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator):
    """A ``DateTime`` that always round-trips as timezone-aware UTC.

    SQLite stores datetimes as strings and silently discards ``tzinfo``, so a
    value written as aware comes back naive. Comparing that against
    ``datetime.now(timezone.utc)`` raises ``TypeError: can't compare
    offset-naive and offset-aware datetimes`` -- and only on a *fresh* process,
    because within one session the identity map still holds the original aware
    object. That makes it exactly the kind of bug that passes the test suite
    and fails the cron job.

    Normalising in both directions here means no caller ever has to remember.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # A naive value is taken to already be UTC; the application never
            # constructs local-time datetimes.
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
