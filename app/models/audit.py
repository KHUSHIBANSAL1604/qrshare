"""Append-only security audit trail.

Deliberately stores no passwords, no encryption keys and no file contents.
IP addresses and user agents are recorded because they are what make an audit
log useful for abuse investigation; both are truncated and the log is pruned
with the share it belongs to.
"""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.file import utcnow
from app.models.types import UtcDateTime


class AuditEvent(str, enum.Enum):
    FILE_UPLOADED = "FILE_UPLOADED"
    SHARE_CREATED = "SHARE_CREATED"
    SHARE_VIEWED = "SHARE_VIEWED"
    DOWNLOAD_ATTEMPT = "DOWNLOAD_ATTEMPT"
    DOWNLOAD_SUCCESS = "DOWNLOAD_SUCCESS"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    PASSWORD_FAILED = "PASSWORD_FAILED"
    PASSWORD_OK = "PASSWORD_OK"
    SHARE_EXPIRED = "SHARE_EXPIRED"
    SHARE_CONSUMED = "SHARE_CONSUMED"
    SHARE_CANCELLED = "SHARE_CANCELLED"
    FILE_DELETED = "FILE_DELETED"
    RATE_LIMITED = "RATE_LIMITED"
    UPLOAD_REJECTED = "UPLOAD_REJECTED"
    TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: nullable so events without a valid share (bad token) are still recorded
    share_id: Mapped[int | None] = mapped_column(
        ForeignKey("shares.id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: short machine-readable reason, e.g. "expired", "bad_password"
    reason: Mapped[str | None] = mapped_column(String(120), nullable=True)

    share: Mapped["Share | None"] = relationship(back_populates="audit_logs")  # noqa: F821

    __table_args__ = (Index("ix_audit_event_time", "event_type", "timestamp"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog {self.event_type} success={self.success}>"
