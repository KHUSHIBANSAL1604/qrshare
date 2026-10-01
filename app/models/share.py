"""A single shareable link to a stored file."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.file import StoredFile, utcnow
from app.models.types import UtcDateTime


class ShareStatus(str, enum.Enum):
    """Lifecycle of a share. Always *derived* server-side, never trusted from
    the client."""

    ACTIVE = "active"
    EXPIRED = "expired"
    USED = "used"
    DELETED = "deleted"


class Share(db.Model):
    __tablename__ = "shares"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[int] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: public bearer token, embedded in the QR code (secrets.token_urlsafe)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    #: separate secret proving "I created this share" (manage page / cancel)
    owner_token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)

    #: Argon2/scrypt hash. NULL means the share is not password protected.
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    one_time: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: set atomically on the first successful download of a one-time share
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    downloads: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: set once the blob has been removed from storage
    deleted_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True, index=True)
    last_accessed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    file: Mapped[StoredFile] = relationship(back_populates="shares")
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        back_populates="share", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (Index("ix_shares_expires_deleted", "expires_at", "deleted_at"),)

    # -- derived properties -------------------------------------------------
    @property
    def expires_at_utc(self) -> datetime:
        """Alias kept for readability at call sites; UtcDateTime guarantees
        the column itself is already timezone-aware."""
        return self.expires_at

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at_utc

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def is_password_protected(self) -> bool:
        return bool(self.password_hash)

    @property
    def status(self) -> ShareStatus:
        """Single source of truth for whether a share may still be downloaded.

        Order matters: a deleted share reports DELETED even if it was also
        expired, and a consumed one-time share reports USED so the receiver
        gets an accurate message.
        """
        if self.is_deleted:
            return ShareStatus.DELETED
        if self.one_time and self.used:
            return ShareStatus.USED
        if self.is_expired:
            return ShareStatus.EXPIRED
        return ShareStatus.ACTIVE

    @property
    def is_downloadable(self) -> bool:
        return self.status is ShareStatus.ACTIVE

    @property
    def seconds_remaining(self) -> int:
        delta = (self.expires_at_utc - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(delta))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Share id={self.id} status={self.status.value}>"
