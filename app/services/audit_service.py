"""Security audit trail.

Records *what happened*, never *what the secret was*. Passwords, encryption
keys, tokens and file contents are deliberately absent from every call site.
"""
from __future__ import annotations

import logging

from flask import has_request_context, request

from app.extensions import db
from app.models import AuditEvent, AuditLog

logger = logging.getLogger(__name__)

MAX_USER_AGENT = 255


class AuditService:
    """Writes audit rows and mirrors them to the application log."""

    @staticmethod
    def _client() -> tuple[str | None, str | None]:
        if not has_request_context():
            return None, None
        ip = request.remote_addr
        agent = (request.user_agent.string or "")[:MAX_USER_AGENT] or None
        return ip, agent

    @classmethod
    def record(
        cls,
        event: AuditEvent,
        *,
        share_id: int | None = None,
        success: bool = True,
        reason: str | None = None,
        commit: bool = False,
    ) -> AuditLog:
        """Append an audit entry.

        ``commit`` is left ``False`` by default so the caller can make the
        audit row part of the same transaction as the state change it
        describes -- an audit entry should never survive a rolled-back action,
        or vice versa.
        """
        ip, agent = cls._client()
        entry = AuditLog(
            share_id=share_id,
            event_type=event.value,
            success=success,
            reason=(reason or None) and reason[:120],
            ip_address=ip,
            user_agent=agent,
        )
        db.session.add(entry)
        if commit:
            db.session.commit()

        log = logger.info if success else logger.warning
        log("audit %s share_id=%s success=%s reason=%s", event.value, share_id, success, reason)
        return entry

    @staticmethod
    def for_share(share_id: int, limit: int = 25) -> list[AuditLog]:
        """Most recent events for one share (shown on the manage page)."""
        return (
            db.session.query(AuditLog)
            .filter(AuditLog.share_id == share_id)
            .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .limit(limit)
            .all()
        )
