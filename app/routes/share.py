"""Browser-facing share pages: the receiver view and the sender manage view."""
from __future__ import annotations

from flask import Blueprint, abort, render_template, request

from app.extensions import limiter
from app.models import AuditEvent, ShareStatus
from app.routes import manage_url, remembered_owner_token, share_url
from app.services import services
from app.services.audit_service import AuditService

share_bp = Blueprint("share", __name__)


def _download_limit() -> str:
    from flask import current_app

    return ";".join(current_app.config["RATE_LIMIT_DOWNLOAD"])


@share_bp.route("/s/<token>")
@limiter.limit(_download_limit)
def view(token: str):
    """The page a receiver lands on after scanning the QR code.

    Never streams the file: it renders state, and the actual bytes come from
    a separate, separately-authorised endpoint.
    """
    share = services().shares.get_by_token(token)
    if share is None:
        # Same response for a malformed token and a token that never existed,
        # so scanning cannot be used to probe which tokens are real.
        AuditService.record(
            AuditEvent.TOKEN_NOT_FOUND, success=False, reason="unknown_token", commit=True
        )
        abort(404)

    status = share.status
    AuditService.record(
        AuditEvent.SHARE_VIEWED,
        share_id=share.id,
        success=status is ShareStatus.ACTIVE,
        reason=None if status is ShareStatus.ACTIVE else status.value,
        commit=True,
    )

    return render_template(
        "download.html",
        share=share,
        info=services().shares.public_status(share),
        status=status.value,
    )


@share_bp.route("/share/<token>")
@limiter.limit(_download_limit)
def manage(token: str):
    """Sender-only page: QR code, link, live countdown and download count.

    Authorisation comes from the signed session first (set at upload time),
    falling back to the ``key`` query parameter so the page survives a
    different browser or a bookmark. ``Referrer-Policy: same-origin`` keeps
    that key out of outbound requests.
    """
    registry = services()
    share = registry.shares.get_by_token(token)
    if share is None:
        abort(404)

    owner_token = remembered_owner_token(token) or request.args.get("key")
    if not registry.shares.owns(share, owner_token):
        # 404, not 403: confirming that the share exists would leak more than
        # it helps.
        abort(404)

    url = share_url(share.token)
    return render_template(
        "share.html",
        share=share,
        info=registry.shares.owner_status(share),
        share_link=url,
        manage_link=manage_url(share.token, share.owner_token),
        qr_data_uri=registry.qr.render_data_uri(url),
        owner_token=share.owner_token,
        events=AuditService.for_share(share.id),
    )
