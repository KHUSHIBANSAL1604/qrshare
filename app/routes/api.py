"""JSON API and the file download endpoint."""
from __future__ import annotations

import logging

from flask import Blueprint, Response, abort, current_app, jsonify, request, session, url_for

from app.extensions import db, limiter
from app.models import AuditEvent, ShareStatus
from app.routes import (
    forget_owner,
    manage_url,
    remember_owner,
    remembered_owner_token,
    share_url,
)
from app.services import services
from app.services.audit_service import AuditService
from app.services.encryption_service import DecryptionError
from app.services.file_service import stream_size
from app.services.share_service import ShareError
from app.services.storage import StorageError
from app.utils.formatting import content_disposition
from app.utils.validation import (
    ValidationError,
    validate_expiry,
    validate_password,
    validate_upload,
)

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


# -- limit callables ---------------------------------------------------------
# Flask-Limiter wants a single ";"-separated string and re-invokes these on
# every request, which is what lets the limits be configured per environment.
def _limit(name: str) -> str:
    return ";".join(current_app.config[name])


def _upload_limit():
    return _limit("RATE_LIMIT_UPLOAD")


def _download_limit():
    return _limit("RATE_LIMIT_DOWNLOAD")


def _password_limit():
    return _limit("RATE_LIMIT_PASSWORD")


def _status_limit():
    return _limit("RATE_LIMIT_STATUS")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "on", "yes"}


def _require_share(token: str):
    share = services().shares.get_by_token(token)
    if share is None:
        AuditService.record(
            AuditEvent.TOKEN_NOT_FOUND, success=False, reason="unknown_token", commit=True
        )
        abort(404)
    return share


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
@api_bp.post("/upload")
@limiter.limit(_upload_limit)
def upload():
    """Accept a file, encrypt it, and create a share.

    Every field is re-validated here; the matching checks in the browser exist
    only to give faster feedback.
    """
    config = current_app.config
    registry = services()

    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        raise ValidationError("Please choose a file to share.", "file")

    size = stream_size(upload_file.stream)
    meta = validate_upload(
        filename=upload_file.filename,
        size=size,
        max_bytes=config["MAX_CONTENT_LENGTH"],
        allowed=config["ALLOWED_EXTENSIONS"],
        blocked=config["BLOCKED_EXTENSIONS"],
        declared_mime=upload_file.mimetype,
    )

    expiry = validate_expiry(
        request.form.get("expiry_minutes"),
        default=config["DEFAULT_EXPIRY_MINUTES"],
        minimum=config["MIN_EXPIRY_MINUTES"],
        maximum=config["MAX_EXPIRY_MINUTES"],
    )
    one_time = _truthy(request.form.get("one_time"))
    password = None
    if _truthy(request.form.get("password_protect")):
        password = validate_password(
            request.form.get("password"), request.form.get("password_confirm")
        )

    try:
        stored = registry.files.store(upload_file.stream, meta, size)
        share = registry.shares.create_share(
            stored, expiry_minutes=expiry, password=password, one_time=one_time
        )
        db.session.flush()  # assign ids so the audit rows can reference them
        AuditService.record(AuditEvent.FILE_UPLOADED, share_id=share.id, success=True)
        AuditService.record(AuditEvent.SHARE_CREATED, share_id=share.id, success=True)
        db.session.commit()
    except StorageError:
        db.session.rollback()
        AuditService.record(
            AuditEvent.UPLOAD_REJECTED, success=False, reason="storage_error", commit=True
        )
        return jsonify({"ok": False, "error": "Could not store that file. Please try again."}), 503
    except Exception:
        db.session.rollback()
        raise

    remember_owner(share.token, share.owner_token)
    return (
        jsonify(
            {
                "ok": True,
                "token": share.token,
                "share_url": share_url(share.token),
                "manage_url": url_for("share.manage", token=share.token),
                "manage_url_absolute": manage_url(share.token, share.owner_token),
                "owner_key": share.owner_token,
                "filename": stored.original_filename,
                "size": stored.size,
                **registry.shares.owner_status(share),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
@api_bp.get("/share/<token>/status")
@limiter.limit(_status_limit)
def status(token: str):
    """Public state of a share. The sender additionally sees owner fields."""
    registry = services()
    share = _require_share(token)
    owner_token = remembered_owner_token(token) or request.args.get("key")
    if registry.shares.owns(share, owner_token):
        return jsonify({"ok": True, **registry.shares.owner_status(share)})
    return jsonify({"ok": True, **registry.shares.public_status(share)})


# ---------------------------------------------------------------------------
# Password verification
# ---------------------------------------------------------------------------
@api_bp.post("/share/<token>/verify-password")
@limiter.limit(_password_limit)
def verify_password_route(token: str):
    """Exchange the share password for a short-lived download ticket.

    Keeps the password out of the download URL, and means the rate limiter
    sees every guess.
    """
    registry = services()
    share = _require_share(token)

    try:
        registry.shares.assert_downloadable(share)
    except ShareError as exc:
        return jsonify({"ok": False, "error": exc.message, "code": exc.code}), exc.status

    payload = request.get_json(silent=True) or request.form
    password = payload.get("password") if hasattr(payload, "get") else None

    if not registry.shares.check_password(share, password):
        # One message for "wrong password" and for "this share has no
        # password", so the endpoint cannot be used to enumerate which shares
        # are protected.
        return (
            jsonify({"ok": False, "error": "Incorrect password.", "code": "bad_password"}),
            401,
        )

    return jsonify({"ok": True, "ticket": registry.shares.issue_ticket(share)})


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
@api_bp.get("/share/<token>/download")
@limiter.limit(_download_limit)
def download(token: str):
    """Stream the decrypted file.

    Order of operations matters:

    1. validate state and password ticket;
    2. **atomically** claim the download (this consumes a one-time share);
    3. only then open the blob and stream it.

    Claiming before streaming means two concurrent requests can never both be
    served a one-time file. The trade-off is that a download interrupted
    mid-flight still counts as consumed -- failing closed is the right
    direction for a link that promises single use.
    """
    registry = services()
    share = _require_share(token)
    AuditService.record(AuditEvent.DOWNLOAD_ATTEMPT, share_id=share.id, success=True, commit=True)

    try:
        registry.shares.authorize_download(share, request.args.get("ticket"))
    except ShareError as exc:
        AuditService.record(
            AuditEvent.DOWNLOAD_FAILED, share_id=share.id, success=False, reason=exc.code, commit=True
        )
        if exc.code == "expired":
            AuditService.record(
                AuditEvent.SHARE_EXPIRED, share_id=share.id, success=False, commit=True
            )
        raise

    record = share.file
    if not registry.files.exists(record):
        logger.error("blob missing for share_id=%s", share.id)
        AuditService.record(
            AuditEvent.DOWNLOAD_FAILED, share_id=share.id, success=False, reason="missing_blob", commit=True
        )
        raise ShareError("This file is no longer available.", status=410, code="deleted")

    if not registry.shares.claim_download(share):
        AuditService.record(
            AuditEvent.DOWNLOAD_FAILED, share_id=share.id, success=False, reason="already_used", commit=True
        )
        raise ShareError(
            "This link was a one-time download and has already been used.",
            status=410,
            code="used",
        )

    # Read everything the generator needs *now*: it runs after the request
    # context (and the database session) is gone.
    filename = record.original_filename
    size = record.size
    try:
        chunks = registry.files.open_plaintext(record)
    except (DecryptionError, StorageError):
        logger.exception("could not open blob for share_id=%s", share.id)
        raise ShareError("This file could not be read.", status=500, code="unreadable") from None

    def stream():
        try:
            yield from chunks
        except DecryptionError:
            # Cutting the stream short is the only safe option; the client
            # gets a truncated file rather than unauthenticated bytes.
            logger.error("integrity failure while streaming a download")
            return

    response = Response(stream(), mimetype="application/octet-stream")
    # Always an attachment, always octet-stream, always nosniff: uploaded
    # content is untrusted and must never be rendered or executed in a
    # browser tab on this origin.
    response.headers["Content-Disposition"] = content_disposition(filename)
    response.headers["Content-Length"] = str(size)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# ---------------------------------------------------------------------------
# QR image
# ---------------------------------------------------------------------------
@api_bp.get("/qr/<token>")
@limiter.limit(_status_limit)
def qr(token: str):
    """PNG QR code for a share URL.

    Encodes only the URL the caller already holds, so this discloses nothing
    new; it is rate limited all the same.
    """
    share = _require_share(token)
    png = services().qr.render_png(share_url(share.token))
    response = Response(png, mimetype="image/png")
    if _truthy(request.args.get("download")):
        safe = share.file.original_filename.rsplit(".", 1)[0][:60] or "share"
        response.headers["Content-Disposition"] = content_disposition(f"qrshare-{safe}.png")
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------
@api_bp.post("/share/<token>/cancel")
@limiter.limit(_status_limit)
def cancel(token: str):
    """Revoke a share early. Only the sender may do this."""
    registry = services()
    share = _require_share(token)
    owner_token = remembered_owner_token(token) or (request.get_json(silent=True) or {}).get("key")
    if not registry.shares.owns(share, owner_token):
        abort(404)

    if share.status is not ShareStatus.DELETED:
        unreferenced = registry.shares.blob_is_unreferenced(share)
        registry.shares.cancel(share)
        if unreferenced:
            registry.files.delete_blob(share.file)
    forget_owner(token)
    session.modified = True
    return jsonify({"ok": True, "status": share.status.value})
