"""Landing page and the upload form."""
from __future__ import annotations

from flask import Blueprint, current_app, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html", max_mb=current_app.config["MAX_FILE_SIZE_MB"])


@main_bp.route("/upload")
def upload():
    config = current_app.config
    return render_template(
        "upload.html",
        max_mb=config["MAX_FILE_SIZE_MB"],
        max_bytes=config["MAX_CONTENT_LENGTH"],
        default_expiry=config["DEFAULT_EXPIRY_MINUTES"],
        max_expiry=config["MAX_EXPIRY_MINUTES"],
        blocked_extensions=sorted(config["BLOCKED_EXTENSIONS"]),
        allowed_extensions=sorted(config["ALLOWED_EXTENSIONS"]),
    )


@main_bp.route("/security")
def security():
    config = current_app.config
    return render_template(
        "security.html",
        max_mb=config["MAX_FILE_SIZE_MB"],
        default_expiry=config["DEFAULT_EXPIRY_MINUTES"],
        max_expiry=config["MAX_EXPIRY_MINUTES"],
    )


@main_bp.route("/healthz")
def healthz():
    """Liveness probe. Deliberately reveals nothing about the deployment."""
    return {"status": "ok"}, 200
