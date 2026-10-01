"""Error handling.

Users get a friendly page (or a small JSON body for API calls); operators get
the traceback in the log. Nothing leaks paths, SQL or stack frames.
"""
from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from app.services.share_service import ShareError
from app.utils.validation import ValidationError

logger = logging.getLogger(__name__)

#: title + human explanation for each status we render
PAGES: dict[int, tuple[str, str]] = {
    400: ("Bad request", "That request could not be understood."),
    403: ("Not allowed", "You do not have permission to do that."),
    404: ("Not found", "That page or sharing link does not exist."),
    405: ("Not allowed", "That action is not supported here."),
    410: ("No longer available", "This sharing link is no longer available."),
    413: ("File too large", "That file exceeds the upload limit."),
    429: ("Too many requests", "You have made too many requests. Please wait a moment."),
    500: ("Something went wrong", "An unexpected error occurred. It has been logged."),
}


def wants_json() -> bool:
    """True when the caller is the fetch/XHR layer rather than a browser nav.

    The ``Accept`` header decides, not the path: a browser navigating straight
    to ``/api/share/<token>/download`` (which is exactly what clicking the
    download button does) must get the friendly HTML page, not raw JSON.
    """
    accept = request.accept_mimetypes
    if accept.accept_html and accept["text/html"] >= accept["application/json"]:
        return False
    if accept.accept_json:
        return True
    return request.path.startswith("/api/")


def error_response(status: int, message: str | None = None, code: str | None = None):
    title, description = PAGES.get(status, PAGES[500])
    detail = message or description
    if wants_json():
        return jsonify({"ok": False, "error": detail, "code": code or _code_for(status)}), status
    return (
        render_template(
            "errors/error.html",
            status=status,
            title=title,
            description=detail,
            code=code or _code_for(status),
        ),
        status,
    )


def _code_for(status: int) -> str:
    return {
        400: "bad_request",
        403: "forbidden",
        404: "not_found",
        410: "gone",
        413: "too_large",
        429: "rate_limited",
    }.get(status, "server_error")


def init_errors(app: Flask) -> None:
    @app.errorhandler(ValidationError)
    def _validation(exc: ValidationError):
        # Expected, user-caused: log at info, never as an exception.
        logger.info("validation rejected an upload: %s", exc.message)
        if wants_json():
            return jsonify({"ok": False, "error": exc.message, "field": exc.field}), 400
        return error_response(400, exc.message)

    @app.errorhandler(ShareError)
    def _share(exc: ShareError):
        return error_response(exc.status, exc.message, exc.code)

    @app.errorhandler(HTTPException)
    def _http(exc: HTTPException):
        status = exc.code or 500
        # Werkzeug's own descriptions can mention internals; use our copy.
        message = PAGES.get(status, (None, exc.description))[1]
        return error_response(status, message)

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        # The traceback goes to the log, never to the client.
        logger.exception("unhandled error on %s %s", request.method, request.path)
        if app.config.get("TESTING"):
            raise exc
        return error_response(500)
