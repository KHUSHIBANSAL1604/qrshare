"""Shared pytest fixtures.

Each test gets a throwaway storage directory and a file-backed SQLite
database, so nothing leaks between tests and the concurrency test can open a
second connection to the same database.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import Share  # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app(
        "testing",
        STORAGE_PATH=tmp_path / "storage",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
    )
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def storage_dir(app):
    return Path(app.config["STORAGE_PATH"])


@pytest.fixture
def services(app):
    return app.extensions["qrshare"]


def upload_payload(
    content: bytes = b"top secret report contents",
    filename: str = "report.pdf",
    **fields: str,
) -> dict:
    """Build a multipart payload for POST /api/upload."""
    data = {"file": (io.BytesIO(content), filename)}
    data.update(fields)
    return data


@pytest.fixture
def make_share(client):
    """Create a share through the real API and return the JSON response."""

    def _make(content: bytes = b"top secret report contents", filename: str = "report.pdf", **fields):
        response = client.post(
            "/api/upload",
            data=upload_payload(content, filename, **fields),
            content_type="multipart/form-data",
        )
        assert response.status_code == 201, response.get_data(as_text=True)
        return response.get_json()

    return _make


@pytest.fixture
def limited_app(tmp_path):
    """An app with rate limiting genuinely switched on.

    Flask-Limiter installs its request hooks inside ``init_app`` and returns
    early when disabled, so enabling the flag after the fact does nothing --
    the limits have to be on from construction.
    """
    application = create_app(
        "testing",
        STORAGE_PATH=tmp_path / "storage",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'limited.db'}",
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_UPLOAD=["3 per minute"],
        RATE_LIMIT_PASSWORD=["5 per minute"],
        RATE_LIMIT_DOWNLOAD=["1000 per minute"],
        RATE_LIMIT_STATUS=["1000 per minute"],
        RATE_LIMIT_DEFAULT=["1000 per minute"],
    )
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()
    # Leave the shared Limiter singleton disabled for the next test.
    from app.extensions import limiter

    limiter.enabled = False


@pytest.fixture
def fresh_client(app):
    """A second client with no session cookies -- i.e. a receiver, not the sender."""
    return app.test_client()


def share_row(token: str) -> Share:
    return db.session.query(Share).filter(Share.token == token).one()
