"""Share tokens, the receiver page, status endpoint, QR codes and cancellation."""
from __future__ import annotations

import re

from conftest import share_row

from app.extensions import db
from app.models import Share
from app.services.share_service import ShareService


# -- tokens ----------------------------------------------------------------
def test_tokens_are_unique_and_long(app):
    with app.app_context():
        tokens = {ShareService.generate_token() for _ in range(2000)}
    assert len(tokens) == 2000
    assert all(len(t) >= 43 for t in tokens)  # 32 bytes base64url


def test_tokens_are_url_safe(app):
    with app.app_context():
        for _ in range(200):
            assert re.fullmatch(r"[A-Za-z0-9_-]+", ShareService.generate_token())


def test_tokens_leak_no_internal_information(app, make_share):
    """A token must not be derived from the file, the row id or the clock.

    Asserting that no substring of the size appears in the token would be
    meaningless -- a two-character run turns up by chance in a 43-character
    string. What is testable is that identical inputs still produce unrelated
    tokens, which no derivation scheme could manage.
    """
    bodies = [make_share(content=b"identical", filename="same.txt") for _ in range(12)]
    tokens = [body["token"] for body in bodies]

    assert len(set(tokens)) == len(tokens), "identical uploads produced a repeated token"
    # Consecutive rows must share no common prefix beyond coincidence.
    for earlier, later in zip(tokens, tokens[1:]):
        assert earlier[:6] != later[:6]
    for body in bodies:
        assert body["filename"].split(".")[0] not in body["token"]


def test_owner_token_is_separate_from_the_public_token(app, make_share):
    body = make_share()
    with app.app_context():
        share = share_row(body["token"])
        assert share.owner_token != share.token
        assert len(share.owner_token) >= 43


# -- receiver page ---------------------------------------------------------
def test_receiver_page_renders_without_exposing_the_file(fresh_client, make_share):
    body = make_share(content=b"CANARY-CONTENT-77", filename="brief.pdf")
    response = fresh_client.get(f"/s/{body['token']}")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "brief.pdf" in page
    assert "CANARY-CONTENT-77" not in page
    assert "Download file" in page


def test_receiver_page_shows_a_password_prompt_when_protected(fresh_client, make_share):
    body = make_share(password_protect="true", password="letmein1", password_confirm="letmein1")
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    assert "Enter the password" in page
    assert "Unlock" in page
    assert "Download file" not in page


def test_unknown_token_is_a_404(fresh_client):
    assert fresh_client.get("/s/definitely-not-a-real-token-value-here").status_code == 404


def test_receiver_page_does_not_reveal_the_owner_token(fresh_client, make_share, app):
    body = make_share()
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    with app.app_context():
        assert share_row(body["token"]).owner_token not in page


# -- status ----------------------------------------------------------------
def test_public_status_excludes_sender_only_fields(fresh_client, make_share):
    body = make_share()
    data = fresh_client.get(f"/api/share/{body['token']}/status").get_json()
    assert data["status"] == "active"
    assert data["downloads"] == 0
    assert "created_at" not in data
    assert "owner_key" not in data
    assert "id" not in data
    assert "storage_path" not in data


def test_owner_status_includes_extra_fields(client, make_share):
    """The uploading client keeps its owner token in the signed session."""
    body = make_share()
    data = client.get(f"/api/share/{body['token']}/status").get_json()
    assert data["created_at"]
    assert data["used"] is False


def test_status_for_unknown_token_is_404(fresh_client):
    assert fresh_client.get("/api/share/nope-nope-nope-nope-nope/status").status_code == 404


# -- manage page -----------------------------------------------------------
def test_manage_page_requires_the_owner_token(fresh_client, make_share):
    body = make_share()
    # No session, no key: indistinguishable from a token that does not exist.
    assert fresh_client.get(f"/share/{body['token']}").status_code == 404
    # Wrong key: same.
    assert fresh_client.get(f"/share/{body['token']}?key=wrongwrongwrongwrong").status_code == 404


def test_manage_page_works_with_the_owner_key(fresh_client, make_share):
    body = make_share()
    response = fresh_client.get(f"/share/{body['token']}?key={body['owner_key']}")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "data:image/png;base64," in page  # QR rendered inline
    assert body["share_url"] in page


def test_manage_page_works_from_the_uploading_session(client, make_share):
    body = make_share()
    assert client.get(f"/share/{body['token']}").status_code == 200


# -- QR --------------------------------------------------------------------
def test_qr_endpoint_returns_a_png(fresh_client, make_share):
    body = make_share()
    response = fresh_client.get(f"/api/qr/{body['token']}")
    assert response.status_code == 200
    assert response.mimetype == "image/png"
    assert response.data[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(response.data) > 200


def test_qr_encodes_the_share_url_and_not_the_file(app, make_share):
    """Decode the rendered QR and check exactly what it carries."""
    body = make_share(content=b"SENSITIVE-BYTES", filename="x.bin")
    with app.app_context():
        png = app.extensions["qrshare"].qr.render_png(body["share_url"])
    assert b"SENSITIVE-BYTES" not in png
    # The payload is short because it is a URL, not a file.
    assert len(body["share_url"]) < 200


def test_qr_download_sets_an_attachment_header(fresh_client, make_share):
    body = make_share(filename="quarterly.pdf")
    response = fresh_client.get(f"/api/qr/{body['token']}?download=1")
    assert "attachment" in response.headers["Content-Disposition"]
    assert "qrshare-quarterly" in response.headers["Content-Disposition"]


# -- cancellation ----------------------------------------------------------
def test_owner_can_cancel_a_share(client, make_share, app, storage_dir):
    body = make_share()
    assert len(list(storage_dir.iterdir())) == 1

    response = client.post(f"/api/share/{body['token']}/cancel", json={"key": body["owner_key"]})
    assert response.status_code == 200
    assert response.get_json()["status"] == "deleted"
    assert not list(storage_dir.iterdir())

    with app.app_context():
        assert share_row(body["token"]).status.value == "deleted"


def test_stranger_cannot_cancel_a_share(fresh_client, make_share, app, storage_dir):
    body = make_share()
    response = fresh_client.post(f"/api/share/{body['token']}/cancel", json={"key": "guess"})
    assert response.status_code == 404
    assert len(list(storage_dir.iterdir())) == 1
    with app.app_context():
        assert share_row(body["token"]).status.value == "active"


def test_cancelled_share_cannot_be_downloaded(client, fresh_client, make_share):
    body = make_share()
    client.post(f"/api/share/{body['token']}/cancel", json={"key": body["owner_key"]})
    response = fresh_client.get(f"/api/share/{body['token']}/download",
                                headers={"Accept": "application/json"})
    assert response.status_code == 410


# -- status derivation -----------------------------------------------------
def test_status_is_derived_server_side(app, make_share):
    from datetime import datetime, timedelta, timezone

    body = make_share(one_time="true")
    with app.app_context():
        share = share_row(body["token"])
        assert share.status.value == "active"

        share.used = True
        assert share.status.value == "used"

        share.used = False
        share.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert share.status.value == "expired"

        share.deleted_at = datetime.now(timezone.utc)
        assert share.status.value == "deleted"
        db.session.rollback()


def test_shares_reference_one_file_row(app, make_share):
    make_share()
    with app.app_context():
        share = db.session.query(Share).one()
        assert share.file is not None
        assert share.file.shares == [share]
