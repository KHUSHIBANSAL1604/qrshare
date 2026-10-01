"""End-to-end walk through the exact demo flow, plus page-level smoke tests."""
from __future__ import annotations

import io

from conftest import share_row

from app.extensions import db
from app.models import AuditLog

JSON = {"Accept": "application/json"}


def test_full_demo_flow(app, client, fresh_client, storage_dir):
    """Upload -> encrypt -> QR -> scan -> password -> download -> refuse reuse.

    ``client`` is the sender's browser, ``fresh_client`` the receiver's phone:
    two independent sessions, as in the live demo.
    """
    original = b"%PDF-1.7 quarterly figures, confidential\n" * 200
    password = "viva-demo-2026"

    # 1-4. Sender uploads with all three protections switched on.
    created = client.post(
        "/api/upload",
        data={
            "file": (io.BytesIO(original), "quarterly-report.pdf"),
            "expiry_minutes": "10",
            "one_time": "true",
            "password_protect": "true",
            "password": password,
            "password_confirm": password,
        },
        content_type="multipart/form-data",
    )
    assert created.status_code == 201
    share = created.get_json()
    token = share["token"]
    assert share["one_time"] is True
    assert share["password_protected"] is True

    # The bytes on disk are ciphertext, not the report.
    blob = next(iter(storage_dir.iterdir()))
    assert b"quarterly figures" not in blob.read_bytes()

    # 5. Sender sees the QR on the manage page.
    manage = client.get(share["manage_url"])
    assert manage.status_code == 200
    assert "data:image/png;base64," in manage.get_data(as_text=True)

    qr = fresh_client.get(f"/api/qr/{token}")
    assert qr.status_code == 200 and qr.data[:4] == b"\x89PNG"

    # 6-7. Receiver scans, lands on the share page, and is asked for a password.
    page = fresh_client.get(f"/s/{token}")
    assert page.status_code == 200
    assert "Enter the password" in page.get_data(as_text=True)

    # A wrong guess is refused and does not count as a download.
    assert fresh_client.post(
        f"/api/share/{token}/verify-password", json={"password": "wrong"}
    ).status_code == 401

    # The file is not reachable without clearing the password gate.
    assert fresh_client.get(
        f"/api/share/{token}/download", headers=JSON
    ).status_code == 401

    # 8-9. Correct password, then the download.
    ticket = fresh_client.post(
        f"/api/share/{token}/verify-password", json={"password": password}
    ).get_json()["ticket"]
    downloaded = fresh_client.get(f"/api/share/{token}/download?ticket={ticket}")
    assert downloaded.status_code == 200
    assert downloaded.data == original  # byte-for-byte round trip

    # 10. A second attempt is refused, ticket or no ticket.
    again = fresh_client.get(f"/api/share/{token}/download?ticket={ticket}", headers=JSON)
    assert again.status_code == 410
    assert again.get_json()["code"] == "used"
    assert "Already used" in fresh_client.get(f"/s/{token}").get_data(as_text=True)

    # The sender's view reflects what happened.
    status = client.get(f"/api/share/{token}/status").get_json()
    assert status["status"] == "used"
    assert status["downloads"] == 1

    # And the audit trail tells the whole story.
    with app.app_context():
        events = [
            row.event_type
            for row in db.session.query(AuditLog)
            .filter(AuditLog.share_id == share_row(token).id)
            .order_by(AuditLog.id)
        ]
    for expected in (
        "FILE_UPLOADED",
        "SHARE_CREATED",
        "SHARE_VIEWED",
        "PASSWORD_FAILED",
        "PASSWORD_OK",
        "SHARE_CONSUMED",
    ):
        assert expected in events, f"{expected} missing from {events}"


def test_simple_flow_without_protections(client, fresh_client):
    """The minimum path: upload, scan, download, download again."""
    created = client.post(
        "/api/upload",
        data={"file": (io.BytesIO(b"just a note"), "note.txt")},
        content_type="multipart/form-data",
    ).get_json()

    assert fresh_client.get(f"/s/{created['token']}").status_code == 200
    for _ in range(2):
        response = fresh_client.get(f"/api/share/{created['token']}/download")
        assert response.status_code == 200
        assert response.data == b"just a note"


# -- page smoke tests ------------------------------------------------------
def test_landing_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "QRShare" in body
    assert "Upload a file" in body


def test_upload_page_renders_the_form(client):
    body = client.get("/upload").get_data(as_text=True)
    assert "Drop a file here" in body
    assert "csrf_token" in body
    assert "Protect with a password" in body
    assert "Delete after the first download" in body


def test_security_page_is_honest_about_limitations(client):
    body = client.get("/security").get_data(as_text=True)
    assert "not end-to-end encryption" in body
    assert "not the security boundary" in body


def test_health_check(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_static_assets_are_served(client):
    for path in ("/static/css/main.css", "/static/js/common.js", "/static/js/upload.js",
                 "/static/js/share.js", "/static/js/download.js", "/static/img/favicon.svg"):
        assert client.get(path).status_code == 200, path


def test_every_page_passes_its_own_csp(client, make_share):
    """No page may rely on inline script, since the CSP forbids it."""
    body = make_share()
    pages = ["/", "/upload", "/security", f"/s/{body['token']}", f"/share/{body['token']}"]
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200, path
        html = response.get_data(as_text=True)
        nonce = response.headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
        # Every <script> tag must carry either src= or this request's nonce.
        for fragment in html.split("<script")[1:]:
            head = fragment.split(">")[0]
            assert "src=" in head or nonce in head, f"inline script without a nonce on {path}"
        assert 'style="' not in html, f"inline style attribute on {path}"
