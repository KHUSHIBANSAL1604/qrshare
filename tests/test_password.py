"""Password protection: hashing, verification, tickets and enumeration resistance."""
from __future__ import annotations

import time

from conftest import share_row

from app.extensions import db
from app.models import AuditLog
from app.utils.passwords import hash_password, verify_password

JSON = {"Accept": "application/json"}
SECRET = "correct-horse-battery"


def protected(make_share, **extra):
    return make_share(password_protect="true", password=SECRET, password_confirm=SECRET, **extra)


# -- hashing ---------------------------------------------------------------
def test_hash_is_salted_and_verifiable():
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second  # unique salts
    assert verify_password(first, "same-password")
    assert verify_password(second, "same-password")


def test_hash_does_not_contain_the_password():
    assert "swordfish" not in hash_password("swordfish")


def test_wrong_password_is_rejected():
    assert not verify_password(hash_password("right"), "wrong")


def test_verify_against_no_hash_is_false_not_an_error():
    assert verify_password(None, "anything") is False
    assert verify_password("", "anything") is False


def test_verify_handles_a_corrupt_hash_gracefully():
    assert verify_password("not-a-real-hash", "anything") is False


# -- endpoint --------------------------------------------------------------
def test_correct_password_returns_a_ticket(fresh_client, make_share):
    body = protected(make_share)
    response = fresh_client.post(
        f"/api/share/{body['token']}/verify-password", json={"password": SECRET}
    )
    assert response.status_code == 200
    assert response.get_json()["ticket"]


def test_incorrect_password_is_rejected(fresh_client, make_share):
    body = protected(make_share)
    response = fresh_client.post(
        f"/api/share/{body['token']}/verify-password", json={"password": "nope"}
    )
    assert response.status_code == 401
    assert response.get_json()["code"] == "bad_password"


def test_missing_password_is_rejected(fresh_client, make_share):
    body = protected(make_share)
    assert fresh_client.post(f"/api/share/{body['token']}/verify-password", json={}).status_code == 401


def test_download_without_a_ticket_is_refused(fresh_client, make_share):
    body = protected(make_share)
    response = fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    assert response.status_code == 401
    assert response.get_json()["code"] == "password_required"


def test_download_with_a_ticket_succeeds(fresh_client, make_share):
    body = protected(make_share)
    ticket = fresh_client.post(
        f"/api/share/{body['token']}/verify-password", json={"password": SECRET}
    ).get_json()["ticket"]
    response = fresh_client.get(f"/api/share/{body['token']}/download?ticket={ticket}")
    assert response.status_code == 200
    assert response.data == b"top secret report contents"


def test_a_forged_ticket_is_refused(fresh_client, make_share):
    body = protected(make_share)
    response = fresh_client.get(
        f"/api/share/{body['token']}/download?ticket=made.up.ticket", headers=JSON
    )
    assert response.status_code == 401


def test_a_ticket_for_one_share_does_not_unlock_another(fresh_client, make_share):
    first = protected(make_share, filename="one.txt")
    second = protected(make_share, filename="two.txt")
    ticket = fresh_client.post(
        f"/api/share/{first['token']}/verify-password", json={"password": SECRET}
    ).get_json()["ticket"]

    response = fresh_client.get(
        f"/api/share/{second['token']}/download?ticket={ticket}", headers=JSON
    )
    assert response.status_code == 401


def test_expired_ticket_is_refused(app, fresh_client, make_share):
    body = protected(make_share)
    registry = app.extensions["qrshare"]
    with app.app_context():
        share = share_row(body["token"])
        ticket = registry.shares.issue_ticket(share)
        registry.shares.ticket_ttl = 0  # make every ticket immediately stale
        time.sleep(1.1)
        assert registry.shares.verify_ticket(share, ticket) is False


# -- information leakage ---------------------------------------------------
def test_endpoint_does_not_reveal_whether_a_share_has_a_password(fresh_client, make_share):
    """An unprotected share must answer a password attempt exactly like a
    protected share with the wrong password."""
    unprotected = make_share(filename="open.txt")
    guarded = protected(make_share, filename="closed.txt")

    open_response = fresh_client.post(
        f"/api/share/{unprotected['token']}/verify-password", json={"password": "guess"}
    )
    guarded_response = fresh_client.post(
        f"/api/share/{guarded['token']}/verify-password", json={"password": "guess"}
    )

    assert open_response.status_code == guarded_response.status_code == 401
    assert open_response.get_json() == guarded_response.get_json()


def test_password_status_is_visible_but_the_hash_is_not(fresh_client, make_share, app):
    body = protected(make_share)
    data = fresh_client.get(f"/api/share/{body['token']}/status").get_json()
    assert data["password_protected"] is True
    assert "password_hash" not in data
    with app.app_context():
        assert share_row(body["token"]).password_hash not in str(data)


def test_receiver_page_never_contains_the_hash(fresh_client, make_share, app):
    body = protected(make_share)
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    with app.app_context():
        assert share_row(body["token"]).password_hash not in page
    assert SECRET not in page


# -- auditing --------------------------------------------------------------
def test_failed_attempts_are_audited(fresh_client, make_share, app):
    body = protected(make_share)
    for _ in range(3):
        fresh_client.post(f"/api/share/{body['token']}/verify-password", json={"password": "x"})

    with app.app_context():
        share = share_row(body["token"])
        rows = db.session.query(AuditLog).filter(
            AuditLog.share_id == share.id, AuditLog.event_type == "PASSWORD_FAILED"
        ).all()
        assert len(rows) == 3
        assert all(row.success is False for row in rows)
        assert all("x" != (row.reason or "") for row in rows)


def test_successful_attempt_is_audited(fresh_client, make_share, app):
    body = protected(make_share)
    fresh_client.post(f"/api/share/{body['token']}/verify-password", json={"password": SECRET})
    with app.app_context():
        share = share_row(body["token"])
        rows = db.session.query(AuditLog).filter(
            AuditLog.share_id == share.id, AuditLog.event_type == "PASSWORD_OK"
        ).all()
        assert len(rows) == 1


def test_password_never_appears_in_any_audit_row(fresh_client, make_share, app):
    body = protected(make_share)
    fresh_client.post(f"/api/share/{body['token']}/verify-password", json={"password": SECRET})
    with app.app_context():
        for row in db.session.query(AuditLog).all():
            assert SECRET not in str(row.__dict__)
