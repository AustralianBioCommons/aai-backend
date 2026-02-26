import hashlib
from datetime import datetime, timezone

import pytest
from sqlmodel import select

from biocommons import emails
from db.models import EmailNotification
from db.types import EmailStatusEnum
from routers import user, utils
from tests.datagen import Auth0UserDataFactory


def test_generate_otp_code_length_and_digits() -> None:
    code = user._generate_otp_code()
    assert len(code) == user.OTP_LENGTH
    assert code.isdigit()


def test_hash_otp_matches_sha256(monkeypatch: pytest.MonkeyPatch) -> None:
    code = "123456"
    expected = hashlib.sha256(code.encode("utf-8")).hexdigest()
    assert user._hash_otp(code) == expected


def test_render_otp_email_includes_code_and_target() -> None:
    code = "999999"
    email = "test@example.com"
    _subject, body = emails.compose_email_change_otp_email(
        code=code,
        target_email=email,
        expiration_minutes=user.OTP_EXPIRATION_MINUTES,
    )
    assert code in body
    assert email in body
    assert str(user.OTP_EXPIRATION_MINUTES) in body


def test_ensure_datetime_is_aware_adds_timezone() -> None:
    naive = datetime(2020, 1, 1, 0, 0, 0)
    aware = user._ensure_datetime_is_aware(naive)
    assert aware.tzinfo is not None
    assert aware.tzinfo == timezone.utc


def test_ensure_datetime_preserves_existing_timezone() -> None:
    aware = datetime(2020, 1, 1, tzinfo=timezone.utc)
    result = user._ensure_datetime_is_aware(aware)
    assert result is aware


@pytest.mark.parametrize(
    "value",
    [
        datetime(2020, 1, 1),
        datetime(2020, 1, 1, tzinfo=timezone.utc),
    ],
)
def test_ensure_datetime_consistency(value: datetime) -> None:
    result = user._ensure_datetime_is_aware(value)
    assert result.tzinfo == timezone.utc


def test_mask_email_keeps_prefix_and_masks_domain() -> None:
    masked = utils._mask_email("abcdef@example.com")
    assert masked == "ab***f@ex****e.c**"


def test_recover_login_email_found_queues_notification(
    test_client,
    mock_auth0_client,
    test_db_session,
    mocker,
):
    mocker.patch("routers.utils.validate_recaptcha", return_value=True)
    auth0_user = Auth0UserDataFactory.build(
        username="example_user",
        email="abcdef@example.com",
    )
    mock_auth0_client.get_users.return_value = [auth0_user]

    response = test_client.post(
        "/utils/login/recover-email",
        json={"username": "example_user", "recaptcha_token": "token"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["found"] is True
    assert payload["masked_email"] == "ab***f@ex****e.c**"

    queued = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued) == 1
    assert queued[0].to_address == "abcdef@example.com"
    assert queued[0].status == EmailStatusEnum.PENDING


def test_recover_login_email_not_found_returns_false(
    test_client,
    mock_auth0_client,
    test_db_session,
    mocker,
):
    mocker.patch("routers.utils.validate_recaptcha", return_value=True)
    mock_auth0_client.get_users.return_value = []

    response = test_client.post(
        "/utils/login/recover-email",
        json={"username": "unknown_user", "recaptcha_token": "token"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["found"] is False
    assert payload["masked_email"] is None

    queued = test_db_session.exec(select(EmailNotification)).all()
    assert queued == []


def test_recover_login_email_invalid_recaptcha_returns_not_found(
    test_client,
    mock_auth0_client,
    test_db_session,
    mocker,
):
    mocker.patch("routers.utils.validate_recaptcha", return_value=False)

    response = test_client.post(
        "/utils/login/recover-email",
        json={"username": "unknown_user", "recaptcha_token": "invalid"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["found"] is False
    assert "Invalid recaptcha token" in payload["message"]
    mock_auth0_client.get_users.assert_not_called()

    queued = test_db_session.exec(select(EmailNotification)).all()
    assert queued == []
