import hashlib
from datetime import datetime, timezone

import pytest

from routers import user


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
    body = user._render_otp_email(code, email)
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
