import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from starlette.exceptions import HTTPException

from auth.otp import OTP_EXPIRATION_MINUTES, OTP_LENGTH, OneTimePassword
from biocommons import emails
from db.models import EmailChangeOtp
from tests.db.datagen import BiocommonsUserFactory


def test_generate_otp_code_length_and_digits() -> None:
    code = OneTimePassword.generate().code
    assert len(code) == OTP_LENGTH
    assert code.isdigit()


def test_hash_otp_matches_sha256() -> None:
    otp = OneTimePassword.generate()
    expected = hashlib.sha256(otp.code.encode("utf-8")).hexdigest()
    assert otp.hash == expected
    assert OneTimePassword.check_code(code=otp.code, hash=expected)


def test_render_otp_email_includes_code_and_target() -> None:
    code = "999999"
    email = "test@example.com"
    _subject, body = emails.compose_email_change_otp_email(
        code=code,
        target_email=email,
        expiration_minutes=OTP_EXPIRATION_MINUTES,
    )
    assert code in body
    assert email in body
    assert str(OTP_EXPIRATION_MINUTES) in body


@pytest.mark.parametrize(
    "tz", [None, timezone.utc, timezone(timedelta(hours=11)), timezone(timedelta(hours=-5))],
)
@pytest.mark.parametrize("expired", [False, True])
def test_otp_verification_handles_expiry_timezones(
    test_db_session, persistent_factories, tz, expired,
) -> None:
    user = BiocommonsUserFactory.create_sync()
    now = datetime(2020, 1, 1, 12, tzinfo=timezone.utc)
    expires_at = now + timedelta(minutes=-1 if expired else 1)
    expires_at = expires_at.astimezone(tz) if tz else expires_at.replace(tzinfo=None)
    otp = OneTimePassword.generate()
    entry = EmailChangeOtp(
        user_id=user.id, target_email="new@example.com", otp_hash=otp.hash,
        created_at=now - timedelta(minutes=1), expires_at=expires_at,
    )
    test_db_session.add(entry)
    test_db_session.flush()

    if expired:
        with pytest.raises(HTTPException) as exc:
            EmailChangeOtp.verify_for_user(test_db_session, user_id=user.id, code=otp.code, now=now)
        assert exc.value.status_code == 400
    else:
        result = EmailChangeOtp.verify_for_user(test_db_session, user_id=user.id, code=otp.code, now=now)
        assert result.id == entry.id
        assert result.is_active is True
