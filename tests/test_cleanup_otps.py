from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, select

from db.models import EmailChangeOtp
from scheduled_tasks.tasks import cleanup_email_otps


def insert_otp(
    session,
    *,
    expires_delta: timedelta,
    is_active: bool = True,
    user_id: str = "test-user",
) -> EmailChangeOtp:
    now = datetime.now(timezone.utc)
    otp = EmailChangeOtp(
        user_id=user_id,
        target_email="user@example.com",
        otp_hash="deadbeef",
        expires_at=now + expires_delta,
        is_active=is_active,
    )
    session.add(otp)
    session.commit()
    return otp


@pytest.fixture(autouse=True)
def override_cleanup_session(monkeypatch, test_db_engine):
    def get_db_session_override():
        session = Session(test_db_engine)
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr("scheduled_tasks.tasks.get_db_session", get_db_session_override)


@pytest.fixture
def persistence_session(test_db_engine):
    session = Session(test_db_engine)
    yield session
    session.close()


@pytest.mark.asyncio
async def test_cleanup_email_otps_removes_expired_and_inactive(
    persistence_session, test_db_engine
):
    insert_otp(persistence_session, expires_delta=timedelta(minutes=-1))
    insert_otp(
        persistence_session,
        expires_delta=timedelta(hours=1),
        is_active=False,
    )
    insert_otp(
        persistence_session,
        expires_delta=timedelta(hours=1),
        user_id="keep-me",
    )
    await cleanup_email_otps()

    with Session(test_db_engine) as session:
        remaining = session.exec(select(EmailChangeOtp)).all()
    assert len(remaining) == 1
    assert remaining[0].user_id == "keep-me"


@pytest.mark.asyncio
async def test_cleanup_email_otps_no_delete_when_none_expired(
    persistence_session, test_db_engine
):
    insert_otp(
        persistence_session,
        expires_delta=timedelta(hours=1),
    )
    await cleanup_email_otps()
    with Session(test_db_engine) as session:
        remaining = session.exec(select(EmailChangeOtp)).all()
    assert len(remaining) == 1
