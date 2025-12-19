from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import Session, select

from db.models import BiocommonsUser
from db.utils import refresh_unverified_users
from tests.db.datagen import BiocommonsUserFactory


@pytest.fixture(autouse=True)
def reset_refresh_time():
    """Reset the global throttle variable before each test."""
    with patch("db.utils.LAST_UNVERIFIED_REFRESH_TIME", None):
        yield


def test_refresh_unverified_users_throttling(test_db_session):
    """Verifies that the function returns early if called within the refresh interval."""
    auth0_client = MagicMock()

    # Patch session.exec to see if it gets called
    with patch.object(test_db_session, 'exec', wraps=test_db_session.exec) as spy_exec:
        # First call: should proceed and update LAST_UNVERIFIED_REFRESH_TIME
        refresh_unverified_users(test_db_session, auth0_client)
        assert spy_exec.call_count == 1

        spy_exec.reset_mock()

        # Second call: should hit the global throttle and return immediately
        with patch("db.utils.logger") as mock_logger:
            refresh_unverified_users(test_db_session, auth0_client)

            # Verify the "Skipping refresh" log was emitted
            mock_logger.info.assert_called_once()
            assert "Skipping refresh" in mock_logger.info.call_args[0][0]

            # Crucially: verify the database was NOT queried a second time
            spy_exec.assert_not_called()
            # And Auth0 was never touched
            auth0_client.get_user.assert_not_called()


def test_refresh_unverified_users_updates_status(test_db_session: Session):
    """Verifies that a user's status is updated when Auth0 reports they are now verified."""
    # Create an unverified user
    user = BiocommonsUser(
        id="auth0|123",
        email="test@example.com",
        username="testuser",
        email_verified=False,
    )
    test_db_session.add(user)
    test_db_session.commit()

    # Mock Auth0 to return verified=True
    auth0_client = MagicMock()
    auth0_data = MagicMock()
    auth0_data.email_verified = True
    auth0_client.get_user.return_value = auth0_data

    refresh_unverified_users(test_db_session, auth0_client)

    # Re-fetch user to check update
    db_session_new = Session(test_db_session.bind)  # Use fresh session to avoid cache
    updated_user = db_session_new.exec(select(BiocommonsUser).where(BiocommonsUser.id == "auth0|123")).one()
    assert updated_user.email_verified is True


def test_refresh_unverified_users_skips_verified_users(test_db_session):
    """Verifies that the query only targets users where email_verified is False."""
    user = BiocommonsUser(
        id="auth0|456",
        email="verified@example.com",
        username="verified",
        email_verified=True,
    )
    test_db_session.add(user)
    test_db_session.commit()

    auth0_client = MagicMock()
    refresh_unverified_users(test_db_session, auth0_client)

    # Auth0 should not have been called for this user
    auth0_client.get_user.assert_not_called()


def test_refresh_unverified_users_no_change(test_db_session, persistent_factories):
    """Verifies no DB update occurs if Auth0 still says False."""
    user = BiocommonsUserFactory.create_sync(email_verified=False)
    test_db_session.add(user)
    test_db_session.commit()

    auth0_client = MagicMock()
    auth0_data = MagicMock()
    auth0_data.email_verified = False
    auth0_client.get_user.return_value = auth0_data

    with patch.object(test_db_session, 'add') as mock_add:
        refresh_unverified_users(test_db_session, auth0_client)
        # session.add(user) should NOT be called if status is the same
        mock_add.assert_not_called()
