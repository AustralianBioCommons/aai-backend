from unittest.mock import MagicMock

import pytest

from scheduled_tasks.tasks import sync_auth0_users, update_auth0_user
from tests.datagen import Auth0UserDataFactory, UsersWithTotalsFactory
from tests.db.datagen import BiocommonsUserFactory


@pytest.mark.asyncio
async def test_sync_auth0_users(mocker, test_client):
    """
    Test syncing Auth0 users - users are fetched until the total is reached,
    update task is scheduled for each user
    """
    mock_auth0_instance = MagicMock()
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_instance)
    mocker.patch("scheduled_tasks.tasks.get_settings")
    mocker.patch("scheduled_tasks.tasks.get_management_token")
    batch1 = UsersWithTotalsFactory.build(total=20, start=0, limit=10)
    batch2 = UsersWithTotalsFactory.build(total=20, start=10, limit=10)
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER")
    mock_auth0_instance.get_users.side_effect = [batch1, batch2]
    await sync_auth0_users()
    assert mock_auth0_instance.get_users.call_count == 2
    # Check add_job was called for the number of users
    assert mock_scheduler.add_job.call_count == 20


@pytest.mark.asyncio
async def test_update_auth0_user(test_db_session, mocker, persistent_factories):
    """
    Test email_verified is updated correctly when updating user from Auth0
    """
    user_data = Auth0UserDataFactory.build(
        email_verified=True
    )
    db_user = BiocommonsUserFactory.create_sync(
        id=user_data.user_id,
        email=user_data.email,
        username=user_data.username,
        email_verified=False
    )
    mocker.patch("scheduled_tasks.tasks.get_db_session",
                 # Needs to be a generator that yields the session
                 return_value=(test_db_session for _ in range(1)))
    await update_auth0_user(user_data=user_data)
    test_db_session.flush()
    test_db_session.refresh(db_user)
    assert db_user.email_verified is True
