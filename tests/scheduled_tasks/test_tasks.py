from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from db.types import GroupEnum
from scheduled_tasks.tasks import (
    populate_db_groups,
    sync_auth0_roles,
    sync_auth0_users,
    update_auth0_user,
)
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


@pytest.mark.asyncio
async def test_update_auth0_user_returns_false_when_not_found(mocker):
    """
    Ensure we exit early when the Auth0 user does not exist in the DB.
    """
    user_data = Auth0UserDataFactory.build()
    fake_session = MagicMock()
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(fake_session for _ in range(1)),
    )
    mocker.patch("scheduled_tasks.tasks.BiocommonsUser.get_by_id", return_value=None)

    result = await update_auth0_user(user_data=user_data)

    assert result is False
    fake_session.commit.assert_not_called()


@pytest.mark.asyncio
async def test_update_auth0_user_no_changes(test_db_session, mocker, persistent_factories):
    """
    When nothing changes we still commit, but the 'unchanged' branch is logged.
    """
    user_data = Auth0UserDataFactory.build(email_verified=True)
    BiocommonsUserFactory.create_sync(
        id=user_data.user_id,
        email=user_data.email,
        username=user_data.username,
        email_verified=True,
    )
    commit_spy = mocker.spy(test_db_session, "commit")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(test_db_session for _ in range(1)),
    )
    mocker.patch.object(test_db_session, "is_modified", return_value=False)

    result = await update_auth0_user(user_data=user_data)

    assert result is True
    assert commit_spy.call_count == 1


@pytest.mark.asyncio
async def test_sync_auth0_roles_creates_missing_roles(mocker, mock_settings):
    """
    Verify Auth0 roles missing in the DB are created while existing ones are skipped.
    """
    role_existing = SimpleNamespace(id="role-1", name="Existing", description="already there")
    role_missing = SimpleNamespace(id="role-2", name="NewRole", description="brand new")
    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [role_existing, role_missing]
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_client)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    fake_session = MagicMock()
    fake_session.begin.return_value = nullcontext()
    fake_session.get.side_effect = [object(), None]
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(fake_session for _ in range(1)),
    )

    await sync_auth0_roles()

    assert fake_session.get.call_count == 2
    fake_session.add.assert_called_once()
    added_role = fake_session.add.call_args[0][0]
    assert added_role.id == role_missing.id
    assert added_role.name == role_missing.name


@pytest.mark.asyncio
async def test_populate_db_groups_only_adds_missing(mocker, mock_settings):
    """
    Ensure existing groups are skipped and missing ones are inserted then committed.
    """
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    fake_session = MagicMock()
    fake_session.begin.return_value = nullcontext()
    fake_session.commit = MagicMock()
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(fake_session for _ in range(1)),
    )
    mocker.patch(
        "scheduled_tasks.tasks.BiocommonsGroup.get_by_id",
        side_effect=[object(), None],
    )

    await populate_db_groups()

    fake_session.add.assert_called_once()
    added_group = fake_session.add.call_args[0][0]
    assert added_group.group_id == GroupEnum.BPA_GALAXY.value
    fake_session.commit.assert_called_once()
