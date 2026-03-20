from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from httpx import HTTPStatusError
from sqlmodel import Session, select

from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    EmailNotification,
    GroupMembership,
    GroupMembershipHistory,
    Platform,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.types import ApprovalStatusEnum, EmailStatusEnum, PlatformEnum
from scheduled_tasks.email_retry import (
    EMAIL_MAX_ATTEMPTS,
    EMAIL_RETRY_WINDOW_SECONDS,
)
from scheduled_tasks.tasks import (
    ExportedUser,
    UserSyncConflictError,
    _ensure_user_from_auth0,
    _get_group_membership_including_deleted,
    export_auth0_users,
    link_admin_roles,
    parse_auth0_export,
    populate_db_groups,
    process_email_queue,
    send_email_notification,
    sync_auth0_roles,
    sync_auth0_users,
    sync_group_user_roles,
    sync_platform_user_roles,
    update_auth0_user,
    update_auth0_users_batch,
)
from tests.datagen import (
    Auth0UserDataFactory,
    ExportedUserFactory,
    RoleUserDataFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)


def _task_session_iter(bind):
    while True:
        yield Session(bind)


def _get_notification_fresh(test_db_session, notification_id):
    with Session(test_db_session.get_bind()) as fresh_session:
        return fresh_session.get(EmailNotification, notification_id)


@pytest.mark.asyncio
async def test_sync_auth0_users_creates_and_soft_deletes(mocker, test_db_session, persistent_factories):
    """
    Users present in Auth0 are created or updated, while missing users are soft deleted.
    """
    existing_email = "existing.user@example.com"
    existing_username = "existing_user"
    existing_user = BiocommonsUserFactory.create_sync(
        email=existing_email,
        username=existing_username,
        email_verified=False,
    )
    # this is a user which is in our DB, but not in Auth0 anymore
    user_not_in_auth0 = BiocommonsUserFactory.create_sync(
        email="stale.user@example.com",
        username="stale_user",
    )
    existing_user_data = ExportedUserFactory.build(
        user_id=existing_user.id,
        email=existing_email,
        username=existing_username,
        email_verified=True,
        blocked=False,
    )
    new_user_data = ExportedUserFactory.build(
        email="new.user@example.com",
        username="new_user",
        blocked=False
    )
    extra_user_data = ExportedUserFactory.build(
        email="extra.user@example.com",
        username="extra_user",
        blocked=False
    )
    users = [existing_user_data, new_user_data, extra_user_data]
    mocker.patch("scheduled_tasks.tasks.get_settings")
    mocker.patch("scheduled_tasks.tasks.get_management_token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mocker.patch("scheduled_tasks.tasks.export_auth0_users", return_value=users)
    auth0_client = mocker.patch("scheduled_tasks.tasks.Auth0Client").return_value

    def _get_user(user_id):
        if user_id == existing_user.id:
            return existing_user_data
        if user_id == new_user_data.user_id:
            return new_user_data
        if user_id == user_not_in_auth0.id:
            raise HTTPStatusError(
                message="Not Found",
                request=mocker.Mock(),
                response=mocker.Mock(status_code=404),
            )

    auth0_client.get_user.side_effect = _get_user

    await sync_auth0_users()

    test_db_session.refresh(existing_user)
    test_db_session.refresh(user_not_in_auth0)
    created_user = test_db_session.get(BiocommonsUser, new_user_data.user_id)

    assert existing_user.email_verified is True
    assert user_not_in_auth0.is_deleted is True
    assert created_user is not None and created_user.is_deleted is False
    second_created = test_db_session.get(BiocommonsUser, extra_user_data.user_id)
    assert second_created is not None


@pytest.mark.asyncio
async def test_sync_auth0_users_skips_soft_delete_if_user_appears_after_export(
    mocker, test_db_session, persistent_factories
):
    """
    If a user is created in Auth0 after the export is fetched but before the soft-delete pass,
    the user should not be soft deleted once the individual Auth0 lookup confirms they exist.
    """
    existing_user = BiocommonsUserFactory.create_sync(
        email="stale.user@example.com",
        username="stale_user",
    )
    late_user = BiocommonsUserFactory.create_sync(
        email="late.user@example.com",
        username="late_user",
    )

    existing_user_export = ExportedUserFactory.build(
        user_id=existing_user.id,
        email=existing_user.email,
        username=existing_user.username,
        email_verified=True,
        blocked=False,
    )
    exported = [existing_user_export]

    mocker.patch("scheduled_tasks.tasks.get_settings")
    mocker.patch("scheduled_tasks.tasks.get_management_token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mocker.patch("scheduled_tasks.tasks.export_auth0_users", return_value=exported)

    auth0_client = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    auth0_instance = auth0_client.return_value
    auth0_instance.get_user.side_effect = lambda user_id: Auth0UserDataFactory.build(
        user_id=user_id,
        email=late_user.email,
        username=late_user.username,
        email_verified=True,
        blocked=False,
    ) if user_id == late_user.id else (_ for _ in ()).throw(AssertionError("Unexpected user lookup"))

    await sync_auth0_users()

    test_db_session.refresh(existing_user)
    test_db_session.refresh(late_user)

    assert existing_user.is_deleted is False
    assert late_user.is_deleted is False


def test_update_auth0_user_updates_existing(test_db_session, mocker, persistent_factories):
    """
    Updating an existing user applies Auth0 data and commits changes.
    """
    user_data = Auth0UserDataFactory.build(email_verified=True)
    db_user = BiocommonsUserFactory.create_sync(
        id=user_data.user_id,
        email=user_data.email,
        username=user_data.username,
        email_verified=False,
    )
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    update_auth0_user(user_data=user_data, session=test_db_session)
    test_db_session.commit()

    test_db_session.refresh(db_user)
    assert db_user.email_verified is True


def test_update_auth0_user_creates_when_missing(test_db_session, mocker):
    """
    Missing users are created when encountered during the update.
    """
    user_data = Auth0UserDataFactory.build()
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    result = update_auth0_user(user_data=user_data, session=test_db_session)
    test_db_session.commit()

    created = test_db_session.get(BiocommonsUser, user_data.user_id)
    assert result is True
    assert created is not None


@pytest.mark.asyncio
async def test_update_auth0_user_batch_closes_session(mocker):
    """
    Check that the session is closed after the update.
    """
    fake_session = mocker.Mock()
    fake_session.is_modified.return_value = False
    fake_session.commit.return_value = None
    fake_session.close.return_value = None
    fake_user = mocker.Mock()

    mocker.patch("scheduled_tasks.tasks._ensure_user_from_auth0", return_value=(fake_user, False, False))
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(fake_session for _ in range(1)),
    )

    # Empty user list (actual user list does nested transactions + hard to mock)
    await update_auth0_users_batch(users=[])

    fake_session.commit.assert_called_once()
    fake_session.close.assert_called_once()


def test_link_admin_roles_links_platform_and_group(test_db_session):
    # Set up platform and group in DB
    platform = PlatformFactory.build(id=PlatformEnum.GALAXY)
    group = BiocommonsGroupFactory.build(group_id="biocommons/group/testgroup")
    test_db_session.add(platform)
    test_db_session.add(group)
    test_db_session.commit()

    # Admin roles following naming conventions
    platform_role = Auth0RoleFactory.build(name="biocommons/role/galaxy/admin")
    group_role = Auth0RoleFactory.build(name="biocommons/role/testgroup/admin")
    test_db_session.add(platform_role)
    test_db_session.add(group_role)
    test_db_session.flush()

    roles_by_name = {
        platform_role.name: platform_role,
        group_role.name: group_role,
    }

    link_admin_roles(test_db_session, roles_by_name)
    test_db_session.commit()
    platform = Platform.get_by_id(PlatformEnum.GALAXY, test_db_session)
    group = BiocommonsGroup.get_by_id("biocommons/group/testgroup", test_db_session)

    assert platform_role in platform.admin_roles
    assert group_role in group.admin_roles


def test_link_admin_roles_case_insensitive(test_db_session):
    platform = PlatformFactory.build(id=PlatformEnum.GALAXY)
    group = BiocommonsGroupFactory.build(group_id="biocommons/group/casegroup")
    test_db_session.add(platform)
    test_db_session.add(group)
    test_db_session.commit()

    platform_role = Auth0RoleFactory.build(name="biocommons/role/GALAXY/Admin")
    group_role = Auth0RoleFactory.build(name="biocommons/role/CaseGroup/Admin")
    test_db_session.add(platform_role)
    test_db_session.add(group_role)
    test_db_session.flush()

    roles_by_name = {platform_role.name: platform_role, group_role.name: group_role}

    link_admin_roles(test_db_session, roles_by_name)
    test_db_session.commit()

    platform = Platform.get_by_id(PlatformEnum.GALAXY, test_db_session)
    group = BiocommonsGroup.get_by_id("biocommons/group/casegroup", test_db_session)

    assert platform_role in platform.admin_roles
    assert group_role in group.admin_roles


def test_ensure_user_from_auth0_creates_user(test_db_session):
    user_data = Auth0UserDataFactory.build(
        user_id="auth0|ensure_create",
        email="ensure.create@example.com",
        username="ensure_create",
        email_verified=True,
        blocked=False,
    )

    user, created, restored = _ensure_user_from_auth0(test_db_session, user_data)

    test_db_session.flush()
    fetched = test_db_session.get(BiocommonsUser, user_data.user_id)

    assert created is True
    assert restored is False
    assert fetched is not None
    assert fetched.email == "ensure.create@example.com"


def test_ensure_user_from_auth0_restores_soft_deleted(test_db_session, persistent_factories):
    existing_user = BiocommonsUserFactory.create_sync(
        id="auth0|restore_user",
        email="restore.user@example.com",
        username="restore_user",
    )
    existing_user_id = existing_user.id
    existing_user.delete(test_db_session, commit=True)
    user_data = Auth0UserDataFactory.build(
        user_id=existing_user_id,
        email="restore.user@example.com",
        username="restore_user",
        email_verified=True,
        blocked=False,
    )

    user, created, restored = _ensure_user_from_auth0(test_db_session, user_data)

    assert created is False
    assert restored is True
    assert user.is_deleted is False


def test_ensure_user_no_restore_if_blocked(test_db_session, persistent_factories):
    """
    Test users are not restored if they are blocked in Auth0
    """
    existing_user = BiocommonsUserFactory.create_sync(
        id="auth0|restore_user",
        email="restore.user@example.com",
        username="restore_user",
    )
    existing_user_id = existing_user.id
    existing_user.delete(test_db_session, commit=True)
    user_data = Auth0UserDataFactory.build(
        user_id=existing_user_id,
        email="restore.user@example.com",
        username="restore_user",
        email_verified=True,
        blocked=True,
    )

    user, created, restored = _ensure_user_from_auth0(test_db_session, user_data)

    assert created is False
    assert restored is False
    assert user.is_deleted is True


def test_ensure_user_from_auth0_raises_on_username_conflict(test_db_session, persistent_factories):
    existing = BiocommonsUserFactory.create_sync(
        id="auth0|existing-user",
        email="existing.user@example.com",
        username="same_username",
    )
    assert existing is not None

    conflicting_user_data = Auth0UserDataFactory.build(
        user_id="auth0|different-user",
        email="different.user@example.com",
        username="same_username",
        email_verified=True,
        blocked=False,
    )

    with pytest.raises(UserSyncConflictError, match="username 'same_username'"):
        _ensure_user_from_auth0(test_db_session, conflicting_user_data)


def test_get_membership_including_deleted_returns_soft_deleted(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/deleted-check",
        name="Deleted Check",
        short_name="DEL",
    )
    user = BiocommonsUserFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    membership_user_id = membership.user_id
    membership_group_id = membership.group_id
    membership.delete(test_db_session, commit=True)

    retrieved = _get_group_membership_including_deleted(test_db_session, membership_user_id, membership_group_id)

    assert retrieved is not None
    assert retrieved.is_deleted is True


@pytest.mark.asyncio
async def test_sync_auth0_roles_updates_and_soft_deletes(mocker, test_db_session, mock_settings, persistent_factories):
    """
    Roles present in Auth0 are created or updated, missing roles are soft deleted.
    """
    existing_role = Auth0RoleFactory.create_sync(id="role-existing", name="Existing", description="old")
    stale_role = Auth0RoleFactory.create_sync(id="role-stale", name="Stale", description="stale")
    restored_role = Auth0RoleFactory.create_sync(id="role-restored", name="RestoreOld", description="restore old")
    restored_role_id = restored_role.id
    restored_role.delete(test_db_session, commit=True)
    role_existing_data = SimpleNamespace(id=existing_role.id, name="Existing", description="updated")
    role_new_data = SimpleNamespace(id="role-new", name="NewRole", description="brand new")
    role_restored_data = SimpleNamespace(id="role-restored", name="Restored", description="restored desc")
    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [role_existing_data, role_new_data, role_restored_data]
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_client)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await sync_auth0_roles()

    test_db_session.refresh(existing_role)
    test_db_session.refresh(stale_role)
    restored_role_fresh = test_db_session.get(Auth0Role, restored_role_id)
    created_role = test_db_session.get(Auth0Role, role_new_data.id)

    assert existing_role.description == "updated"
    assert stale_role.is_deleted is True
    assert created_role is not None and created_role.name == "NewRole"
    assert restored_role_fresh is not None
    assert restored_role_fresh.is_deleted is False
    assert restored_role_fresh.name == "Restored"


@pytest.mark.asyncio
async def test_sync_auth0_group_roles_syncs_assignments(mocker, test_db_session, mock_settings, persistent_factories):
    """
    User-role assignments from Auth0 are mirrored in the database and stale assignments are soft deleted.
    """
    role = Auth0RoleFactory.create_sync(id="role-1", name="biocommons/group/test", description="desc")
    group = BiocommonsGroupFactory.create_sync(
        group_id=role.name,
        name="Test Group",
        short_name="TEST",
        admin_roles=[role],
    )
    user_remove = BiocommonsUserFactory.create_sync()
    GroupMembershipFactory.create_sync(
        group=group,
        user=user_remove,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    user_pending = BiocommonsUserFactory.create_sync(
        email="pending.user@example.com",
        username="pending_user",
    )
    _ = GroupMembershipFactory.create_sync(
        group=group,
        user=user_pending,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    history_before = test_db_session.exec(
        select(GroupMembershipHistory).where(
            GroupMembershipHistory.user_id == user_pending.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
    ).all()
    user_keep = BiocommonsUserFactory.create_sync(
        email="keep.user@example.com",
        username="keep_user",
    )
    auth0_user_keep = Auth0UserDataFactory.build(
        user_id=user_keep.id,
        email="keep.user@example.com",
        username="keep_user",
    )
    auth0_user_pending = Auth0UserDataFactory.build(
        user_id=user_pending.id,
        email="pending.user@example.com",
        username="pending_user",
    )
    auth0_user_new = Auth0UserDataFactory.build(
        email="new.assignment@example.com",
        username="new_assignment",
    )
    role_user_keep = RoleUserDataFactory.build(user_id=auth0_user_keep.user_id)
    role_user_pending = RoleUserDataFactory.build(user_id=auth0_user_pending.user_id)
    role_user_new = RoleUserDataFactory.build(user_id=auth0_user_new.user_id)

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [
        SimpleNamespace(id=role.id, name=role.name, description=role.description)
    ]
    mock_auth0_client.get_all_role_users.return_value = [
        role_user_keep,
        role_user_pending,
        role_user_new,
    ]
    mock_auth0_client.get_user.side_effect = [
        auth0_user_keep,
        auth0_user_pending,
        auth0_user_new,
    ]
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_client)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await sync_group_user_roles()

    kept_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user_keep.id,
        group_id=group.group_id,
        session=test_db_session,
    )
    new_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=auth0_user_new.user_id,
        group_id=group.group_id,
        session=test_db_session,
    )
    updated_pending_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user_pending.id,
        group_id=group.group_id,
        session=test_db_session,
    )
    removed_membership = test_db_session.exec(
        select(GroupMembership)
        .execution_options(include_deleted=True)
        .where(
            GroupMembership.user_id == user_remove.id,
            GroupMembership.group_id == group.group_id,
        )
    ).one()
    created_user = test_db_session.get(BiocommonsUser, auth0_user_new.user_id)
    history_entries = test_db_session.exec(
        select(GroupMembershipHistory).where(
            GroupMembershipHistory.user_id == user_pending.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
    ).all()

    assert kept_membership is not None
    assert new_membership is not None
    assert updated_pending_membership is not None
    assert updated_pending_membership.approval_status == ApprovalStatusEnum.APPROVED
    assert removed_membership.is_deleted is True
    assert created_user is not None
    assert len(history_entries) > len(history_before)


@pytest.mark.asyncio
async def test_populate_db_groups_only_adds_missing(test_db_session, mocker, mock_settings, persistent_factories):
    """
    Ensure existing groups are skipped and missing ones are inserted then committed.
    """
    class TestGroups(Enum):
        TSI = "biocommons/group/tsi"
        TEST = "biocommons/group/test"

    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    BiocommonsGroupFactory.create_sync(group_id=TestGroups.TSI.value)

    await populate_db_groups(groups=TestGroups)

    added_group = test_db_session.get(BiocommonsGroup, TestGroups.TEST.value)
    assert added_group is not None


@pytest.mark.asyncio
async def test_sync_auth0_platform_roles(mocker, test_db_session, mock_settings, persistent_factories):
    """
    User-role assignments from Auth0 are mirrored in the database and stale assignments are soft deleted.
    """
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/admin")
    platform = PlatformFactory.create_sync(
        id="galaxy",
        name="Galaxy",
        platform_role=platform_role,
        admin_roles=[admin_role],
    )
    user_remove = BiocommonsUserFactory.create_sync()
    PlatformMembershipFactory.create_sync(
        platform=platform,
        user=user_remove,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    user_pending = BiocommonsUserFactory.create_sync(
        email="pending.user@example.com",
        username="pending_user",
    )
    PlatformMembershipFactory.create_sync(
        platform=platform,
        user=user_pending,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    history_before = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.user_id == user_pending.id,
            PlatformMembershipHistory.platform_id == platform.id,
            )
    ).all()
    user_keep = BiocommonsUserFactory.create_sync(
        email="keep.user@example.com",
        username="keep_user",
    )
    auth0_user_keep = Auth0UserDataFactory.build(
        user_id=user_keep.id,
        email="keep.user@example.com",
        username="keep_user",
    )
    auth0_user_pending = Auth0UserDataFactory.build(
        user_id=user_pending.id,
        email="pending.user@example.com",
        username="pending_user",
    )
    auth0_user_new = Auth0UserDataFactory.build(
        email="new.assignment@example.com",
        username="new_assignment",
    )
    role_user_keep = RoleUserDataFactory.build(user_id=auth0_user_keep.user_id)
    role_user_pending = RoleUserDataFactory.build(user_id=auth0_user_pending.user_id)
    role_user_new = RoleUserDataFactory.build(user_id=auth0_user_new.user_id)

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [
        SimpleNamespace(id=platform_role.id, name=platform_role.name, description=platform_role.description)
    ]
    mock_auth0_client.get_all_role_users_generator.return_value = (x for x in [[role_user_keep, role_user_pending], [role_user_new]])
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_client)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mocker.patch(
        "scheduled_tasks.tasks.export_auth0_users",
        return_value=[ExportedUser(user_id=u.user_id, email=u.email, email_verified=u.email_verified,
                                   username=u.username, blocked=u.blocked, updated_at=u.updated_at)
                      for u in [auth0_user_keep, auth0_user_pending, auth0_user_new]]
    )

    await sync_platform_user_roles()

    kept_membership = PlatformMembership.get_by_user_id_and_platform_id(
        user_id=user_keep.id,
        platform_id=platform.id,
        session=test_db_session,
    )
    new_membership = PlatformMembership.get_by_user_id_and_platform_id(
        user_id=auth0_user_new.user_id,
        platform_id=platform.id,
        session=test_db_session,
    )
    updated_pending_membership = PlatformMembership.get_by_user_id_and_platform_id(
        user_id=user_pending.id,
        platform_id=platform.id,
        session=test_db_session,
    )
    removed_membership = test_db_session.exec(
        select(PlatformMembership)
        .execution_options(include_deleted=True)
        .where(
            PlatformMembership.user_id == user_remove.id,
            PlatformMembership.platform_id == platform.id,
            )
    ).one()
    created_user = test_db_session.get(BiocommonsUser, auth0_user_new.user_id)
    history_entries = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.user_id == user_pending.id,
            PlatformMembershipHistory.platform_id == platform.id,
            )
    ).all()

    assert kept_membership is not None
    assert new_membership is not None
    assert updated_pending_membership is not None
    assert updated_pending_membership.approval_status == ApprovalStatusEnum.APPROVED
    assert removed_membership.is_deleted is True
    assert created_user is not None
    assert len(history_entries) > len(history_before)


@pytest.mark.asyncio
async def test_process_email_queue_sends_notifications(test_db_session, mock_settings, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=mock_settings.no_reply_email_sender,
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    mock_service = mocker.Mock()
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 1
    mock_scheduler.assert_called_once()
    await send_email_notification(notification_id)
    updated = _get_notification_fresh(test_db_session, notification_id)
    assert updated.status == EmailStatusEnum.SENT
    mock_service.send.assert_called_once_with(
        "user@example.com",
        "Hello",
        "<p>Test</p>",
        settings=mock_settings
    )


@pytest.mark.asyncio
async def test_send_email_notification_retries_transient_errors(test_db_session, mock_settings, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=mock_settings.no_reply_email_sender,
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    mock_service = mocker.Mock()
    mock_service.send.side_effect = EndpointConnectionError(endpoint_url="https://ses")
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")
    mocker.patch("scheduled_tasks.tasks.next_retry_delay_seconds", return_value=900)

    scheduled = await process_email_queue()

    assert scheduled == 1
    mock_scheduler.assert_called_once()
    await send_email_notification(notification_id)
    updated = _get_notification_fresh(test_db_session, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.last_error is not None
    assert updated.send_after is not None
    delay = (updated.send_after - updated.updated_at).total_seconds()
    assert delay == pytest.approx(900, abs=0.1)


@pytest.mark.asyncio
async def test_send_email_notification_does_not_retry_non_transient_error(test_db_session, mock_settings, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=mock_settings.no_reply_email_sender,
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    error = ClientError(
        error_response={
            "Error": {
                "Code": "MessageRejected",
                "Message": "Address blacklisted",
            }
        },
        operation_name="SendEmail",
    )
    mock_service = mocker.Mock()
    mock_service.send.side_effect = error
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    await process_email_queue()
    await send_email_notification(notification_id)
    updated = _get_notification_fresh(test_db_session, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None


@pytest.mark.asyncio
async def test_process_email_queue_skips_when_max_attempts_reached(test_db_session, mock_settings, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=mock_settings.no_reply_email_sender,
        subject="Hello",
        body_html="<p>Test</p>",
        status=EmailStatusEnum.FAILED,
        attempts=EMAIL_MAX_ATTEMPTS,
        send_after=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    test_db_session.add(notification)
    notification_id = notification.id
    test_db_session.commit()

    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 0
    mock_scheduler.assert_not_called()
    updated = _get_notification_fresh(test_db_session, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None


@pytest.mark.asyncio
async def test_process_email_queue_skips_when_retry_window_exceeded(test_db_session, mock_settings, mocker):
    first_attempt = datetime.now(timezone.utc) - timedelta(
        seconds=EMAIL_RETRY_WINDOW_SECONDS + 60
    )
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=mock_settings.no_reply_email_sender,
        subject="Hello",
        body_html="<p>Test</p>",
        status=EmailStatusEnum.FAILED,
        attempts=1,
        send_after=datetime.now(timezone.utc) - timedelta(minutes=5),
        last_attempt_at=first_attempt,
    )
    test_db_session.add(notification)
    notification_id = notification.id
    test_db_session.commit()

    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 0
    mock_scheduler.assert_not_called()
    updated = _get_notification_fresh(test_db_session, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None


def test_parse_auth0_export_parses_csv_file(tmp_path):
    csv_path = tmp_path / "auth0_users.csv"
    csv_path.write_text(
        "user_id,email,email_verified,username,blocked,updated_at\n"
        "'auth0|u1,'u1@example.com,True,'u1,False,2024-01-01T12:00:00+00:00\n"
        "'auth0|u2,'u2@example.com,,,,2024-01-02T12:00:00+00:00\n",
        encoding="utf-8",
    )

    users = parse_auth0_export(csv_path)

    assert len(users) == 2
    assert all(isinstance(u, ExportedUser) for u in users)

    assert users[0].user_id == "auth0|u1"
    assert users[0].email == "u1@example.com"
    assert users[0].email_verified is True
    assert users[0].username == "u1"
    assert users[0].blocked is False
    assert users[0].updated_at.isoformat() == "2024-01-01T12:00:00+00:00"


    assert users[1].user_id == "auth0|u2"
    assert users[1].email == "u2@example.com"
    # Check empty bools parse as False
    assert users[1].blocked is False
    assert users[1].email_verified is False
    # Check empty username parses as None
    assert users[1].username is None
    assert users[1].updated_at.isoformat() == "2024-01-02T12:00:00+00:00"


@pytest.mark.asyncio
async def test_export_auth0_users_writes_temp_csv_file(mocker):
    """
    Test that export_auth0_users() calls export_and_download_users with a path that exists,
    and that the CSV file exists (was written) before parsing.
    """
    csv_existed_at_parse_time = False
    csv_path: Path | None = None

    def _fake_export_and_download_users(*, download_path, fields):
        # Simulate Auth0Client writing the file to the provided temp path
        download_path.write_text(
            "user_id,email,email_verified,username,blocked,updated_at\n"
            "'auth0|u1,'u1@example.com,True,'u1,False,2024-01-01T12:00:00+00:00\n",
            encoding="utf-8",
        )

    def _parse_spy(path):
        nonlocal csv_existed_at_parse_time
        nonlocal csv_path
        csv_path = path
        csv_existed_at_parse_time = path.exists()
        # Return a minimal valid parsed result (we test parse_auth0_export separately)
        return [
            ExportedUser(
                user_id="auth0|u1",
                email="u1@example.com",
                email_verified=True,
                username="u1",
                blocked=False,
                updated_at="2024-01-01T12:00:00+00:00",
            )
        ]

    mocker.patch("scheduled_tasks.tasks.parse_auth0_export", side_effect=_parse_spy)

    auth0_client = MagicMock()
    auth0_client.export_and_download_users.side_effect = _fake_export_and_download_users

    users = await export_auth0_users(auth0_client)

    auth0_client.export_and_download_users.assert_called_once()
    assert csv_existed_at_parse_time is True
    # Path should be deleted after parsing
    assert not csv_path.exists()
    assert len(users) == 1
    assert users[0].user_id == "auth0|u1"
