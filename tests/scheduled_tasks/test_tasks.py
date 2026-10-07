from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
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
from db.types import ApprovalStatusEnum, EmailStatusEnum, GroupEnum, PlatformEnum
from scheduled_tasks.email_retry import (
    EMAIL_MAX_ATTEMPTS,
    EMAIL_RETRY_WINDOW_SECONDS,
)
from scheduled_tasks.sync.memberships import (
    MembershipSyncResult,
    MembershipSyncSummary,
    sync_one_group_membership,
)
from scheduled_tasks.sync.memberships import (
    sync_group_memberships_for_role as sync_group_memberships_for_role_new,
)
from scheduled_tasks.sync.memberships import (
    sync_platform_memberships_for_role as sync_platform_memberships_for_role_new,
)
from scheduled_tasks.sync.users import (
    Auth0ExportIdentityIndex,
    UserSyncAction,
    UserSyncConflictError,
    UserSyncRecord,
    UserSyncSummary,
    normalize_auth0_user,
    normalize_exported_user,
    soft_delete_users_missing_from_auth0,
    sync_exported_users,
    sync_one_user,
    sync_users_from_records,
)
from scheduled_tasks.tasks import (
    ExportedUser,
    export_auth0_users,
    link_admin_roles,
    parse_auth0_json_export,
    populate_db_groups,
    populate_platforms_from_auth0,
    process_email_queue,
    send_email_notification,
    sync_auth0_roles,
    sync_auth0_users,
    sync_group_user_roles,
    sync_platform_user_roles,
)
from schemas.biocommons import BiocommonsUserAccountType
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
        session = Session(bind)
        try:
            yield session
        finally:
            session.close()


def _get_notification_fresh(test_db_session, notification_id):
    with Session(test_db_session.get_bind()) as fresh_session:
        return fresh_session.get(EmailNotification, notification_id)


def test_sync_exported_users_creates_updates_and_soft_deletes(test_db_session, persistent_factories):
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

    summary = sync_exported_users(test_db_session, users, batch_size=2, commit=False)
    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list(users),
        commit=False,
    )
    test_db_session.flush()

    test_db_session.refresh(existing_user)
    test_db_session.refresh(user_not_in_auth0)
    created_user = test_db_session.get(BiocommonsUser, new_user_data.user_id)

    assert summary.updated == 1
    assert summary.created == 2
    assert deleted == 1
    assert existing_user.email_verified is True
    assert user_not_in_auth0.is_deleted is True
    assert created_user is not None and created_user.is_deleted is False
    second_created = test_db_session.get(BiocommonsUser, extra_user_data.user_id)
    assert second_created is not None


def test_soft_delete_users_missing_from_auth0_keeps_user_seen_by_linked_identity(
    test_db_session, persistent_factories
):
    """
    Linked AAF users may appear in Auth0 export identities rather than as the top-level ID.
    """
    linked_user = BiocommonsUserFactory.create_sync(
        id="auth0|primary",
        other_user_id="oidc|AAF|linked-aaf",
        email="linked.aaf@example.com",
        username="linked_aaf",
        account_type=BiocommonsUserAccountType.AAF,
    )

    exported = [
        ExportedUser(
            user_id="auth0|export-row",
            email=linked_user.email,
            username=linked_user.username,
            email_verified=True,
            blocked=False,
            updated_at="2024-01-01T12:00:00+00:00",
            identities=[
                {
                    "connection": "AAF",
                    "provider": "oidc",
                    "user_id": "linked-aaf",
                    "isSocial": False,
                }
            ],
        )
    ]

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list(exported),
        commit=False,
    )

    assert deleted == 0
    assert linked_user.is_deleted is False


def test_soft_delete_users_missing_from_auth0_skips_ambiguous_aaf_user(
    test_db_session, persistent_factories, mocker
):
    user = BiocommonsUserFactory.create_sync(
        id="auth0|aaf-without-link",
        other_user_id=None,
        email="aaf.without.link@example.com",
        username="aaf_without_link",
        account_type=BiocommonsUserAccountType.AAF,
    )
    warning = mocker.patch("scheduled_tasks.sync.users.logger.warning")
    exported = [
        ExportedUserFactory.build(
            user_id="auth0|other",
            email="other@example.com",
            username="other_user",
            blocked=False,
        )
    ]

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list(exported),
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    warning.assert_called_once()


def test_sync_one_user_updates_existing(test_db_session, persistent_factories):
    """
    Updating an existing user applies Auth0 data.
    """
    user_data = Auth0UserDataFactory.build(email_verified=True)
    db_user = BiocommonsUserFactory.create_sync(
        id=user_data.user_id,
        email=user_data.email,
        username=user_data.username,
        email_verified=False,
    )

    result = sync_one_user(test_db_session, normalize_auth0_user(user_data))
    test_db_session.flush()

    test_db_session.refresh(db_user)
    assert result.action == UserSyncAction.UPDATED
    assert db_user.email_verified is True


def test_sync_one_user_creates_when_missing(test_db_session):
    """
    Missing users are created by user sync.
    """
    user_data = Auth0UserDataFactory.build()

    result = sync_one_user(test_db_session, normalize_auth0_user(user_data))
    test_db_session.flush()

    created = test_db_session.get(BiocommonsUser, user_data.user_id)
    assert result.action == UserSyncAction.CREATED
    assert created is not None


def test_sync_users_from_records_commits_each_batch(test_db_session, mocker):
    """
    Batch sync commits after each batch.
    """
    records = [
        normalize_exported_user(
            ExportedUserFactory.build(
                email=f"user{index}@example.com",
                username=f"user_{index}",
                blocked=False,
            )
        )
        for index in range(3)
    ]
    commit_spy = mocker.spy(test_db_session, "commit")

    summary = sync_users_from_records(
        test_db_session,
        records,
        batch_size=2,
        commit=True,
    )

    assert summary.created == 3
    assert commit_spy.call_count == 2


def test_sync_one_user_creates_user(test_db_session):
    user_data = Auth0UserDataFactory.build(
        user_id="auth0|ensure_create",
        email="ensure.create@example.com",
        username="ensure_create",
        email_verified=True,
        blocked=False,
    )

    result = sync_one_user(test_db_session, normalize_auth0_user(user_data))

    test_db_session.flush()
    fetched = test_db_session.get(BiocommonsUser, user_data.user_id)

    assert result.action == UserSyncAction.CREATED
    assert fetched is not None
    assert fetched.email == "ensure.create@example.com"


@pytest.mark.asyncio
async def test_sync_auth0_users_uses_new_sync_code(mocker, test_db_session, mock_settings):
    exported_user = ExportedUserFactory.build(
        email="exported.user@example.com",
        username="exported_user",
        blocked=False,
    )
    auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    auth0_client = auth0_client_cm.return_value.__enter__.return_value
    auth0_client.get_connection_by_name.return_value = SimpleNamespace(id="con-db")
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    export = mocker.patch(
        "scheduled_tasks.tasks.export_auth0_users",
        return_value=[exported_user],
    )
    sync_export = mocker.patch(
        "scheduled_tasks.tasks.sync_exported_users",
        return_value=UserSyncSummary(created=1),
    )
    soft_delete = mocker.patch(
        "scheduled_tasks.tasks.soft_delete_users_missing_from_auth0",
        return_value=2,
    )

    summary = await sync_auth0_users(batch_size=123)

    export.assert_awaited_once_with(auth0_client)
    sync_export.assert_called_once()
    assert sync_export.call_args.args[1] == [exported_user]
    assert sync_export.call_args.kwargs["batch_size"] == 123
    soft_delete.assert_called_once()
    assert soft_delete.call_args.kwargs["auth0_client"] is auth0_client
    assert soft_delete.call_args.kwargs["batch_size"] == 123
    assert summary.created == 1
    assert summary.soft_deleted == 2


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


def test_link_admin_roles_splits_sbp_service_and_bundle(test_db_session):
    """SBP has two separate admin roles: the service admin role
    (biocommons/role/sbp/admin) links only to the SBP platform, and the bundle
    admin role (biocommons/role/sbp_workflow_execution/admin) links only to the
    SBP bundle group."""
    from db.types import GroupEnum

    platform = PlatformFactory.build(id=PlatformEnum.SBP)
    group = BiocommonsGroupFactory.build(group_id=GroupEnum.SBP.value)
    test_db_session.add(platform)
    test_db_session.add(group)
    test_db_session.commit()

    service_admin_role = Auth0RoleFactory.build(name="biocommons/role/sbp/admin")
    bundle_admin_role = Auth0RoleFactory.build(
        name="biocommons/role/sbp_workflow_execution/admin"
    )
    test_db_session.add(service_admin_role)
    test_db_session.add(bundle_admin_role)
    test_db_session.flush()

    link_admin_roles(
        test_db_session,
        {
            service_admin_role.name: service_admin_role,
            bundle_admin_role.name: bundle_admin_role,
        },
    )
    test_db_session.commit()

    platform = Platform.get_by_id(PlatformEnum.SBP, test_db_session)
    group = BiocommonsGroup.get_by_id(GroupEnum.SBP.value, test_db_session)

    # Service admin role gates the platform only
    assert service_admin_role in platform.admin_roles
    assert service_admin_role not in group.admin_roles
    # Bundle admin role gates the bundle group only
    assert bundle_admin_role in group.admin_roles
    assert bundle_admin_role not in platform.admin_roles


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


def test_sync_one_user_restores_soft_deleted(test_db_session, persistent_factories):
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

    result = sync_one_user(test_db_session, normalize_auth0_user(user_data))

    assert result.action == UserSyncAction.RESTORED
    assert result.user is not None
    assert result.user.is_deleted is False


def test_sync_one_user_no_restore_if_blocked(test_db_session, persistent_factories):
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

    result = sync_one_user(test_db_session, normalize_auth0_user(user_data))
    fetched = BiocommonsUser.get_by_id(
        existing_user_id,
        test_db_session,
        include_deleted=True,
    )

    assert result.action == UserSyncAction.SKIPPED_UNCHANGED
    assert fetched is not None
    assert fetched.is_deleted is True


def test_sync_one_user_raises_on_username_conflict(test_db_session, persistent_factories):
    existing = BiocommonsUserFactory.build(
        id="auth0|existing-user",
        email="existing.user@example.com",
        username="same_username",
    )
    test_db_session.add(existing)
    test_db_session.flush()
    assert existing is not None

    conflicting_user = UserSyncRecord(
        user_id="auth0|different-user",
        email="different.user@example.com",
        username="same_username",
        email_verified=True,
        blocked=False,
        account_type=BiocommonsUserAccountType.AUTH0,
    )

    with pytest.raises(UserSyncConflictError, match="username 'same_username'"):
        sync_one_user(test_db_session, conflicting_user)


def test_sync_one_group_membership_restores_soft_deleted(test_db_session, persistent_factories):
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
    membership.delete(test_db_session, commit=True)

    result = sync_one_group_membership(
        test_db_session,
        user_id=user.id,
        group_id=group.group_id,
    )
    restored_membership = GroupMembership.get_by_user_id_and_group_id(
        user.id,
        group.group_id,
        test_db_session,
        include_deleted=True,
    )

    assert result == MembershipSyncResult.RESTORED
    assert restored_membership is not None
    assert restored_membership.is_deleted is False


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
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
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
async def test_sync_group_memberships_for_role_syncs_assignments(test_db_session, persistent_factories):
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
    GroupMembershipFactory.create_sync(
        group=group,
        user=user_keep,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    user_new = BiocommonsUserFactory.create_sync(
        email="new.assignment@example.com",
        username="new_assignment",
    )
    role_user_keep = RoleUserDataFactory.build(user_id=user_keep.id)
    role_user_pending = RoleUserDataFactory.build(user_id=user_pending.id)
    role_user_new = RoleUserDataFactory.build(user_id=user_new.id)
    role_user_missing = RoleUserDataFactory.build(user_id="auth0|missing")

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_role_users_generator.return_value = [
        [
            role_user_keep,
            role_user_pending,
            role_user_new,
            role_user_missing,
        ]
    ]

    summary = await sync_group_memberships_for_role_new(
        SimpleNamespace(id=role.id, name=role.name, description=role.description),
        mock_auth0_client,
        test_db_session,
        batch_size=2,
        commit=False,
    )

    kept_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user_keep.id,
        group_id=group.group_id,
        session=test_db_session,
    )
    new_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user_new.id,
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
    history_entries = test_db_session.exec(
        select(GroupMembershipHistory).where(
            GroupMembershipHistory.user_id == user_pending.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
    ).all()
    missing_user = test_db_session.get(BiocommonsUser, "auth0|missing")

    assert summary.created == 1
    assert summary.status_changed == 1
    assert summary.soft_deleted == 1
    assert summary.skipped_missing_user == 1
    assert kept_membership is not None
    assert new_membership is not None
    assert updated_pending_membership is not None
    assert updated_pending_membership.approval_status == ApprovalStatusEnum.APPROVED
    assert removed_membership.is_deleted is True
    assert missing_user is None
    assert len(history_entries) > len(history_before)
    mock_auth0_client.get_user.assert_not_called()


@pytest.mark.asyncio
async def test_sync_auth0_group_roles_skips_sbp_when_disabled(mocker, test_db_session, mock_settings):
    mock_settings.sbp_enabled = False
    tsi_role = SimpleNamespace(id="role-tsi", name=GroupEnum.TSI.value, description="TSI")
    sbp_role = SimpleNamespace(id="role-sbp", name=GroupEnum.SBP.value, description="SBP")

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [tsi_role, sbp_role]
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
    sync_role = mocker.patch(
        "scheduled_tasks.tasks.sync_group_memberships_for_role",
        new=AsyncMock(),
    )
    sync_role.return_value = MembershipSyncSummary()
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await sync_group_user_roles(batch_size=123)

    sync_role.assert_awaited_once()
    assert sync_role.await_args.args[0] is tsi_role
    assert sync_role.await_args.kwargs["batch_size"] == 123


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
async def test_populate_db_groups_adds_sbp_with_expected_metadata(
    test_db_session, mocker, mock_settings, persistent_factories
):
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await populate_db_groups()

    sbp_group = test_db_session.get(BiocommonsGroup, "biocommons/group/sbp_workflow_execution")
    assert sbp_group is not None
    assert sbp_group.name == "Structural Biology Platform Bundle"
    assert sbp_group.short_name == "SBP"


@pytest.mark.asyncio
async def test_sync_platform_memberships_for_role_syncs_assignments(test_db_session, persistent_factories):
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
    PlatformMembershipFactory.create_sync(
        platform=platform,
        user=user_keep,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    user_new = BiocommonsUserFactory.create_sync(
        email="new.assignment@example.com",
        username="new_assignment",
    )
    role_user_keep = RoleUserDataFactory.build(user_id=user_keep.id)
    role_user_pending = RoleUserDataFactory.build(user_id=user_pending.id)
    role_user_new = RoleUserDataFactory.build(user_id=user_new.id)
    role_user_missing = RoleUserDataFactory.build(user_id="auth0|missing")

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_role_users_generator.return_value = [
        [role_user_keep, role_user_pending],
        [role_user_new, role_user_missing],
    ]

    summary = await sync_platform_memberships_for_role_new(
        SimpleNamespace(
            id=platform_role.id,
            name=platform_role.name,
            description=platform_role.description,
        ),
        mock_auth0_client,
        test_db_session,
        batch_size=2,
        commit=False,
    )

    kept_membership = PlatformMembership.get_by_user_id_and_platform_id(
        user_id=user_keep.id,
        platform_id=platform.id,
        session=test_db_session,
    )
    new_membership = PlatformMembership.get_by_user_id_and_platform_id(
        user_id=user_new.id,
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
    history_entries = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.user_id == user_pending.id,
            PlatformMembershipHistory.platform_id == platform.id,
            )
    ).all()
    missing_user = test_db_session.get(BiocommonsUser, "auth0|missing")

    assert summary.created == 1
    assert summary.status_changed == 1
    assert summary.soft_deleted == 1
    assert summary.skipped_missing_user == 1
    assert kept_membership is not None
    assert new_membership is not None
    assert updated_pending_membership is not None
    assert updated_pending_membership.approval_status == ApprovalStatusEnum.APPROVED
    assert removed_membership.is_deleted is True
    assert missing_user is None
    assert len(history_entries) > len(history_before)
    mock_auth0_client.get_user.assert_not_called()


@pytest.mark.asyncio
async def test_sync_auth0_platform_roles_skips_sbp_when_disabled(mocker, test_db_session, mock_settings):
    mock_settings.sbp_enabled = False
    galaxy_role = SimpleNamespace(
        id="role-galaxy",
        name="biocommons/platform/galaxy",
        description="Galaxy",
    )
    sbp_role = SimpleNamespace(
        id="role-sbp",
        name="biocommons/platform/sbp",
        description="SBP",
    )

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [galaxy_role, sbp_role]
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
    sync_role = mocker.patch(
        "scheduled_tasks.tasks.sync_platform_memberships_for_role",
        new=AsyncMock(),
    )
    sync_role.return_value = MembershipSyncSummary()
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await sync_platform_user_roles(batch_size=123)

    sync_role.assert_awaited_once()
    assert sync_role.await_args.args[0] is galaxy_role
    assert sync_role.await_args.kwargs["batch_size"] == 123


@pytest.mark.asyncio
async def test_populate_platforms_from_auth0_creates_missing_platform_and_links_admin_roles(
    mocker, test_db_session, mock_settings, persistent_factories
):
    admin_role = Auth0RoleFactory.create_sync(
        id="role-galaxy-admin",
        name="biocommons/role/galaxy/admin",
        description="Galaxy Admin",
    )
    platform_role_data = SimpleNamespace(
        id="role-galaxy-platform",
        name="biocommons/platform/galaxy",
        description="Galaxy Platform",
    )
    ignored_role = SimpleNamespace(
        id="role-ignore",
        name="biocommons/role/not-a-platform/admin",
        description="Ignore",
    )

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [platform_role_data, ignored_role]
    mock_auth0_client.get_role_by_id.return_value = platform_role_data
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )
    link_admin_roles_spy = mocker.spy(__import__("scheduled_tasks.tasks", fromlist=["link_admin_roles"]), "link_admin_roles")

    await populate_platforms_from_auth0()

    created_platform = Platform.get_by_id(PlatformEnum.GALAXY, test_db_session)
    created_platform_role = test_db_session.get(Auth0Role, platform_role_data.id)

    assert created_platform is not None
    assert created_platform.role_id == platform_role_data.id
    assert created_platform.name == platform_role_data.description
    assert created_platform_role is not None
    assert admin_role in created_platform.admin_roles
    link_admin_roles_spy.assert_called_once()


@pytest.mark.asyncio
async def test_populate_platforms_from_auth0_updates_existing_platform(
    mocker, test_db_session, mock_settings, persistent_factories
):
    Auth0RoleFactory.create_sync(
        id="role-galaxy-admin",
        name="biocommons/role/galaxy/admin",
        description="Galaxy Admin",
    )
    existing_platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Old Galaxy",
        role_id="old-role-id",
    )
    platform_role_data = SimpleNamespace(
        id="role-galaxy-platform-updated",
        name="biocommons/platform/galaxy",
        description="Galaxy Updated",
    )

    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [platform_role_data]
    mock_auth0_client.get_role_by_id.return_value = platform_role_data
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=_task_session_iter(test_db_session.get_bind()),
    )

    await populate_platforms_from_auth0()

    test_db_session.refresh(existing_platform)
    created_platform_role = test_db_session.get(Auth0Role, platform_role_data.id)

    assert existing_platform.role_id == platform_role_data.id
    assert existing_platform.name == platform_role_data.description
    assert created_platform_role is not None


@pytest.mark.asyncio
async def test_populate_platforms_from_auth0_closes_db_session_on_error(mocker, mock_settings):
    platform_role_data = SimpleNamespace(
        id="role-galaxy-platform",
        name="biocommons/platform/galaxy",
        description="Galaxy Platform",
    )
    fake_role = Auth0RoleFactory.build(
        id=platform_role_data.id,
        name=platform_role_data.name,
        description=platform_role_data.description,
    )
    fake_session = mocker.MagicMock()
    fake_session.begin.return_value = mocker.MagicMock()
    mock_auth0_client = MagicMock()
    mock_auth0_client.get_all_roles.return_value = [platform_role_data]
    mock_auth0_client_cm = mocker.patch("scheduled_tasks.tasks.Auth0Client")
    mock_auth0_client_cm.return_value.__enter__.return_value = mock_auth0_client
    mocker.patch("scheduled_tasks.tasks.get_settings", return_value=mock_settings)
    mocker.patch("scheduled_tasks.tasks.get_management_token", return_value="token")
    mocker.patch("scheduled_tasks.tasks.get_db_session", return_value=iter([fake_session]))
    mocker.patch("scheduled_tasks.tasks.Auth0Role.get_by_id", return_value=None)
    mocker.patch("scheduled_tasks.tasks.Auth0Role.get_or_create_by_id", return_value=fake_role)
    mocker.patch("scheduled_tasks.tasks.Platform.get_by_id", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.Platform.create_from_auth0_role",
        side_effect=RuntimeError("platform create failed"),
    )

    with pytest.raises(RuntimeError, match="platform create failed"):
        await populate_platforms_from_auth0()

    fake_session.close.assert_called_once()


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


def test_parse_auth0_json_export_parses_user_metadata(tmp_path):
    json_path = tmp_path / "auth0_users.json"
    json_path.write_text(
        '{"user_id":"auth0|u1","email":"u1@example.com","email_verified":true,'
        '"username":"u1","metadata_username":"metadata_u1","blocked":false,'
        '"updated_at":"2024-01-01T12:00:00+00:00",'
        '"aaf_only":true,"aaf_registration_complete":true}\n'
        '{"user_id":"auth0|u2","email":"u2@example.com",'
        '"updated_at":"2024-01-02T12:00:00+00:00",'
        '"linking_completed":true,'
        '"linking_completed_at":"2024-01-03T12:00:00+00:00"}\n',
        encoding="utf-8",
    )

    users = parse_auth0_json_export(json_path)

    assert len(users) == 2
    assert all(isinstance(u, ExportedUser) for u in users)

    assert users[0].user_id == "auth0|u1"
    assert users[0].email == "u1@example.com"
    assert users[0].email_verified is True
    assert users[0].username == "u1"
    assert users[0].metadata_username == "metadata_u1"
    assert users[0].blocked is False
    assert users[0].updated_at.isoformat() == "2024-01-01T12:00:00+00:00"
    assert users[0].account_type == BiocommonsUserAccountType.AAF
    assert users[0].aaf_only is True
    assert users[0].aaf_registration_complete is True
    assert users[0].linking_completed is None
    assert users[0].linking_completed_at is None

    assert users[1].user_id == "auth0|u2"
    assert users[1].email == "u2@example.com"
    assert users[1].blocked is False
    assert users[1].email_verified is None
    assert users[1].username is None
    assert users[1].metadata_username is None
    assert users[1].updated_at.isoformat() == "2024-01-02T12:00:00+00:00"
    assert users[1].account_type == BiocommonsUserAccountType.AUTH0
    assert users[1].aaf_only is None
    assert users[1].aaf_registration_complete is None
    assert users[1].linking_completed is True
    assert users[1].linking_completed_at.isoformat() == "2024-01-03T12:00:00+00:00"


def test_parse_auth0_json_export_defaults_account_type_when_field_missing(tmp_path):
    json_path = tmp_path / "auth0_users.json"
    json_path.write_text(
        '{"user_id":"auth0|u1","email":"u1@example.com",'
        '"email_verified":true,"username":"u1","blocked":false,'
        '"updated_at":"2024-01-01T12:00:00+00:00"}\n',
        encoding="utf-8",
    )

    users = parse_auth0_json_export(json_path)

    assert users[0].account_type == BiocommonsUserAccountType.AUTH0


def test_parse_auth0_json_export_parses_nested_identities(tmp_path):
    json_path = tmp_path / "auth0_users.json"
    json_path.write_text(
        '{"user_id":"auth0|u1","email":"u1@example.com","email_verified":true,'
        '"username":"u1","metadata_username":"metadata_u1","blocked":false,'
        '"updated_at":"2024-01-01T12:00:00+00:00","account_type":"aaf",'
        '"aaf_only":false,"linking_completed":true,'
        '"identities":[{"connection":"Username-Password-Authentication",'
        '"provider":"auth0","user_id":"u1","isSocial":false},'
        '{"connection":"AAF","provider":"oidc",'
        '"user_id":"linked-aaf","isSocial":false}]}\n',
        encoding="utf-8",
    )

    users = parse_auth0_json_export(json_path)

    assert len(users) == 1
    assert users[0].account_type == BiocommonsUserAccountType.AAF
    assert users[0].metadata_username == "metadata_u1"
    assert len(users[0].identities) == 2
    assert users[0].identities[1].connection == "AAF"
    assert users[0].identities[1].provider == "oidc"
    assert users[0].identities[1].user_id == "linked-aaf"


def test_parse_auth0_json_export_defaults_missing_blocked(tmp_path):
    json_path = tmp_path / "auth0_users.json"
    json_path.write_text(
        '{"user_id":"auth0|u1","email":"u1@example.com",'
        '"email_verified":true,"username":"u1",'
        '"updated_at":"2024-01-01T12:00:00+00:00"}\n',
        encoding="utf-8",
    )

    users = parse_auth0_json_export(json_path)

    assert users[0].blocked is False


@pytest.mark.asyncio
async def test_export_auth0_users_writes_temp_json_file(mocker):
    """
    Test that export_auth0_users() calls export_and_download_users with a path that exists,
    and that the JSON file exists (was written) before parsing.
    """
    json_existed_at_parse_time = False
    json_path: Path | None = None

    def _fake_export_and_download_users(*, download_path, fields, format, connection_id):
        assert connection_id is None
        assert format == "json"
        # Simulate Auth0Client writing the file to the provided temp path
        download_path.write_text(
            '{"user_id":"auth0|u1","email":"u1@example.com",'
            '"email_verified":true,"username":"u1","blocked":false,'
            '"updated_at":"2024-01-01T12:00:00+00:00"}\n',
            encoding="utf-8",
        )

    def _parse_spy(path):
        nonlocal json_existed_at_parse_time
        nonlocal json_path
        json_path = path
        json_existed_at_parse_time = path.exists()
        # Return a minimal valid parsed result (we test parse_auth0_json_export separately)
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

    mocker.patch("scheduled_tasks.tasks.parse_auth0_json_export", side_effect=_parse_spy)

    auth0_client = MagicMock()
    auth0_client.export_and_download_users.side_effect = _fake_export_and_download_users

    users = await export_auth0_users(auth0_client)

    auth0_client.export_and_download_users.assert_called_once()
    assert json_existed_at_parse_time is True
    # Path should be deleted after parsing
    assert not json_path.exists()
    assert len(users) == 1
    assert users[0].user_id == "auth0|u1"


@pytest.mark.asyncio
async def test_export_auth0_users_passes_connection_id(mocker):
    def _fake_export_and_download_users(*, download_path, fields, format, connection_id):
        assert format == "json"
        assert fields == [
            {"name": "user_id"},
            {"name": "email"},
            {"name": "email_verified"},
            {"name": "username"},
            {"name": "app_metadata.username", "export_as": "metadata_username"},
            {"name": "blocked"},
            {"name": "updated_at"},
            {"name": "app_metadata.account_type", "export_as": "account_type"},
            {"name": "app_metadata.aaf_only", "export_as": "aaf_only"},
            {
                "name": "app_metadata.aaf_registration_complete",
                "export_as": "aaf_registration_complete",
            },
            {"name": "app_metadata.linking_completed", "export_as": "linking_completed"},
            {
                "name": "app_metadata.linking_completed_at",
                "export_as": "linking_completed_at",
            },
            {"name": "identities"},
        ]
        assert connection_id == "con_aaf"
        download_path.write_text(
            "",
            encoding="utf-8",
        )

    auth0_client = MagicMock()
    auth0_client.export_and_download_users.side_effect = _fake_export_and_download_users

    users = await export_auth0_users(auth0_client, connection_id="con_aaf")

    assert users == []
    auth0_client.export_and_download_users.assert_called_once()
