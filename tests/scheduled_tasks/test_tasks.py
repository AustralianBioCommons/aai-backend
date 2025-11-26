from datetime import datetime, timedelta, timezone
from enum import Enum
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from sqlmodel import select

from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    EmailNotification,
    GroupMembership,
    GroupMembershipHistory,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.types import ApprovalStatusEnum, EmailStatusEnum
from scheduled_tasks.email_retry import (
    EMAIL_MAX_ATTEMPTS,
    EMAIL_RETRY_WINDOW_SECONDS,
)
from scheduled_tasks.tasks import (
    _ensure_user_from_auth0,
    _get_group_membership_including_deleted,
    populate_db_groups,
    process_email_queue,
    send_email_notification,
    sync_auth0_roles,
    sync_auth0_users,
    sync_group_user_roles,
    sync_platform_user_roles,
    update_auth0_user,
)
from tests.datagen import (
    Auth0UserDataFactory,
    RoleUserDataFactory,
    UsersWithTotalsFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)

DEFAULT_EMAIL_SENDER = "amanda@biocommons.org.au"


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
    existing_user_data = Auth0UserDataFactory.build(
        user_id=existing_user.id,
        email=existing_email,
        username=existing_username,
        email_verified=True,
    )
    new_user_data = Auth0UserDataFactory.build(
        email="new.user@example.com",
        username="new_user",
    )
    extra_user_data = Auth0UserDataFactory.build(
        email="extra.user@example.com",
        username="extra_user",
    )
    batch = UsersWithTotalsFactory.build(
        total=3,
        start=0,
        limit=2,
        users=[existing_user_data, new_user_data],
    )
    batch_two = UsersWithTotalsFactory.build(
        total=3,
        start=2,
        limit=1,
        users=[extra_user_data],
    )
    mock_auth0_instance = MagicMock()
    mock_auth0_instance.get_users.side_effect = [batch, batch_two]
    mocker.patch("scheduled_tasks.tasks.Auth0Client", return_value=mock_auth0_instance)
    mocker.patch("scheduled_tasks.tasks.get_settings")
    mocker.patch("scheduled_tasks.tasks.get_management_token")
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER")
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, object()),
    )

    await sync_auth0_users()

    test_db_session.refresh(existing_user)
    test_db_session.refresh(user_not_in_auth0)
    created_user = test_db_session.get(BiocommonsUser, new_user_data.user_id)

    assert mock_auth0_instance.get_users.call_count == 2
    assert mock_scheduler.add_job.call_count == 3
    assert existing_user.email_verified is True
    assert user_not_in_auth0.is_deleted is True
    assert created_user is not None and created_user.is_deleted is False
    second_created = test_db_session.get(BiocommonsUser, extra_user_data.user_id)
    assert second_created is not None


@pytest.mark.asyncio
async def test_update_auth0_user_updates_existing(test_db_session, mocker, persistent_factories):
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
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, object()),
    )

    await update_auth0_user(user_data=user_data)

    test_db_session.refresh(db_user)
    assert db_user.email_verified is True


@pytest.mark.asyncio
async def test_update_auth0_user_creates_when_missing(test_db_session, mocker):
    """
    Missing users are created when encountered during the update.
    """
    user_data = Auth0UserDataFactory.build()
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, object()),
    )

    result = await update_auth0_user(user_data=user_data)

    created = test_db_session.get(BiocommonsUser, user_data.user_id)
    assert result is True
    assert created is not None


@pytest.mark.asyncio
async def test_update_auth0_user_closes_session(mocker):
    user_data = Auth0UserDataFactory.build(
        email="close.session@example.com",
        username="close_session",
    )
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

    await update_auth0_user(user_data=user_data)

    fake_session.commit.assert_called_once()
    fake_session.close.assert_called_once()


def test_ensure_user_from_auth0_creates_user(test_db_session):
    user_data = Auth0UserDataFactory.build(
        user_id="auth0|ensure_create",
        email="ensure.create@example.com",
        username="ensure_create",
        email_verified=True,
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
    )

    user, created, restored = _ensure_user_from_auth0(test_db_session, user_data)

    assert created is False
    assert restored is True
    assert user.is_deleted is False


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
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, object()),
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
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, None),
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
        return_value=iter(lambda: test_db_session, None),
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
    mocker.patch.object(test_db_session, "close", return_value=None)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=(test_db_session for _ in range(1)),
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
async def test_process_email_queue_sends_notifications(test_db_session, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=DEFAULT_EMAIL_SENDER,
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    mock_service = mocker.Mock()
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, None),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 1
    mock_scheduler.assert_called_once()
    await send_email_notification(notification_id)
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.SENT
    mock_service.send.assert_called_once_with(
        "user@example.com",
        "Hello",
        "<p>Test</p>",
        sender=DEFAULT_EMAIL_SENDER,
    )


@pytest.mark.asyncio
async def test_send_email_notification_uses_custom_sender(test_db_session, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address="custom@example.com",
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    mock_service = mocker.Mock()
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, None),
    )

    await send_email_notification(notification_id)

    mock_service.send.assert_called_once_with(
        "user@example.com",
        "Hello",
        "<p>Test</p>",
        sender="custom@example.com",
    )
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.SENT


@pytest.mark.asyncio
async def test_send_email_notification_retries_transient_errors(test_db_session, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=DEFAULT_EMAIL_SENDER,
        subject="Hello",
        body_html="<p>Test</p>",
    )
    test_db_session.add(notification)
    test_db_session.commit()
    notification_id = notification.id

    mock_service = mocker.Mock()
    mock_service.send.side_effect = EndpointConnectionError(endpoint_url="https://ses")
    mocker.patch("scheduled_tasks.tasks.get_email_service", return_value=mock_service)
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, None),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")
    mocker.patch("scheduled_tasks.tasks.next_retry_delay_seconds", return_value=900)

    scheduled = await process_email_queue()

    assert scheduled == 1
    mock_scheduler.assert_called_once()
    await send_email_notification(notification_id)
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.last_error is not None
    assert updated.send_after is not None
    delay = (updated.send_after - updated.updated_at).total_seconds()
    assert delay == pytest.approx(900, abs=0.1)


@pytest.mark.asyncio
async def test_send_email_notification_does_not_retry_non_transient_error(test_db_session, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=DEFAULT_EMAIL_SENDER,
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
    mocker.patch(
        "scheduled_tasks.tasks.get_db_session",
        return_value=iter(lambda: test_db_session, None),
    )
    mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    await process_email_queue()
    await send_email_notification(notification_id)
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None


@pytest.mark.asyncio
async def test_process_email_queue_skips_when_max_attempts_reached(test_db_session, mocker):
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=DEFAULT_EMAIL_SENDER,
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
        return_value=iter(lambda: test_db_session, None),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 0
    mock_scheduler.assert_not_called()
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None


@pytest.mark.asyncio
async def test_process_email_queue_skips_when_retry_window_exceeded(test_db_session, mocker):
    first_attempt = datetime.now(timezone.utc) - timedelta(
        seconds=EMAIL_RETRY_WINDOW_SECONDS + 60
    )
    notification = EmailNotification(
        to_address="user@example.com",
        from_address=DEFAULT_EMAIL_SENDER,
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
        return_value=iter(lambda: test_db_session, None),
    )
    mock_scheduler = mocker.patch("scheduled_tasks.tasks.SCHEDULER.add_job")

    scheduled = await process_email_queue()

    assert scheduled == 0
    mock_scheduler.assert_not_called()
    updated = test_db_session.get(EmailNotification, notification_id)
    assert updated.status == EmailStatusEnum.FAILED
    assert updated.send_after is None
