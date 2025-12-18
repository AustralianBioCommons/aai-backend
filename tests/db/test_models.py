from datetime import datetime, timezone
from unittest.mock import ANY, call

import pytest
import respx
from freezegun import freeze_time
from httpx import Response
from mimesis import Person
from mimesis.locales import Locale
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from db.models import (
    ApprovalStatusEnum,
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    GroupMembershipHistory,
    Platform,
    PlatformEnum,
    PlatformMembership,
    PlatformMembershipHistory,
)
from tests.biocommons.datagen import RoleDataFactory
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    RoleUserDataFactory,
    random_auth0_id,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)

FROZEN_TIME = datetime(2025, 1, 1, 12, 0, 0)


@pytest.fixture
def frozen_time():
    """
    Freeze time so datetime.now() returns FROZEN_TIME.
    """
    with freeze_time("2025-01-01 12:00:00"):
        yield


def test_create_biocommons_user(test_db_session):
    """
    Test creating the BiocommonsUser model
    """
    user_data = Person(locale=Locale("en"))
    auth0_id = random_auth0_id()
    email = user_data.email()
    user = BiocommonsUser(id=auth0_id, email=email, username="user_name")
    test_db_session.add(user)
    test_db_session.commit()
    test_db_session.refresh(user)
    assert user.id == auth0_id
    assert user.email == email
    assert user.username == "user_name"
    assert not user.email_verified


def test_create_biocommons_user_from_auth0(test_db_session, mock_auth0_client):
    """
    Test creating the BiocommonsUser model from Auth0 user data from the API
    """
    user_data = Auth0UserDataFactory.build()
    mock_auth0_client.get_user.return_value = user_data
    user = BiocommonsUser.create_from_auth0(auth0_id=user_data.user_id, auth0_client=mock_auth0_client)
    test_db_session.add(user)
    test_db_session.commit()
    test_db_session.refresh(user)
    assert user.id == user_data.user_id
    assert user.email == user_data.email
    assert user.username == user_data.username
    assert user.email_verified == user_data.email_verified


def test_get_or_create_biocommons_user(test_db_session, mock_auth0_client, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    fetched_user = BiocommonsUser.get_or_create(auth0_id=user.id, db_session=test_db_session, auth0_client=mock_auth0_client)
    assert fetched_user.id == user.id
    # Check that we didn't call Auth0 API to get the user data
    assert not mock_auth0_client.get_user.called


def test_get_or_create_biocommons_user_from_auth0(test_db_session, mock_auth0_client):
    """
    Test get_or_create method when user doesn't exist in the DB
    """
    user_data = Auth0UserDataFactory.build()
    mock_auth0_client.get_user.return_value = user_data
    user = BiocommonsUser.get_or_create(auth0_id=user_data.user_id, db_session=test_db_session, auth0_client=mock_auth0_client)
    test_db_session.refresh(user)
    assert mock_auth0_client.get_user.called
    assert user.id == user_data.user_id
    assert user.email == user_data.email
    assert user.username == user_data.username


def test_is_any_platform_admin_returns_true_for_matching_role(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/platform/admin")
    PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Galaxy Admin Platform",
        admin_roles=[admin_role],
    )
    payload = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    user = BiocommonsUserFactory.create_sync(id=payload.sub)

    assert user.is_any_platform_admin(access_token=payload, db_session=test_db_session) is True


def test_is_any_platform_admin_returns_false_without_matching_role(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/platform/admin")
    PlatformFactory.create_sync(
        id=PlatformEnum.BPA_DATA_PORTAL,
        name="BPA Admin Platform",
        admin_roles=[admin_role],
    )
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/platform/user"])
    user = BiocommonsUserFactory.create_sync(id=payload.sub)

    assert user.is_any_platform_admin(access_token=payload, db_session=test_db_session) is False


def test_is_any_platform_admin_raises_for_mismatched_sub(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/platform/admin")
    PlatformFactory.create_sync(
        id=PlatformEnum.SBP,
        name="TSI Portal Platform",
        admin_roles=[admin_role],
    )
    user = BiocommonsUserFactory.create_sync(id="auth0|user")
    payload = AccessTokenPayloadFactory.build(
        sub="auth0|other",
        biocommons_roles=[admin_role.name],
    )

    with pytest.raises(ValueError, match="User ID does not match access token"):
        user.is_any_platform_admin(access_token=payload, db_session=test_db_session)


def test_is_any_group_admin_returns_true_for_matching_role(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/group/admin")
    BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/test",
        name="Test Group",
        admin_roles=[admin_role],
    )
    payload = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    user = BiocommonsUserFactory.create_sync(id=payload.sub)

    assert user.is_any_group_admin(access_token=payload, db_session=test_db_session) is True


def test_is_any_group_admin_returns_false_without_matching_role(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/group/admin")
    BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/test-false",
        name="Test Group False",
        admin_roles=[admin_role],
    )
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/group/user"])
    user = BiocommonsUserFactory.create_sync(id=payload.sub)

    assert user.is_any_group_admin(access_token=payload, db_session=test_db_session) is False


def test_is_any_group_admin_raises_for_mismatched_sub(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/group/admin")
    BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/test-mismatch",
        name="Test Group Mismatch",
        admin_roles=[admin_role],
    )
    user = BiocommonsUserFactory.create_sync(id="auth0|user")
    payload = AccessTokenPayloadFactory.build(
        sub="auth0|other",
        biocommons_roles=[admin_role.name],
    )

    with pytest.raises(ValueError, match="User ID does not match access token"):
        user.is_any_group_admin(access_token=payload, db_session=test_db_session)


def test_platform_get_all_admin_roles_returns_distinct_roles(test_db_session, persistent_factories):
    admin_role_one = Auth0RoleFactory.create_sync(name="biocommons/role/platform/admin-one")
    admin_role_two = Auth0RoleFactory.create_sync(name="biocommons/role/platform/admin-two")
    PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Galaxy Admin Distinct",
        admin_roles=[admin_role_one],
    )
    PlatformFactory.create_sync(
        id=PlatformEnum.BPA_DATA_PORTAL,
        name="BPA Admin Distinct",
        admin_roles=[admin_role_one, admin_role_two],
    )
    Auth0RoleFactory.create_sync(name="biocommons/role/platform/unused")

    roles = Platform.get_all_admin_roles(test_db_session)

    assert {role.id for role in roles} == {admin_role_one.id, admin_role_two.id}


def test_biocommons_group_get_all_admin_roles_returns_distinct_roles(test_db_session, persistent_factories):
    admin_role_one = Auth0RoleFactory.create_sync(name="biocommons/role/group/admin-one")
    admin_role_two = Auth0RoleFactory.create_sync(name="biocommons/role/group/admin-two")
    BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/distinct-one",
        name="Distinct Group One",
        admin_roles=[admin_role_one],
    )
    BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/distinct-two",
        name="Distinct Group Two",
        admin_roles=[admin_role_one, admin_role_two],
    )
    Auth0RoleFactory.create_sync(name="biocommons/role/group/unused")

    roles = BiocommonsGroup.get_all_admin_roles(test_db_session)

    assert {role.id for role in roles} == {admin_role_one.id, admin_role_two.id}


def test_biocommons_user_update_from_auth0(test_db_session, mocker, persistent_factories):
    user = BiocommonsUserFactory.create_sync(email_verified=False)
    data = Auth0UserDataFactory.build(user_id=user.id, email_verified=True)
    mock_client = mocker.Mock()
    mock_client.get_user.return_value = data

    user.update_from_auth0(user.id, mock_client)

    mock_client.get_user.assert_called_once_with(user_id=user.id)
    assert user.email_verified is True


def test_biocommons_user_add_group_membership_creates_history(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync()

    membership = user.add_group_membership(group_id=group.group_id, db_session=test_db_session, auto_approve=True)
    test_db_session.commit()

    assert membership.group_id == group.group_id
    history_entries = test_db_session.exec(
        select(GroupMembershipHistory).where(
            GroupMembershipHistory.user_id == user.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
    ).all()
    assert len(history_entries) == 1


def test_biocommons_user_group_membership_delete_restore_creates_history(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync()
    membership = user.add_group_membership(group_id=group.group_id, db_session=test_db_session, auto_approve=True)
    test_db_session.commit()

    membership_id = membership.id
    history_entries = test_db_session.exec(
        select(GroupMembershipHistory)
        .where(
            GroupMembershipHistory.user_id == user.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
        .order_by(GroupMembershipHistory.updated_at)
    ).all()
    assert [entry.approval_status for entry in history_entries] == [ApprovalStatusEnum.APPROVED]

    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = "No longer required"
    membership.updated_at = datetime.now(tz=timezone.utc)
    _revoked_history = membership.save_history(test_db_session, commit=True)

    membership.delete(test_db_session, commit=True)
    deleted_membership = GroupMembership.get_deleted_by_id(test_db_session, membership_id)
    assert deleted_membership is not None

    deleted_membership.restore(test_db_session, commit=True)
    restored_membership = GroupMembership.get_by_user_id_and_group_id(user.id, group.group_id, test_db_session)
    assert restored_membership is not None
    restored_membership.approval_status = ApprovalStatusEnum.APPROVED
    restored_membership.revocation_reason = None
    restored_membership.updated_at = datetime.now(tz=timezone.utc)
    _final_history_entry = restored_membership.save_history(test_db_session, commit=True)

    final_history = test_db_session.exec(
        select(GroupMembershipHistory)
        .where(
            GroupMembershipHistory.user_id == user.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
        .order_by(GroupMembershipHistory.updated_at)
    ).all()
    assert [entry.approval_status for entry in final_history] == [ApprovalStatusEnum.APPROVED]
    assert final_history[0].reason is None

    all_history_including_deleted = test_db_session.exec(
        select(GroupMembershipHistory)
        .execution_options(include_deleted=True)
        .where(
            GroupMembershipHistory.user_id == user.id,
            GroupMembershipHistory.group_id == group.group_id,
        )
        .order_by(GroupMembershipHistory.updated_at)
    ).all()
    assert [entry.approval_status for entry in all_history_including_deleted] == [
        ApprovalStatusEnum.APPROVED,
        ApprovalStatusEnum.REVOKED,
        ApprovalStatusEnum.APPROVED,
    ]
    assert [entry.is_deleted for entry in all_history_including_deleted] == [True, True, False]
    assert all_history_including_deleted[1].reason == "No longer required"


@pytest.mark.parametrize("platform_id", list(PlatformEnum))
def test_create_platform(platform_id, test_db_session, persistent_factories):
    platform_role = Auth0RoleFactory.create_sync(name=f"biocommons/platform/{platform_id}")
    admin_role = Auth0RoleFactory.create_sync(name=f"biocommons/role/{platform_id}/admin")
    platform = Platform(
        id=platform_id,
        role_id=platform_role.id,
        name=f"Platform {platform_id}",
        admin_roles=[admin_role]
    )
    test_db_session.add(platform)
    test_db_session.commit()
    assert platform.id == platform_id


def test_create_platform_unique_id(test_db_session, persistent_factories):
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    platform = Platform(id=PlatformEnum.GALAXY, name="Galaxy", role_id=platform_role.id, admin_roles=[])
    test_db_session.add(platform)
    test_db_session.commit()
    with pytest.raises(IntegrityError):
        platform = Platform(id=PlatformEnum.GALAXY, name="Galaxy Duplicate", admin_roles=[])
        test_db_session.add(platform)
        test_db_session.commit()


def test_create_platform_membership(test_db_session, persistent_factories, frozen_time):
    """
    Test creating a platform membership model
    """
    user = BiocommonsUserFactory.create_sync(platform_memberships=[])
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembership(
        platform_id=platform.id,
        user_id=user.id,
        approval_status=ApprovalStatusEnum.APPROVED,
        updated_by_id=None
    )
    test_db_session.add(membership)
    test_db_session.commit()
    test_db_session.refresh(membership)
    assert membership.user_id == user.id
    assert membership.user == user
    assert membership.approval_status == ApprovalStatusEnum.APPROVED
    assert membership.platform_id == "galaxy"
    # Check the related platform object is populated
    assert membership.platform.id == "galaxy"
    assert membership.updated_at == FROZEN_TIME
    assert membership.revocation_reason is None


def test_create_platform_membership_history(test_db_session, persistent_factories, frozen_time):
    """
    Test creating a platform membership history model
    """
    user = BiocommonsUserFactory.create_sync()
    membership = PlatformMembershipHistory(
        platform_id=PlatformEnum.GALAXY,
        user_id=user.id,
        approval_status=ApprovalStatusEnum.APPROVED,
        updated_by_id=None
    )
    test_db_session.add(membership)
    test_db_session.commit()
    test_db_session.refresh(membership)
    assert membership.user_id == user.id
    assert membership.approval_status == ApprovalStatusEnum.APPROVED
    assert membership.platform_id == "galaxy"
    assert membership.updated_at == FROZEN_TIME


def test_create_group_membership(test_db_session, persistent_factories):
    """
    Test creating a group membership
    """
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    updater = BiocommonsUserFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    membership = GroupMembership(
        group=group,
        user=user,
        approval_status="pending",
        updated_at=datetime.now(tz=timezone.utc),
        updated_by=updater,
    )
    test_db_session.add(membership)
    test_db_session.commit()
    test_db_session.refresh(membership)
    assert membership.group.group_id == "biocommons/group/tsi"
    assert membership.user_id == user.id
    assert membership.updated_by_id == updater.id


def test_platform_membership_save_history_stores_reason(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        approval_status=ApprovalStatusEnum.REVOKED,
        revocation_reason="Policy violation",
    )
    membership.save_history(test_db_session)
    history = test_db_session.exec(
        select(PlatformMembershipHistory)
        .where(
            PlatformMembershipHistory.user_id == membership.user_id,
            PlatformMembershipHistory.platform_id == membership.platform_id,
        )
        .order_by(PlatformMembershipHistory.updated_at.desc())
    ).first()
    assert history is not None
    assert history.reason == "Policy violation"


def test_platform_membership_revoke_auth0_role(mock_auth0_client, persistent_factories):
    membership = PlatformMembershipFactory.create_sync(
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    role = RoleDataFactory.build(name="biocommons/platform/galaxy")
    mock_auth0_client.get_role_by_name.return_value = role

    assert membership.revoke_auth0_role(mock_auth0_client) is True
    mock_auth0_client.get_role_by_name.assert_called_once_with("biocommons/platform/galaxy")
    mock_auth0_client.remove_roles_from_user.assert_called_once_with(
        user_id=membership.user_id,
        role_id=role.id,
    )


@pytest.mark.parametrize("status", [ApprovalStatusEnum.PENDING, ApprovalStatusEnum.REVOKED])
def test_platform_membership_revoke_auth0_role_not_approved(status, mock_auth0_client, persistent_factories):
    membership = PlatformMembershipFactory.create_sync(
        platform_id=PlatformEnum.GALAXY,
        approval_status=status,
    )

    assert membership.revoke_auth0_role(mock_auth0_client) is False
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.remove_roles_from_user.assert_not_called()


def test_platform_membership_grant_auth0_role(mock_auth0_client, persistent_factories):
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        platform_role=platform_role,
        role_id=platform_role.id,
    )
    membership = PlatformMembershipFactory.create_sync(
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )

    assert membership.grant_auth0_role(mock_auth0_client) is True
    mock_auth0_client.add_roles_to_user.assert_called_once_with(
        user_id=membership.user_id,
        role_id=platform_role.id,
    )
    mock_auth0_client.get_role_by_name.assert_not_called()


@pytest.mark.parametrize("status", [ApprovalStatusEnum.PENDING, ApprovalStatusEnum.REVOKED])
def test_platform_membership_grant_auth0_role_requires_approval(status, mock_auth0_client, persistent_factories):
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        platform_role=platform_role,
        role_id=platform_role.id,
    )
    membership = PlatformMembershipFactory.create_sync(
        platform=platform,
        approval_status=status,
    )

    with pytest.raises(ValueError):
        membership.grant_auth0_role(mock_auth0_client)
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.add_roles_to_user.assert_not_called()


def test_platform_membership_revoke_updates_state(test_db_session, mock_auth0_client, persistent_factories):
    admin = BiocommonsUserFactory.create_sync()
    membership = PlatformMembershipFactory.create_sync(
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    role = RoleDataFactory.build(name="biocommons/platform/galaxy")
    mock_auth0_client.get_role_by_name.return_value = role

    result = membership.revoke(
        auth0_client=mock_auth0_client,
        reason="No longer required",
        updated_by=admin,
        session=test_db_session,
    )

    assert result is True
    mock_auth0_client.remove_roles_from_user.assert_called_once_with(
        user_id=membership.user_id,
        role_id=role.id,
    )
    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REVOKED
    assert membership.revocation_reason == "No longer required"
    assert membership.updated_by_id == admin.id


def test_create_group_membership_no_updater(test_db_session, persistent_factories):
    """
    Test creating a group membership without an updated_by (for automatic approvals)
    """
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    membership = GroupMembership(
        group=group,
        user=user,
        approval_status="pending",
        updated_at=datetime.now(tz=timezone.utc),
        updated_by=None,
    )
    test_db_session.add(membership)
    test_db_session.commit()
    test_db_session.refresh(membership)
    assert membership.group.group_id == "biocommons/group/tsi"
    assert membership.user_id == user.id
    assert membership.updated_by_id is None


def test_create_group_membership_unique_constraint(test_db_session, persistent_factories):
    """
    Check that trying to create multiple group memberships
    for the same user/group raises IntegrityError
    """
    user = Person(locale=Locale("en"))
    user_id = random_auth0_id()
    updater = Person(locale=Locale("en"))
    updater_id = random_auth0_id()
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    membership = GroupMembership(
        group=group,
        user_id=user_id,
        user_email=user.email(),
        approval_status="pending",
        updated_at=datetime.now(tz=timezone.utc),
        updated_by_id=updater_id,
        updated_by_email=updater.email(),
    )
    test_db_session.add(membership)
    test_db_session.commit()

    dupe_membership = GroupMembership(
        group=group,
        user_id=user_id,
        user_email=user.email(),
        approval_status="approved",
        updated_at=datetime.now(tz=timezone.utc),
        updated_by_id=updater_id,
        updated_by_email=updater.email(),
    )
    with pytest.raises(IntegrityError):
        test_db_session.add(dupe_membership)
        test_db_session.commit()


def test_create_auth0_role(test_db_session):
    """
    Test creating an auth0 role
    """
    role = Auth0Role(id=random_auth0_id(), name="Example group")
    test_db_session.add(role)
    test_db_session.commit()
    test_db_session.refresh(role)
    assert role.name == "Example group"


@respx.mock
def test_create_auth0_role_by_name(test_db_session, test_auth0_client):
    """
    Test when can create an auth0 role by name, looking up the role in Auth0 first
    """
    role_data = RoleDataFactory.build(name="biocommons/role/tsi/admin")
    respx.get(f"https://{test_auth0_client.domain}/api/v2/roles", params={"name_filter": ANY}).mock(
        return_value=Response(200, json=[role_data.model_dump(mode="json")])
    )
    Auth0Role.get_or_create_by_name(
        name=role_data.name,
        session=test_db_session,
        auth0_client=test_auth0_client
    )
    role_from_db = test_db_session.exec(
        select(Auth0Role).where(Auth0Role.id == role_data.id)
    ).first()
    assert role_from_db.name == role_data.name


def test_get_or_create_auth0_role_existing(test_db_session, mock_auth0_client, persistent_factories):
    role = Auth0RoleFactory.create_sync()
    role_lookup = Auth0Role.get_or_create_by_id(
        auth0_id=role.id,
        session=test_db_session,
        auth0_client=mock_auth0_client
    )
    assert role_lookup.id == role.id
    assert not mock_auth0_client.get_role.called


def test_auth0_role_get_or_create_by_name_existing(test_db_session, mocker, persistent_factories):
    role = Auth0RoleFactory.create_sync(name="existing-role")
    mock_client = mocker.Mock()

    fetched = Auth0Role.get_or_create_by_name("existing-role", test_db_session, mock_client)

    assert fetched.id == role.id
    mock_client.get_role_by_name.assert_not_called()


def test_auth0_role_get_or_create_by_name_revives_deleted_role(test_db_session, mocker, persistent_factories):
    role_data = RoleDataFactory.build(name="restorable-role")
    mock_client = mocker.Mock()
    mock_client.get_role_by_name.return_value = role_data

    created = Auth0Role.get_or_create_by_name(role_data.name, test_db_session, mock_client)
    assert created.id == role_data.id
    mock_client.get_role_by_name.assert_called_once_with(name=role_data.name)

    created.delete(test_db_session, commit=True)
    assert Auth0Role.get_deleted_by_id(test_db_session, role_data.id) is not None

    mock_client.reset_mock()
    mock_client.get_role_by_name.return_value = role_data

    revived = Auth0Role.get_or_create_by_name(role_data.name, test_db_session, mock_client)

    assert revived.id == role_data.id
    assert revived.is_deleted is False
    mock_client.get_role_by_name.assert_called_once_with(name=role_data.name)
    stored_role = test_db_session.exec(select(Auth0Role).where(Auth0Role.id == role_data.id)).one()
    assert stored_role.is_deleted is False


@respx.mock
def test_create_auth0_role_by_id(test_db_session, test_auth0_client):
    """
    Test when can create an auth0 role by id, looking up the role in Auth0 first
    """
    role_data = RoleDataFactory.build(name="biocommons/role/tsi/admin")
    respx.get(f"https://auth0.example.com/api/v2/roles/{role_data.id}").mock(
        return_value=Response(200, json=role_data.model_dump(mode="json"))
    )
    Auth0Role.get_or_create_by_id(
        auth0_id=role_data.id,
        session=test_db_session,
        auth0_client=test_auth0_client
    )
    role_from_db = test_db_session.exec(
        select(Auth0Role).where(Auth0Role.id == role_data.id)
    ).first()
    assert role_from_db.name == role_data.name


def test_create_biocommons_group(test_db_session, persistent_factories):
    """
    Test creating a biocommons group (with associated roles)
    """
    roles = Auth0RoleFactory.create_batch_sync(size=2)
    group = BiocommonsGroup(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        short_name="TSI",
        admin_roles=roles
    )
    test_db_session.add(group)
    test_db_session.commit()
    test_db_session.refresh(group)
    assert group.group_id == "biocommons/group/tsi"
    assert all(role in group.admin_roles for role in roles)
    # Check the relationship in the other direction
    role = roles[0]
    assert group in role.admin_groups


def test_biocommons_group_get_admins_collects_emails(test_db_session, mocker, persistent_factories):
    primary_role = Auth0RoleFactory.create_sync(id="role-primary")
    secondary_role = Auth0RoleFactory.create_sync(id="role-secondary")
    group = BiocommonsGroupFactory.create_sync(admin_roles=[primary_role, secondary_role])
    mock_client = mocker.Mock()
    mock_user_1 = Auth0UserDataFactory.build()
    mock_user_2 = Auth0UserDataFactory.build()
    mock_user_3 = Auth0UserDataFactory.build()
    stub_1 = RoleUserDataFactory.build(user_id=mock_user_1.user_id, email=mock_user_1.email)
    stub_2 = RoleUserDataFactory.build(user_id=mock_user_2.user_id, email=None)
    stub_3 = RoleUserDataFactory.build(user_id=mock_user_3.user_id, email=None)

    def _get_all_role_users(*, role_id):
        if role_id == primary_role.id:
            return [stub_1, stub_2]
        if role_id == secondary_role.id:
            return [stub_3]
        raise AssertionError(f"Unexpected role id {role_id}")

    mock_client.get_all_role_users.side_effect = _get_all_role_users
    mock_client.get_user.side_effect = [mock_user_2, mock_user_3]

    admins = group.get_admins(mock_client)

    assert admins == {mock_user_1.email, mock_user_2.email, mock_user_3.email}
    assert mock_client.get_all_role_users.call_args_list == [
        call(role_id=primary_role.id),
        call(role_id=secondary_role.id),
    ]


def test_platform_get_admins_collects_emails(test_db_session, mocker, persistent_factories):
    primary_role = Auth0RoleFactory.create_sync(id="platform-role-primary")
    secondary_role = Auth0RoleFactory.create_sync(id="platform-role-secondary")
    platform = PlatformFactory.create_sync(id=PlatformEnum.SBP, admin_roles=[primary_role, secondary_role])
    mock_client = mocker.Mock()
    mock_user_1 = Auth0UserDataFactory.build()
    mock_user_2 = Auth0UserDataFactory.build()
    mock_user_3 = Auth0UserDataFactory.build()
    stub_1 = RoleUserDataFactory.build(user_id=mock_user_1.user_id, email=mock_user_1.email)
    stub_2 = RoleUserDataFactory.build(user_id=mock_user_2.user_id, email=None)
    stub_3 = RoleUserDataFactory.build(user_id=mock_user_3.user_id, email=None)

    def _get_all_role_users(*, role_id):
        if role_id == primary_role.id:
            return [stub_1, stub_2]
        if role_id == secondary_role.id:
            return [stub_3]
        raise AssertionError(f"Unexpected role id {role_id}")

    mock_client.get_all_role_users.side_effect = _get_all_role_users
    mock_client.get_user.side_effect = [mock_user_2, mock_user_3]

    admins = platform.get_admins(mock_client)

    assert admins == {mock_user_1.email, mock_user_2.email, mock_user_3.email}
    assert mock_client.get_all_role_users.call_args_list == [
        call(role_id=primary_role.id),
        call(role_id=secondary_role.id),
    ]


@respx.mock
def test_group_membership_grant_auth0_role(test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    role_data = RoleDataFactory.build(name="biocommons/group/tsi")
    membership_request = GroupMembershipFactory.create_sync(group=group, user=user, approval_status="approved")
    # Mock the auth0 calls involved
    respx.get(
        "https://auth0.example.com/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(status_code=200, json=[role_data.model_dump(mode="json")])
    route = respx.post(f"https://auth0.example.com/api/v2/users/{user.id}/roles").respond(status_code=200)
    result = membership_request.grant_auth0_role(test_auth0_client)
    assert result
    assert route.called


@pytest.mark.parametrize("status", ["pending", "revoked"])
@respx.mock
def test_group_membership_grant_auth0_role_not_approved(status, test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    user = Auth0UserDataFactory.build()
    membership_request = GroupMembershipFactory.create_sync(group=group, user_id=user.user_id, approval_status=status)
    with pytest.raises(ValueError):
        membership_request.grant_auth0_role(test_auth0_client)


@respx.mock
def test_group_membership_revoke_auth0_role(test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(group=group, user=user, approval_status=ApprovalStatusEnum.APPROVED.value)
    role_data = RoleDataFactory.build(name=group.group_id)
    role_lookup = respx.get(
        "https://auth0.example.com/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(status_code=200, json=[role_data.model_dump(mode="json")])
    route = respx.delete(f"https://auth0.example.com/api/v2/users/{user.id}/roles").respond(status_code=200)
    assert membership.revoke_auth0_role(test_auth0_client)
    assert role_lookup.called
    assert route.called


@respx.mock
def test_group_membership_revoke_updates_state(test_db_session, test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    admin = BiocommonsUserFactory.create_sync()
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(group=group, user=user, approval_status=ApprovalStatusEnum.APPROVED.value)
    role_data = RoleDataFactory.build(name=group.group_id)
    respx.get(
        "https://auth0.example.com/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(status_code=200, json=[role_data.model_dump(mode="json")])
    route = respx.delete(f"https://auth0.example.com/api/v2/users/{user.id}/roles").respond(status_code=200)

    with freeze_time("2025-01-01 12:00:00"):
        result = membership.revoke(
            auth0_client=test_auth0_client,
            reason="No longer required",
            updated_by=admin,
            session=test_db_session,
        )

    assert result is True
    assert route.called
    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REVOKED
    assert membership.revocation_reason == "No longer required"
    assert membership.updated_by_id == admin.id


@pytest.mark.parametrize("status", ["pending", "revoked"])
@respx.mock
def test_group_membership_revoke_skips_auth0_when_not_approved(status, test_db_session, test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    admin = BiocommonsUserFactory.create_sync()
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(group=group, user=user, approval_status=status)
    role_lookup = respx.get(
        "https://auth0.example.com/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(status_code=200, json=[])

    result = membership.revoke(
        auth0_client=test_auth0_client,
        reason="Policy update",
        updated_by=admin,
        session=test_db_session,
    )

    assert result is False
    assert not role_lookup.called
    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REVOKED
    assert membership.revocation_reason == "Policy update"
    assert membership.updated_by_id == admin.id


@pytest.mark.parametrize("status", ["pending", "revoked"])
@respx.mock
def test_group_membership_revoke_auth0_role_not_approved(status, test_auth0_client, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    user = Auth0UserDataFactory.build()
    membership = GroupMembershipFactory.create_sync(group=group, user_id=user.user_id, approval_status=status)
    role_lookup = respx.get(
        "https://auth0.example.com/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(status_code=200, json=[])
    assert membership.revoke_auth0_role(test_auth0_client) is False
    assert not role_lookup.called


def test_group_membership_save_with_history(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    membership = GroupMembershipFactory.build(group_id=group.group_id)
    membership.save(test_db_session, commit=True)
    test_db_session.refresh(membership)
    assert membership.id is not None
    history = test_db_session.exec(
        select(GroupMembershipHistory)
        .where(GroupMembershipHistory.group_id == membership.group_id,
               GroupMembershipHistory.user_id == membership.user_id)
    ).one()
    assert history.group_id == membership.group_id
    assert history.user_id == membership.user_id
    assert history.reason == membership.revocation_reason


def test_group_membership_save_and_commit_history(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    membership = GroupMembershipFactory.build(
        group_id=group.group_id, approval_status=ApprovalStatusEnum.APPROVED
    )
    membership.save_history(test_db_session, commit=True)
    test_db_session.refresh(membership)
    assert membership.id is not None
    history = test_db_session.exec(
        select(GroupMembershipHistory)
        .where(GroupMembershipHistory.group_id == membership.group_id,
               GroupMembershipHistory.user_id == membership.user_id)
        ).one()
    assert history.group_id == membership.group_id
    assert history.user_id == membership.user_id
    assert history.reason == membership.revocation_reason


def test_soft_delete_hides_records(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    test_db_session.commit()

    user_id = user.id
    user.delete(test_db_session, commit=True)

    assert test_db_session.get(BiocommonsUser, user_id) is None
    deleted = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert deleted is not None
    assert deleted.is_deleted

    role = Auth0RoleFactory.create_sync(name="SoftDeleteRole")
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY, admin_roles=[role])
    test_db_session.flush()

    role_name = role.name
    found = Platform.get_for_admin_roles([role_name], test_db_session)
    assert [p.id for p in found] == [platform.id]

    role.delete(test_db_session, commit=True)
    assert Platform.get_for_admin_roles([role_name], test_db_session) == []


def test_platform_getters_respect_soft_delete(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="SoftDeletePlatformRole")
    other_role = Auth0RoleFactory.create_sync(name="OtherRole")
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY, admin_roles=[admin_role])
    test_db_session.commit()

    admin_role_name = admin_role.name
    assert [p.id for p in Platform.get_for_admin_roles([admin_role_name], test_db_session)] == [platform.id]

    # Deleting unrelated role does not affect the result
    other_role.delete(test_db_session, commit=True)
    assert [p.id for p in Platform.get_for_admin_roles([admin_role_name], test_db_session)] == [platform.id]

    # Deleting the referenced role hides the platform
    admin_role.delete(test_db_session, commit=True)
    assert Platform.get_for_admin_roles([admin_role_name], test_db_session) == []

    # Restoring role re-exposes the platform
    admin_role.restore(test_db_session, commit=True)
    assert [p.id for p in Platform.get_for_admin_roles([admin_role_name], test_db_session)] == [platform.id]

    # Soft-deleting the platform hides it regardless of role state
    platform.delete(test_db_session, commit=True)
    assert Platform.get_for_admin_roles([admin_role_name], test_db_session) == []


def test_platform_membership_getters_respect_soft_delete(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    assert PlatformMembership.get_by_user_id(user.id, test_db_session)
    assert (
        PlatformMembership.get_by_user_id_and_platform_id(
            user.id, PlatformEnum.GALAXY, test_db_session
        )
        is not None
    )
    assert [p.id for p in Platform.get_approved_by_user_id(user.id, test_db_session)] == [PlatformEnum.GALAXY]

    membership.delete(test_db_session, commit=True)
    assert PlatformMembership.get_by_user_id(user.id, test_db_session) == []
    assert (
        PlatformMembership.get_by_user_id_and_platform_id(
            user.id, PlatformEnum.GALAXY, test_db_session
        )
        is None
    )
    assert Platform.get_approved_by_user_id(user.id, test_db_session) == []

    membership.restore(test_db_session, commit=True)
    restored = PlatformMembership.get_by_user_id_and_platform_id(
        user.id, PlatformEnum.GALAXY, test_db_session
    )
    assert restored is not None
    assert restored.id == membership.id
    assert [p.id for p in Platform.get_approved_by_user_id(user.id, test_db_session)] == [PlatformEnum.GALAXY]


def test_platform_membership_delete_soft_deletes_history(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    first_history = membership.save_history(test_db_session)
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = "Revoked by admin"
    membership.updated_at = datetime.now(tz=timezone.utc)
    second_history = membership.save_history(test_db_session)
    test_db_session.commit()

    history_ids = [first_history.id, second_history.id]

    membership.delete(test_db_session, commit=True)

    for history_id in history_ids:
        deleted_entry = PlatformMembershipHistory.get_deleted_by_id(test_db_session, history_id)
        assert deleted_entry is not None
        assert deleted_entry.is_deleted


def test_platform_delete_soft_deletes_memberships_and_history(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    first_history = membership.save_history(test_db_session)
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = "Revoked by platform admin"
    membership.updated_at = datetime.now(tz=timezone.utc)
    second_history = membership.save_history(test_db_session)
    test_db_session.commit()

    platform_id = platform.id
    membership_id = membership.id
    history_ids = [first_history.id, second_history.id]

    test_db_session.refresh(platform)
    platform.delete(test_db_session, commit=True)

    deleted_platform = Platform.get_deleted_by_id(test_db_session, platform_id)
    assert deleted_platform is not None and deleted_platform.is_deleted

    deleted_membership = PlatformMembership.get_deleted_by_id(test_db_session, membership_id)
    assert deleted_membership is not None and deleted_membership.is_deleted

    active_memberships = PlatformMembership.get_by_user_id(user.id, test_db_session)
    assert active_memberships == []

    for history_id in history_ids:
        deleted_history = PlatformMembershipHistory.get_deleted_by_id(test_db_session, history_id)
        assert deleted_history is not None and deleted_history.is_deleted

    active_history = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.platform_id == platform_id,
            PlatformMembershipHistory.user_id == user.id,
        )
    ).all()
    assert active_history == []


def test_group_membership_getters_respect_soft_delete(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    user = BiocommonsUserFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    membership.save_history(test_db_session, commit=True)
    test_db_session.commit()

    assert GroupMembership.get_by_user_id(user.id, test_db_session)
    assert GroupMembership.get_by_user_id(
        user.id, test_db_session, ApprovalStatusEnum.APPROVED
    )
    initial_history = GroupMembershipHistory.get_by_user_id_and_group_id(user.id, membership.group_id, test_db_session)[0]

    membership_id = membership.id
    group_id = membership.group_id
    membership.delete(test_db_session, commit=True)
    assert GroupMembership.get_by_user_id(user.id, test_db_session) == []
    assert (
        GroupMembership.get_by_user_id(
            user.id, test_db_session, ApprovalStatusEnum.APPROVED
        )
        == []
    )
    assert GroupMembership.get_deleted_by_id(test_db_session, membership_id) is not None

    assert GroupMembershipHistory.get_by_user_id_and_group_id(user.id, group_id, test_db_session) == []
    deleted_history_entry = GroupMembershipHistory.get_deleted_by_id(test_db_session, initial_history.id)
    assert deleted_history_entry is not None and deleted_history_entry.is_deleted

    restored_membership = GroupMembership.get_deleted_by_id(test_db_session, membership_id)
    restored_membership.restore(test_db_session, commit=True)
    assert GroupMembership.get_by_user_id(user.id, test_db_session)


def test_biocommons_user_delete_soft_deletes_memberships_and_history(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    group = BiocommonsGroupFactory.create_sync()

    platform_membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    group_membership = GroupMembershipFactory.create_sync(
        user=user,
        group=group,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    platform_history = platform_membership.save_history(test_db_session)
    group_history = group_membership.save_history(test_db_session, commit=True)
    test_db_session.commit()

    platform_history_id = platform_history.id
    group_history_id = group_history.id

    user_id = user.id
    platform_membership_id = platform_membership.id
    group_membership_id = group_membership.id

    test_db_session.refresh(user)
    user.delete(test_db_session, commit=True)

    deleted_user = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert deleted_user is not None and deleted_user.is_deleted

    deleted_platform_membership = PlatformMembership.get_deleted_by_id(test_db_session, platform_membership_id)
    assert deleted_platform_membership is not None and deleted_platform_membership.is_deleted
    assert PlatformMembership.get_by_user_id(user_id, test_db_session) == []

    deleted_group_membership = GroupMembership.get_deleted_by_id(test_db_session, group_membership_id)
    assert deleted_group_membership is not None and deleted_group_membership.is_deleted
    assert GroupMembership.get_by_user_id(user_id, test_db_session) == []

    deleted_platform_history = PlatformMembershipHistory.get_deleted_by_id(test_db_session, platform_history_id)
    assert deleted_platform_history is not None and deleted_platform_history.is_deleted
    assert (
        test_db_session.exec(
            select(PlatformMembershipHistory).where(
                PlatformMembershipHistory.user_id == user_id,
                PlatformMembershipHistory.platform_id == PlatformEnum.GALAXY,
            )
        ).all()
        == []
    )

    deleted_group_history = GroupMembershipHistory.get_deleted_by_id(test_db_session, group_history_id)
    assert deleted_group_history is not None and deleted_group_history.is_deleted
    assert GroupMembershipHistory.get_by_user_id_and_group_id(user_id, group.group_id, test_db_session) == []


def test_group_delete_soft_deletes_memberships_and_history(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    user = BiocommonsUserFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    first_history = membership.save_history(test_db_session)
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = "Revoked by group admin"
    membership.updated_at = datetime.now(tz=timezone.utc)
    second_history = membership.save_history(test_db_session, commit=True)

    group_id = group.group_id
    membership_id = membership.id
    history_ids = [first_history.id, second_history.id]

    test_db_session.refresh(group)
    group.delete(test_db_session, commit=True)

    deleted_group = BiocommonsGroup.get_deleted_by_id(test_db_session, group_id)
    assert deleted_group is not None and deleted_group.is_deleted

    deleted_membership = GroupMembership.get_deleted_by_id(test_db_session, membership_id)
    assert deleted_membership is not None and deleted_membership.is_deleted
    assert GroupMembership.get_by_user_id(user.id, test_db_session) == []

    for history_id in history_ids:
        deleted_history = GroupMembershipHistory.get_deleted_by_id(test_db_session, history_id)
        assert deleted_history is not None and deleted_history.is_deleted

    active_history = GroupMembershipHistory.get_by_user_id_and_group_id(user.id, group_id, test_db_session)
    assert active_history == []


def test_platform_membership_get_by_user_filters(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.BPA_DATA_PORTAL,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    test_db_session.commit()

    approved_only = PlatformMembership.get_by_user_id(
        user.id, test_db_session, ApprovalStatusEnum.APPROVED
    )
    assert {m.platform_id for m in approved_only} == {PlatformEnum.GALAXY}

    approved_set = PlatformMembership.get_by_user_id(
        user.id,
        test_db_session,
        {ApprovalStatusEnum.APPROVED, ApprovalStatusEnum.REVOKED},
    )
    assert {m.platform_id for m in approved_set} == {PlatformEnum.GALAXY}


def test_platform_membership_save_history_adds_when_not_in_session(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembership(
        platform_id=platform.id,
        platform=platform,
        user_id=user.id,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )

    history = membership.save_history(test_db_session)
    test_db_session.flush()

    assert membership in test_db_session
    assert history.platform_id == platform.id
    assert history.user_id == user.id


def test_platform_membership_get_data_updated_by(test_db_session, persistent_factories):
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    membership = PlatformMembershipFactory.create_sync(
        platform=platform,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    automatic_data = membership.get_data()
    assert automatic_data.updated_by == "(automatic)"
    assert automatic_data.platform_name == platform.name

    updater = BiocommonsUserFactory.create_sync()
    membership.updated_by = updater
    test_db_session.commit()

    updated_data = membership.get_data()
    assert updated_data.updated_by == updater.email


def test_group_membership_get_by_user_filters(test_db_session, persistent_factories):
    approved_group = BiocommonsGroupFactory.create_sync()
    pending_group = BiocommonsGroupFactory.create_sync()
    user = BiocommonsUserFactory.create_sync()
    GroupMembershipFactory.create_sync(
        group=approved_group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    GroupMembershipFactory.create_sync(
        group=pending_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    test_db_session.commit()

    approved_only = GroupMembership.get_by_user_id(
        user.id, test_db_session, ApprovalStatusEnum.APPROVED
    )
    assert {m.approval_status for m in approved_only} == {ApprovalStatusEnum.APPROVED}

    approved_set = GroupMembership.get_by_user_id(
        user.id,
        test_db_session,
        {ApprovalStatusEnum.APPROVED, ApprovalStatusEnum.REVOKED},
    )
    assert {m.approval_status for m in approved_set} == {ApprovalStatusEnum.APPROVED}


def test_group_membership_has_membership(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    user = BiocommonsUserFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    assert GroupMembership.has_group_membership(user.id, group.group_id, test_db_session)

    membership.approval_status = ApprovalStatusEnum.PENDING
    test_db_session.commit()
    assert not GroupMembership.has_group_membership(user.id, group.group_id, test_db_session)


def test_group_membership_get_data_updated_by(test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(group=group, approval_status=ApprovalStatusEnum.APPROVED)
    test_db_session.commit()

    automatic_data = membership.get_data()
    assert automatic_data.updated_by == "(automatic)"

    updater = BiocommonsUserFactory.create_sync()
    membership.updated_by = updater
    test_db_session.commit()

    updated_data = membership.get_data()
    assert updated_data.updated_by == updater.email


def test_group_membership_history_get_by_user(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    membership.save_history(test_db_session, commit=True)

    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.save_history(test_db_session, commit=True)

    other_group = BiocommonsGroupFactory.create_sync()
    other_membership = GroupMembershipFactory.create_sync(
        group=other_group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    other_membership.save_history(test_db_session, commit=True)

    history_entries = GroupMembershipHistory.get_by_user_id(user.id, test_db_session)
    assert len(history_entries) == 3
    assert {entry.group_id for entry in history_entries} == {group.group_id, other_group.group_id}


def test_group_membership_history_get_by_user_id_and_group(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync()
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    membership.save_history(test_db_session, commit=True)
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.save_history(test_db_session, commit=True)

    history_for_group = GroupMembershipHistory.get_by_user_id_and_group_id(
        user.id, group.group_id, test_db_session
    )
    assert len(history_for_group) == 2


def test_biocommons_user_has_platform_membership_respects_soft_delete(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.commit()

    assert BiocommonsUser.has_platform_membership(user.id, PlatformEnum.GALAXY, test_db_session)

    membership.delete(test_db_session, commit=True)
    assert not BiocommonsUser.has_platform_membership(user.id, PlatformEnum.GALAXY, test_db_session)

    membership.restore(test_db_session, commit=True)
    assert BiocommonsUser.has_platform_membership(user.id, PlatformEnum.GALAXY, test_db_session)


def test_soft_delete_recreate_revives_deleted(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync(
        email="user@example.com",
        username="soft_delete_user",
    )
    test_db_session.commit()

    user_id = user.id
    user.delete(test_db_session, commit=True)

    replacement = BiocommonsUser(
        id=user_id,
        email="new@example.com",
        username="soft_delete_user",
        email_verified=True,
    )
    test_db_session.add(replacement)
    test_db_session.commit()

    revived = test_db_session.get(BiocommonsUser, user_id)
    assert revived is not None
    assert revived.email == "new@example.com"
    assert not revived.is_deleted
    assert BiocommonsUser.get_deleted_by_id(test_db_session, user_id) is None


def test_soft_delete_duplicate_active_raises(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    test_db_session.commit()

    duplicate = BiocommonsUser(
        id=user.id,
        email=user.email,
        username=user.username,
        email_verified=True,
    )
    test_db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        test_db_session.commit()
    test_db_session.rollback()


def test_soft_delete_restore(test_db_session, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    test_db_session.commit()

    user_id = user.id
    user.delete(test_db_session, commit=True)
    deleted = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert deleted is not None

    deleted.restore(test_db_session, commit=True)
    restored = test_db_session.get(BiocommonsUser, user_id)
    assert restored is not None
    assert not restored.is_deleted
