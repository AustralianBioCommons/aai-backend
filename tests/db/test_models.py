from datetime import datetime, timezone
from unittest.mock import ANY

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
from tests.datagen import Auth0UserDataFactory, random_auth0_id
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


@pytest.mark.parametrize("platform_id", list(PlatformEnum))
def test_create_platform(platform_id, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync()
    platform = Platform(
        id=platform_id,
        name=f"Platform {platform_id}",
        admin_roles=[admin_role]
    )
    test_db_session.add(platform)
    test_db_session.commit()
    assert platform.id == platform_id


def test_create_platform_unique_id(test_db_session):
    platform = Platform(id=PlatformEnum.GALAXY, name="Galaxy", admin_roles=[])
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
    role = Auth0RoleFactory.create_sync()
    group = BiocommonsGroupFactory.create_sync(admin_roles=[role])
    mock_client = mocker.Mock()
    mock_user_1 = Auth0UserDataFactory.build()
    mock_user_2 = Auth0UserDataFactory.build()
    mock_client.get_all_role_users.return_value = [mock_user_1, mock_user_2]

    admins = group.get_admins(mock_client)

    assert admins == {mock_user_1.email, mock_user_2.email}
    mock_client.get_all_role_users.assert_called_once_with(role_id=role.id)


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
    membership = GroupMembershipFactory.build(group_id=group.group_id)
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
    assert GroupMembershipHistory.get_by_user_id_and_group_id(user.id, membership.group_id, test_db_session)

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

    GroupMembershipHistory.get_by_user_id_and_group_id(user.id, group_id, test_db_session)[0].delete(test_db_session, commit=True)
    assert GroupMembershipHistory.get_by_user_id_and_group_id(user.id, group_id, test_db_session) == []

    restored_membership = GroupMembership.get_deleted_by_id(test_db_session, membership_id)
    restored_membership.restore(test_db_session, commit=True)
    assert GroupMembership.get_by_user_id(user.id, test_db_session)


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
