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


@pytest.mark.parametrize("platform_id", list(PlatformEnum))
def test_create_platform(platform_id, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync()
    platform = Platform(
        id=platform_id,
        name=f"Platform {platform_id}",
        admin_roles=[admin_role]
    )
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
    membership = PlatformMembershipFactory.create_sync(
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
