from datetime import datetime, timezone
from unittest.mock import ANY

import pytest
import respx
from httpx import Response
from mimesis import Person
from mimesis.locales import Locale
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from db.models import Auth0Role, BiocommonsGroup, GroupMembership
from tests.biocommons.datagen import RoleFactory
from tests.datagen import random_auth0_id
from tests.db.datagen import Auth0RoleFactory, BiocommonsGroupFactory


def test_create_group_membership(test_db_session):
    """
    Test creating a group membership
    """
    # Provide test_db_session to factories
    BiocommonsGroupFactory.__session__  = test_db_session

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
    test_db_session.refresh(membership)
    assert membership.group.group_id == "biocommons/group/tsi"
    BiocommonsGroupFactory.__session__  = None


def test_create_group_membership_unique_constraint(test_db_session):
    """
    Check that trying to create multiple group memberships
    for the same user/group raises IntegrityError
    """
    # Provide test_db_session to factories
    BiocommonsGroupFactory.__session__ = test_db_session

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
    BiocommonsGroupFactory.__session__  = None


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
def test_create_auth0_role_by_name(test_db_session, auth0_client):
    """
    Test when can create an auth0 role by name, looking up the role in Auth0 first
    """
    role_data = RoleFactory.build(name="biocommons/role/tsi/admin")
    respx.get("https://example.auth0.com/api/v2/roles", params={"name_filter": ANY}).mock(
        return_value=Response(200, json=[role_data.model_dump(mode="json")])
    )
    Auth0Role.get_or_create_by_name(
        name=role_data.name,
        session=test_db_session,
        auth0_client=auth0_client
    )
    role_from_db = test_db_session.exec(
        select(Auth0Role).where(Auth0Role.id == role_data.id)
    ).first()
    assert role_from_db.name == role_data.name


@respx.mock
def test_create_auth0_role_by_id(test_db_session, auth0_client):
    """
    Test when can create an auth0 role by id, looking up the role in Auth0 first
    """
    role_data = RoleFactory.build(name="biocommons/role/tsi/admin")
    respx.get(f"https://example.auth0.com/api/v2/roles/{role_data.id}").mock(
        return_value=Response(200, json=role_data.model_dump(mode="json"))
    )
    Auth0Role.get_or_create_by_id(
        auth0_id=role_data.id,
        session=test_db_session,
        auth0_client=auth0_client
    )
    role_from_db = test_db_session.exec(
        select(Auth0Role).where(Auth0Role.id == role_data.id)
    ).first()
    assert role_from_db.name == role_data.name


def test_create_biocommons_group(test_db_session):
    """
    Test creating a biocommons group (with associated roles)
    """
    Auth0RoleFactory.__session__ = test_db_session
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
    Auth0RoleFactory.__session__ = None
