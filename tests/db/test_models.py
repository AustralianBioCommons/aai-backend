from datetime import datetime, timezone

import pytest
from mimesis import Person
from mimesis.locales import Locale
from sqlalchemy.exc import IntegrityError

from db.models import Auth0Role, BiocommonsGroup, GroupMembership
from tests.datagen import random_auth0_id
from tests.db.datagen import Auth0RoleFactory, BiocommonsGroupFactory


def test_create_group_membership(session):
    """
    Test creating a group membership
    """
    # Provide session to factories
    BiocommonsGroupFactory.__session__ = session

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
    session.add(membership)
    session.commit()
    session.refresh(membership)
    assert membership.group.group_id == "biocommons/group/tsi"


def test_create_group_membership_unique_constraint(session):
    """
    Check that trying to create multiple group memberships
    for the same user/group raises IntegrityError
    """
    # Provide session to factories
    BiocommonsGroupFactory.__session__ = session

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
    session.add(membership)
    session.commit()

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
        session.add(dupe_membership)
        session.commit()


def test_create_auth0_role(session):
    """
    Test creating an auth0 role
    """
    role = Auth0Role(auth0_id=random_auth0_id(), name="Example group")
    session.add(role)
    session.commit()
    session.refresh(role)
    assert role.name == "Example group"


def test_create_biocommons_group(session):
    """
    Test creating a biocommons group (with associated roles)
    """
    Auth0RoleFactory.__session__ = session
    roles = Auth0RoleFactory.create_batch_sync(size=2)
    group = BiocommonsGroup(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        admin_roles=roles
    )
    session.add(group)
    session.commit()
    session.refresh(group)
    assert group.group_id == "biocommons/group/tsi"
    assert all(role in group.admin_roles for role in roles)
    # Check the relationship in the other direction
    role = roles[0]
    assert group in role.admin_groups
