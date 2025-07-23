from unittest.mock import ANY

import pytest
import respx
from httpx import Response
from sqlmodel import select

from biocommons.groups import BiocommonsGroupCreate, is_valid_group_id, is_valid_role_id
from db.models import Auth0Role, BiocommonsGroup
from tests.biocommons.datagen import RoleDataFactory
from tests.db.datagen import Auth0RoleFactory


@pytest.mark.parametrize("group_id", [
    "biocommons/group/tsi",
    "biocommons/group/bird_genomics",
    "biocommons/group/biology2",
])
def test_valid_group_ids(group_id):
    assert is_valid_group_id(group_id)


@pytest.mark.parametrize("group_id", [
    "BioCommons/Group/TSI",
    "biocommons/tsi",
    "biocommons/group/crab-data"
])
def test_invalid_group_ids(group_id):
    assert not is_valid_group_id(group_id)


@pytest.mark.parametrize("role_id", [
    "biocommons/role/tsi/admin",
    "biocommons/role/biocommons/sysadmin",
    "biocommons/role/tsi/data_manager",
])
def test_valid_role_ids(role_id):
    assert is_valid_role_id(role_id)


def test_biocommons_group_create():
    """
    Test we can create a BiocommonsGroupCreate object
    that doesn't required the DB
    """
    group = BiocommonsGroupCreate(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        admin_roles=["biocommons/role/tsi/admin", "biocommons/role/bpa/admin"]
    )
    assert group.group_id == "biocommons/group/tsi"


def test_biocommons_group_create_save(test_db_session, auth0_client):
    """
    Test saving BiocommonsGroupCreate object to the DB
    """
    tsi_admin = Auth0RoleFactory.build(name="biocommons/role/tsi/admin")

    sysadmin = Auth0RoleFactory.build(name="biocommons/role/biocommons/sysadmin")
    group = BiocommonsGroupCreate(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        admin_roles=[tsi_admin, sysadmin]
    )
    group.save(test_db_session, auth0_client=auth0_client)
    group_from_db = test_db_session.exec(
        select(BiocommonsGroup).where(BiocommonsGroup.group_id == group.group_id)
    ).one()
    assert group_from_db.group_id == group.group_id


@respx.mock
def test_biocommons_group_save_get_roles(test_db_session, auth0_client, mocker):
    """
    Test saving BiocommonsGroupCreate to the DB when
    roles have to be fetched from Auth0.
    """
    role = RoleDataFactory.build(name="biocommons/role/tsi/admin")
    route = respx.get("https://example.auth0.com/api/v2/roles", params={"name_filter": ANY}).mock(
        return_value=Response(200, json=[role.model_dump(mode="json")])
    )
    group = BiocommonsGroupCreate(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        admin_roles=["biocommons/role/tsi/admin"]
    )
    group.save(test_db_session, auth0_client=auth0_client)
    group_from_db = test_db_session.exec(
        select(BiocommonsGroup).where(BiocommonsGroup.group_id == group.group_id)
    ).one()
    assert group_from_db.group_id == group.group_id
    role_from_db = test_db_session.exec(
        select(Auth0Role).where(Auth0Role.id == role.id)
    ).first()
    assert route.called
    assert role_from_db is not None
