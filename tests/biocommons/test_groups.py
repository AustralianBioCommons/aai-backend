
import pytest
from sqlmodel import select

from biocommons.groups import BiocommonsGroupCreate, is_valid_group_id, is_valid_role_id
from db.models import BiocommonsGroup
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


def test_biocommons_group_create_save(test_db_session, test_auth0_client):
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
    group.save_group(test_db_session)
    group_from_db = test_db_session.exec(
        select(BiocommonsGroup).where(BiocommonsGroup.group_id == group.group_id)
    ).one()
    assert group_from_db.group_id == group.group_id
