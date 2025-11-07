from http import HTTPStatus

import pytest
import respx
from httpx import Response
from sqlmodel import select

from db.models import Auth0Role, BiocommonsGroup, Platform
from db.types import PlatformEnum
from routers.biocommons_admin import PlatformCreateData
from tests.biocommons.datagen import RoleDataFactory
from tests.db.datagen import Auth0RoleFactory, PlatformFactory


@respx.mock
def test_create_group(test_client, as_admin_user, test_db_session, persistent_factories):
    # Role must exist in the DB beforehand
    Auth0RoleFactory.create_sync(name="biocommons/group/tsi")
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    resp = test_client.post(
        "/biocommons-admin/groups/create",
        json={
            "group_id": "biocommons/group/tsi",
            "name": "Threatened Species Initiative",
            "short_name": "TSI",
            "admin_roles": [admin_role.name]
        }
    )
    assert resp.status_code == 200
    group_from_db = test_db_session.exec(select(BiocommonsGroup).where(BiocommonsGroup.group_id == "biocommons/group/tsi")).one()
    assert group_from_db.group_id == "biocommons/group/tsi"
    assert group_from_db.name == "Threatened Species Initiative"
    assert admin_role in group_from_db.admin_roles


@pytest.mark.parametrize("role_name", ["biocommons/role/tsi/admin", "biocommons/group/tsi"])
@respx.mock
def test_create_role(role_name, test_client, as_admin_user, test_auth0_client, test_db_session, mocker):
    """
    Test we can create Auth0 roles using either the format for roles or groups.
    """
    mock_resp = RoleDataFactory.build(name=role_name)
    # Patch check of existing role
    mocker.patch("auth0.client.Auth0Client.get_role_by_name", side_effect=ValueError)
    route = respx.post(f"https://{test_auth0_client.domain}/api/v2/roles").mock(
        return_value=Response(200, json=mock_resp.model_dump(mode="json"))
    )
    resp = test_client.post(
        "/biocommons-admin/roles/create",
        json={
            "name": role_name,
            "description": "Admin role for Threatened Species Initiative"
        }
    )
    assert resp.status_code == 200
    assert route.called
    role_from_db = test_db_session.exec(select(Auth0Role).where(Auth0Role.name == role_name)).one()
    assert role_from_db.name == role_name


@pytest.mark.parametrize("role_name", ["biocommons/role/tsi/admin", "biocommons/group/tsi"])
def test_create_role_already_exists(role_name, test_client, test_auth0_client, as_admin_user, test_db_session, mocker):
    """
    Test we can add existing Auth0 roles to the DB
    """
    mock_resp = RoleDataFactory.build(name=role_name)
    # Patch check of existing role
    mocker.patch("auth0.client.Auth0Client.get_role_by_name", return_value=mock_resp)
    # No call to Auth0 API to create when the role already exists
    resp = test_client.post(
        "/biocommons-admin/roles/create",
        json={
            "name": role_name,
            "description": "Admin role for Threatened Species Initiative"
        }
    )
    assert resp.status_code == 200
    role_from_db = test_db_session.exec(select(Auth0Role).where(Auth0Role.name == role_name)).one()
    assert role_from_db.name == role_name


def test_create_group_missing_role(test_client, as_admin_user, test_db_session):
    resp = test_client.post(
        "/biocommons-admin/groups/create",
        json={
            "group_id": "biocommons/group/tsi",
            "name": "Threatened Species Initiative",
            "short_name": "TSI",
            "admin_roles": ["biocommons/role/tsi/admin"]
        },
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND
    assert resp.json()["detail"] == "Role for Threatened Species Initiative doesn't exist in the DB"
    assert (
        test_db_session.exec(
            select(BiocommonsGroup).where(BiocommonsGroup.group_id == "biocommons/group/tsi")
        ).first()
        is None
    )


def test_create_platform(test_client, as_admin_user, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/bdp/admin")
    resp = test_client.post(
        "/biocommons-admin/platforms/create",
        json={
            "id": PlatformEnum.BPA_DATA_PORTAL.value,
            "name": "BPA Data Portal",
            "admin_roles": [admin_role.name],
        },
    )
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert body["id"] == PlatformEnum.BPA_DATA_PORTAL.value
    assert body["name"] == "BPA Data Portal"
    platform_from_db = test_db_session.get(Platform, PlatformEnum.BPA_DATA_PORTAL)
    assert platform_from_db is not None
    test_db_session.refresh(platform_from_db)
    assert [role.name for role in platform_from_db.admin_roles] == [admin_role.name]


def test_create_platform_duplicate_id(test_client, as_admin_user, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/admin")
    payload = {
        "id": PlatformEnum.GALAXY.value,
        "name": "Galaxy Platform",
        "admin_roles": [admin_role.name],
    }
    first_resp = test_client.post("/biocommons-admin/platforms/create", json=payload)
    assert first_resp.status_code == HTTPStatus.OK

    second_resp = test_client.post("/biocommons-admin/platforms/create", json=payload)
    assert second_resp.status_code == HTTPStatus.BAD_REQUEST
    assert second_resp.json()["detail"] == "Platform PlatformEnum.GALAXY already exists"


def test_create_platform_missing_role(test_client, as_admin_user, test_db_session):
    resp = test_client.post(
        "/biocommons-admin/platforms/create",
        json={
            "id": PlatformEnum.SBP.value,
            "name": "SBP Platform",
            "admin_roles": ["biocommons/role/sbp/admin"],
        },
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["detail"] == "Role biocommons/role/sbp/admin doesn't exist in DB - create roles first"
    assert Platform.get_by_id(PlatformEnum.SBP, test_db_session) is None


def test_platform_create_data_save_without_commit(test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/local/admin")
    create_data = PlatformCreateData(
        id=PlatformEnum.SBP,
        name="SBP Platform",
        admin_roles=[admin_role.name],
    )
    platform = create_data.save_platform(test_db_session, commit=False)
    test_db_session.flush()

    persisted = test_db_session.exec(
        select(Platform).where(Platform.id == PlatformEnum.SBP)
    ).one()
    assert persisted is platform

    test_db_session.rollback()
    assert Platform.get_by_id(PlatformEnum.SBP, test_db_session) is None


@pytest.fixture
def galaxy_platform(persistent_factories):
    """
    Set up a Galaxy platform with the associated platform role
    """
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    return PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        role_id=platform_role.id,
        name="Galaxy Australia",
    )


def test_set_admin_roles_success(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    # Arrange
    pid = "galaxy"
    r1 = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/admin")
    r2 = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/moderator")

    # Act
    resp = test_client.post(
        f"/biocommons-admin/platforms/{pid}/set-admin-roles",
        json={"role_names": [r1.name, r2.name]},
    )

    # Assert
    assert resp.status_code == 200
    assert "set successfully" in resp.json()["message"]

    refreshed = test_db_session.get(Platform, galaxy_platform.id)
    names = sorted([r.name for r in refreshed.admin_roles])
    assert names == sorted([r1.name, r2.name])


def test_set_admin_roles_unknown_role(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    pid = "galaxy"
    known = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/admin")
    unknown = "biocommons/role/galaxy/does-not-exist"

    resp = test_client.post(
        f"/biocommons-admin/platforms/{pid}/set-admin-roles",
        json={"role_names": [known.name, unknown]},
    )

    assert resp.status_code == 400
    assert "doesn't exist in DB" in resp.json()["detail"]

    # Ensure no partial update occurred
    refreshed = test_db_session.get(Platform, pid)
    assert [r.name for r in refreshed.admin_roles] == []
