
import pytest
import respx
from httpx import Response
from sqlmodel import select

from db.models import Auth0Role, BiocommonsGroup
from tests.biocommons.datagen import RoleDataFactory
from tests.db.datagen import Auth0RoleFactory


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
