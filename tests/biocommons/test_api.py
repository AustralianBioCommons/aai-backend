from unittest.mock import ANY

import pytest
import respx
from httpx import Response
from sqlmodel import select

from auth0.client import get_auth0_client
from db.models import Auth0Role, BiocommonsGroup
from main import app
from tests.biocommons.datagen import RoleFactory
from tests.db.datagen import Auth0RoleFactory


@pytest.fixture
def override_auth0_client(auth0_client):
    app.dependency_overrides[get_auth0_client] = lambda: auth0_client
    yield
    app.dependency_overrides.clear()


@respx.mock
def test_create_group(test_client, as_admin_user, override_auth0_client, test_db_session):
    Auth0RoleFactory.__session__ = test_db_session
    # Mock Auth0 response to check group exists
    mock_group = RoleFactory.build(name="biocommons/group/tsi")
    route = respx.get("https://example.auth0.com/api/v2/roles", params={"name_filter": ANY}).mock(
        return_value=Response(200, json=[mock_group.model_dump(mode="json")])
    )

    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    resp = test_client.post(
        "/biocommons/groups/create",
        json={
            "group_id": "biocommons/group/tsi",
            "name": "Threatened Species Initiative",
            "admin_roles": [admin_role.name]
        }
    )
    print(resp.json())
    assert resp.status_code == 200
    assert route.called
    group_from_db = test_db_session.exec(select(BiocommonsGroup).where(BiocommonsGroup.group_id == "biocommons/group/tsi")).one()
    assert group_from_db.group_id == "biocommons/group/tsi"
    assert group_from_db.name == "Threatened Species Initiative"
    assert admin_role in group_from_db.admin_roles


@respx.mock
def test_create_role(test_client, as_admin_user, override_auth0_client, test_db_session):
    mock_resp = RoleFactory.build(name="biocommons/role/tsi/admin")
    route = respx.post("https://example.auth0.com/api/v2/roles").mock(
        return_value=Response(200, json=mock_resp.model_dump(mode="json"))
    )
    resp = test_client.post(
        "/biocommons/roles/create",
        json={
            "name": "biocommons/role/tsi/admin",
            "description": "Admin role for Threatened Species Initiative"
        }
    )
    assert resp.status_code == 200
    assert route.called
    role_from_db = test_db_session.exec(select(Auth0Role).where(Auth0Role.name == "biocommons/role/tsi/admin")).one()
    assert role_from_db.name == "biocommons/role/tsi/admin"
