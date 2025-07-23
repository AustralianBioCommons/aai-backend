from http import HTTPStatus
from unittest.mock import ANY

import pytest
import respx
from httpx import Response
from sqlmodel import select

from auth.validator import get_current_user
from auth0.client import get_auth0_client
from db.models import ApprovalHistory, Auth0Role, BiocommonsGroup, GroupMembership
from main import app
from tests.biocommons.datagen import RoleDataFactory
from tests.datagen import (
    AccessTokenPayloadFactory,
    BiocommonsAuth0UserFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    GroupMembershipFactory,
)


@pytest.fixture
def override_auth0_client(auth0_client):
    app.dependency_overrides[get_auth0_client] = lambda: auth0_client
    yield
    app.dependency_overrides.clear()


@respx.mock
def test_create_group(test_client, as_admin_user, override_auth0_client, test_db_session, persistent_factories):
    # Mock Auth0 response to check group exists
    mock_group = RoleDataFactory.build(name="biocommons/group/tsi")
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


@pytest.mark.parametrize("role_name", ["biocommons/role/tsi/admin", "biocommons/group/tsi"])
@respx.mock
def test_create_role(role_name, test_client, as_admin_user, override_auth0_client, test_db_session):
    """
    Test we can create Auth0 roles using either the format for roles or groups.
    """
    mock_resp = RoleDataFactory.build(name=role_name)
    route = respx.post("https://example.auth0.com/api/v2/roles").mock(
        return_value=Response(200, json=mock_resp.model_dump(mode="json"))
    )
    resp = test_client.post(
        "/biocommons/roles/create",
        json={
            "name": role_name,
            "description": "Admin role for Threatened Species Initiative"
        }
    )
    assert resp.status_code == 200
    assert route.called
    role_from_db = test_db_session.exec(select(Auth0Role).where(Auth0Role.name == role_name)).one()
    assert role_from_db.name == role_name


# TODO: test that approval emails are sent
@respx.mock
def test_request_group_membership(test_client, admin_user, as_admin_user, override_auth0_client, test_db_session, persistent_factories):
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[])
    resp = test_client.post(
        "/biocommons/groups/request",
        json={
            "group_id": group.group_id,
        }
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == f"Group membership for {group.group_id} requested successfully."
    membership = GroupMembership.get_by_user_id(user_id=admin_user.access_token.sub, group_id=group.group_id, session=test_db_session)
    assert membership.approval_status == "pending"
    history = ApprovalHistory.get_by_user_id(user_id=admin_user.access_token.sub, group_id=group.group_id, session=test_db_session)
    assert len(history) == 1
    assert history[0].approval_status == "pending"


def test_approve_group_membership(test_client, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    group_admin = SessionUserFactory.build(access_token=access_token)
    user = BiocommonsAuth0UserFactory.build()
    membership_request = GroupMembershipFactory.create_sync(group=group, user_id=user.user_id, approval_status="pending")
    # Override get_current_user to return the group admin
    app.dependency_overrides[get_current_user] = lambda: group_admin
    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.user_id
        }
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == f"Group membership for {group.name} approved successfully."
    test_db_session.refresh(membership_request)
    assert membership_request.approval_status == "approved"
    assert membership_request.updated_by_id == group_admin.access_token.sub
    assert membership_request.updated_by_email == group_admin.access_token.email


def test_approve_group_membership_invalid_role(test_client, test_db_session, persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/biocommons/sysadmin"])
    unauth_admin = SessionUserFactory.build(access_token=access_token)
    user = BiocommonsAuth0UserFactory.build()
    GroupMembershipFactory.create_sync(group=group, user_id=user.user_id, approval_status="pending")
    # Override get_current_user to return the group admin
    app.dependency_overrides[get_current_user] = lambda: unauth_admin
    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.user_id
        }
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json()["detail"] == f"You do not have permission to approve group memberships for {group.name}"
