from http import HTTPStatus
from unittest.mock import ANY

import pytest
import respx
from httpx import Response
from moto.core import DEFAULT_ACCOUNT_ID
from moto.ses import ses_backends
from sqlmodel import select

from auth.validator import get_current_user
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    GroupMembership,
    GroupMembershipHistory,
)
from main import app
from tests.biocommons.datagen import RoleDataFactory
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
)


@respx.mock
def test_create_group(test_client, as_admin_user, test_auth0_client, test_db_session, persistent_factories):
    # Mock Auth0 response to check group exists
    mock_group = RoleDataFactory.build(name="biocommons/group/tsi")
    route = respx.get(f"https://{test_auth0_client.domain}/api/v2/roles", params={"name_filter": ANY}).mock(
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
    assert resp.status_code == 200
    assert route.called
    role_lookup = route.calls[0].request.url.params
    assert role_lookup["name_filter"] == "biocommons/group/tsi"
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
        "/biocommons/roles/create",
        json={
            "name": role_name,
            "description": "Admin role for Threatened Species Initiative"
        }
    )
    assert resp.status_code == 200
    role_from_db = test_db_session.exec(select(Auth0Role).where(Auth0Role.name == role_name)).one()
    assert role_from_db.name == role_name


@respx.mock
def test_request_group_membership(test_client_with_email, normal_user, as_normal_user, mock_auth0_client, test_db_session, persistent_factories, mock_email_service, mocker):
    """
    Test the full process of requesting group membership - request membership for a user
    and send approval email to the relevant admins.
    """
    test_client = test_client_with_email
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    user = BiocommonsUserFactory.create_sync(group_memberships=[], id=normal_user.access_token.sub)
    # Mock an admin that has the required admin role (to send approval email to)
    admin_info = Auth0UserDataFactory.build(email="admin@example.com")
    mock_auth0_client.get_all_role_users.return_value = [admin_info]
    # Request membership
    resp = test_client.post(
        "/biocommons/groups/request",
        json={
            "group_id": group.group_id,
        }
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == f"Group membership for {group.group_id} requested successfully."
    # Check membership request is created along with history entry
    membership = GroupMembership.get_by_user_id(user_id=normal_user.access_token.sub, group_id=group.group_id, session=test_db_session)
    assert membership.approval_status == "pending"
    history = GroupMembershipHistory.get_by_user_id(user_id=normal_user.access_token.sub, group_id=group.group_id, session=test_db_session)
    assert len(history) == 1
    assert history[0].approval_status == "pending"
    assert membership.user == user
    # Check approval email is sent to admins
    ses_backend = ses_backends[DEFAULT_ACCOUNT_ID]["us-east-1"]
    assert len(ses_backend.sent_messages) == 1
    to_addresses = ses_backend.sent_messages[0].destinations['ToAddresses']
    assert admin_info.email in to_addresses


@respx.mock
def test_approve_group_membership(test_client, test_db_session, persistent_factories, test_auth0_client):
    """
    Test the full approval process, including:
    * Checking that the group admin has the required role
    * Adding the role via the Auth0 API
    * Updating the group membership request in the DB
    """
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    group_admin = SessionUserFactory.build(access_token=access_token)
    group_admin_db = BiocommonsUserFactory.create_sync(id=group_admin.access_token.sub, email=group_admin.access_token.email)
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership_request = GroupMembershipFactory.create_sync(group=group, user=user, approval_status="pending")
    # Override get_current_user to return the group admin
    app.dependency_overrides[get_current_user] = lambda: group_admin
    # Mock auth0 route for adding roles
    respx.get(
        f"https://{test_auth0_client.domain}/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(
        200,
        json=[RoleDataFactory.build(name=group.group_id).model_dump(mode="json")]
    )
    route = respx.post(f"https://{test_auth0_client.domain}/api/v2/users/{user.id}/roles").respond(204)
    # Call our group approval endpoint
    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.id
        }
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == f"Group membership for {group.name} approved successfully."
    # Check role added in Auth0 API
    assert route.called
    test_db_session.refresh(membership_request)
    assert membership_request.approval_status == "approved"
    assert membership_request.updated_by == group_admin_db
    assert membership_request.updated_by.email == group_admin.access_token.email


def test_approve_group_membership_invalid_role(test_client, test_db_session, persistent_factories, test_auth0_client):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/biocommons/sysadmin"])
    unauthorized_admin = SessionUserFactory.build(access_token=access_token)
    user = Auth0UserDataFactory.build()
    GroupMembershipFactory.create_sync(group=group, user_id=user.user_id, approval_status="pending")
    # Override get_current_user to return the group admin
    app.dependency_overrides[get_current_user] = lambda: unauthorized_admin
    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.user_id
        }
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json()["detail"] == f"You do not have permission to approve group memberships for {group.name}"
