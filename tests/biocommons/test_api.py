from http import HTTPStatus

import respx
from moto.core import DEFAULT_ACCOUNT_ID
from moto.ses import ses_backends

from auth.user_permissions import get_session_user
from db.models import (
    GroupMembership,
    GroupMembershipHistory,
)
from main import app
from tests.biocommons.datagen import RoleDataFactory
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    RoleUserDataFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
)


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
    admin_stub = RoleUserDataFactory.build(user_id=admin_info.user_id, email=admin_info.email)
    mock_auth0_client.get_all_role_users.return_value = [admin_stub]
    mock_auth0_client.get_user.return_value = admin_info
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
    membership = GroupMembership.get_by_user_id_and_group_id(user_id=normal_user.access_token.sub, group_id=group.group_id, session=test_db_session)
    assert membership.approval_status == "pending"
    history = GroupMembershipHistory.get_by_user_id_and_group_id(user_id=normal_user.access_token.sub, group_id=group.group_id, session=test_db_session)
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
    # Override get_session_user to return the group admin
    app.dependency_overrides[get_session_user] = lambda: group_admin
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
    # Override get_session_user to return the group admin
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.user_id
        }
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json()["detail"] == f"You do not have permission to approve group memberships for {group.name}"
