from http import HTTPStatus

import respx
from sqlmodel import select

from auth.user_permissions import get_session_user
from db.models import (
    EmailNotification,
)
from db.types import ApprovalStatusEnum, EmailStatusEnum
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


@respx.mock
def test_group_admin_cannot_approve_rejected_membership(
    test_client,
    test_db_session,
    persistent_factories,
    test_auth0_client,
):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    group_admin = SessionUserFactory.build(access_token=access_token)
    app.dependency_overrides[get_session_user] = lambda: group_admin
    BiocommonsUserFactory.create_sync(id=group_admin.access_token.sub, email=group_admin.access_token.email)
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership_request = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.REJECTED.value,
    )
    respx.get(
        f"https://{test_auth0_client.domain}/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(
        200,
        json=[RoleDataFactory.build(name=group.group_id).model_dump(mode="json")]
    )
    respx.post(f"https://{test_auth0_client.domain}/api/v2/users/{user.id}/roles").respond(204)

    resp = test_client.post(
        "/biocommons/groups/approve",
        json={
            "group_id": group.group_id,
            "user_id": user.id
        }
    )

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Only pending or revoked group memberships can be approved."
    test_db_session.refresh(membership_request)
    assert membership_request.approval_status == ApprovalStatusEnum.REJECTED


@respx.mock
def test_group_admin_approval_sends_user_email(
    test_client_with_email,
    test_db_session,
    persistent_factories,
    test_auth0_client,
    mocker,
):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    access_token = AccessTokenPayloadFactory.build(biocommons_roles=[admin_role.name])
    group_admin = SessionUserFactory.build(access_token=access_token)
    BiocommonsUserFactory.create_sync(id=group_admin.access_token.sub, email=group_admin.access_token.email)
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    GroupMembershipFactory.create_sync(group=group, user=user, approval_status="pending")
    app.dependency_overrides[get_session_user] = lambda: group_admin
    respx.get(
        f"https://{test_auth0_client.domain}/api/v2/roles",
        params={"name_filter": group.group_id}
    ).respond(
        200,
        json=[RoleDataFactory.build(name=group.group_id).model_dump(mode="json")]
    )
    respx.post(f"https://{test_auth0_client.domain}/api/v2/users/{user.id}/roles").respond(204)
    resp = test_client_with_email.post(
        "/biocommons/groups/approve",
        json={"group_id": group.group_id, "user_id": user.id},
    )
    assert resp.status_code == 200
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == user.email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


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
