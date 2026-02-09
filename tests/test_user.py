import hashlib
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import AsyncMock

import pytest
import respx
from fastapi import HTTPException
from httpx import HTTPStatusError, Request, Response
from sqlmodel import select

from db.models import (
    BiocommonsUserHistory,
    EmailChangeOtp,
    EmailNotification,
    GroupMembership,
    GroupMembershipHistory,
)
from db.types import (
    ApprovalStatusEnum,
    EmailStatusEnum,
    GroupEnum,
    PlatformEnum,
)
from routers.user import get_user_data, update_user_metadata
from schemas.biocommons import Auth0Identity, BiocommonsAppMetadata
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    RoleUserDataFactory,
    SessionUserFactory,
    UserInfoFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)


# --- Test Fixtures ---
@pytest.fixture
def mock_auth_token(mocker):
    """Fixture to mock authentication token"""
    token = AccessTokenPayloadFactory.build(
        sub="auth0|123456789",
        biocommons_roles=["acdc/indexd_admin"],
    )
    mocker.patch("auth.validator.verify_jwt", return_value=token)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    return token


@pytest.fixture
def mock_verify_action_token(mocker):
    mocked = mocker.patch("routers.user.verify_action_token")
    return mocked


@pytest.fixture
def auth_headers():
    """Fixture to provide auth headers"""
    return {"Authorization": "Bearer valid_token"}


@pytest.fixture
def mock_user_data():
    """Fixture to provide mock user data"""
    return Auth0UserDataFactory.build(
        app_metadata=BiocommonsAppMetadata(registration_from="biocommons"),
)


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "status_code, expect_error",
    [
        (200, False),
        (500, True),
    ],
    ids=["success", "auth0-error"],
)
async def test_get_user_data_handles_responses(mocker, mock_settings, status_code, expect_error):
    user = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(sub="auth0|123")
    )
    expected = Auth0UserDataFactory.build()
    mocker.patch("routers.user.get_management_token", return_value="token")
    if status_code == 200:
        response = Response(status_code, json=expected.model_dump(mode="json"))
    else:
        response = Response(status_code, text="boom")

    route = respx.get(
        f"https://mock-domain/api/v2/users/{user.access_token.sub}"
    ).mock(return_value=response)

    if expect_error:
        with pytest.raises(HTTPException) as exc:
            await get_user_data(user, mock_settings)
        assert exc.value.status_code == 403
        assert exc.value.detail == "Failed to fetch user data"
    else:
        result = await get_user_data(user, mock_settings)
        assert result == expected

    assert route.called


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "status_code, expect_error",
    [
        (200, False),
        (500, True),
    ],
    ids=["success", "auth0-error"],
)
async def test_update_user_metadata_handles_responses(mocker, mock_settings, status_code, expect_error):
    metadata = {"foo": "bar"}
    mocker.patch("routers.user.get_settings", return_value=mock_settings)
    if status_code == 200:
        response = Response(status_code, json={"ok": True})
    else:
        response = Response(status_code, text="fail")

    route = respx.patch(
        "https://mock-domain/api/v2/users/auth0|123"
    ).mock(return_value=response)

    if expect_error:
        with pytest.raises(HTTPException) as exc:
            await update_user_metadata("auth0|123", "token", metadata)
        assert exc.value.status_code == 403
        assert exc.value.detail == "Failed to update user metadata"
    else:
        result = await update_user_metadata("auth0|123", "token", metadata)
        assert result == {"ok": True}

    assert route.called


# --- Authentication Tests (GET) ---
@pytest.mark.parametrize(
    "endpoint",
    [
        "/me/is-general-admin",
        "/me/platforms",
        "/me/platforms/approved",
        "/me/platforms/pending",
        "/me/groups",
        "/me/groups/approved",
        "/me/groups/pending",
        "/me/all/pending",
    ],
)
def test_endpoints_require_auth(endpoint, test_client):
    """Test that all endpoints require authentication"""
    response = test_client.get(endpoint)
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_check_is_admin_with_admin_role(test_client, mock_settings, mocker, test_db_session):
    """Test that admin check returns True for users with admin role"""
    from tests.datagen import SessionUserFactory

    admin_token = AccessTokenPayloadFactory.build(
        biocommons_roles=["Admin"]
    )
    admin_user = SessionUserFactory.build(access_token=admin_token)

    mocker.patch("auth.user_permissions.verify_jwt", return_value=admin_token)
    mocker.patch("auth.user_permissions.get_session_user", return_value=admin_user)

    response = test_client.get(
        "/me/is-general-admin",
        headers={"Authorization": "Bearer valid_token"}
    )

    assert response.status_code == 200
    is_admin = response.json()
    assert is_admin


def test_check_is_admin_with_non_admin_role(test_client, mock_settings, mocker, test_db_session):
    """Test that admin check returns False for users without admin role"""
    from tests.datagen import SessionUserFactory

    user_token = AccessTokenPayloadFactory.build(
        biocommons_roles=["User"]
    )
    user = SessionUserFactory.build(access_token=user_token)

    mocker.patch("auth.user_permissions.verify_jwt", return_value=user_token)
    mocker.patch("auth.user_permissions.get_session_user", return_value=user)

    response = test_client.get(
        "/me/is-general-admin",
        headers={"Authorization": "Bearer valid_token"}
    )

    assert response.status_code == 200
    is_admin = response.json()
    assert not is_admin


def test_check_is_admin_without_authentication(test_client):
    """Test that admin check requires authentication"""
    response = test_client.get("/me/is-general-admin")
    assert response.status_code == 401


def _act_as_user(mocker, db_user, roles: list[str] = None):
    """
    Set up mocks so that the test client authenticates as the given user
    """
    access_token = AccessTokenPayloadFactory.build(sub=db_user.id, biocommons_roles=roles or [])
    auth0_user = SessionUserFactory.build(access_token=access_token)
    mocker.patch("auth.user_permissions.verify_jwt", return_value=access_token)
    mocker.patch("routers.user.get_session_user", return_value=auth0_user)
    return auth0_user


def test_get_profile_returns_user_profile(test_client, test_db_session, mocker, persistent_factories):
    """Ensure the profile endpoint combines Auth0 data with DB memberships."""
    auth0_data = UserInfoFactory.build(
        sub="auth0|profile-user",
        email="profile.user@example.com",
        name="Profile User",
    )
    db_user = BiocommonsUserFactory.create_sync(
        id=auth0_data.sub,
        email=auth0_data.email,
        username="profile_user",
        platform_memberships=[],
        group_memberships=[],
    )

    galaxy_platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Galaxy Australia",
    )
    sbp_platform = PlatformFactory.create_sync(
        id=PlatformEnum.SBP,
        name="Sydney BioPlatforms",
    )
    tsi_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        short_name="TSI",
    )
    other_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/other_group",
        name="Research Group",
        short_name="RG",
    )

    PlatformMembershipFactory.create_sync(
        user=db_user,
        platform=galaxy_platform,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    PlatformMembershipFactory.create_sync(
        user=db_user,
        platform=sbp_platform,
        platform_id=sbp_platform.id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    GroupMembershipFactory.create_sync(
        user=db_user,
        group=tsi_group,
        group_id=tsi_group.group_id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    GroupMembershipFactory.create_sync(
        user=db_user,
        group=other_group,
        group_id=other_group.group_id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    test_db_session.flush()
    test_db_session.refresh(db_user)

    _act_as_user(mocker, db_user)

    with respx.mock:
        auth0_route = respx.get("https://mock-domain/userinfo").mock(
            return_value=Response(200, json=auth0_data.model_dump(mode="json"))
        )
        response = test_client.get("/me/profile", headers={"Authorization": "Bearer valid_token"})
        assert response.status_code == 200
        data = response.json()

        assert data["user_id"] == auth0_data.sub
        assert data["name"] == auth0_data.name
        assert data["email"] == db_user.email
        assert data["username"] == db_user.username

        platform_map = {item["platform_id"]: item for item in data["platform_memberships"]}
        assert platform_map[PlatformEnum.GALAXY]["platform_name"] == galaxy_platform.name
        assert platform_map[PlatformEnum.GALAXY]["approval_status"] == ApprovalStatusEnum.APPROVED.value
        assert platform_map[PlatformEnum.SBP]["platform_name"] == sbp_platform.name
        assert platform_map[PlatformEnum.SBP]["approval_status"] == ApprovalStatusEnum.PENDING.value

        group_map = {item["group_id"]: item for item in data["group_memberships"]}
        assert group_map[tsi_group.group_id]["group_name"] == tsi_group.name
        assert group_map[tsi_group.group_id]["group_short_name"] == tsi_group.short_name
        assert group_map[tsi_group.group_id]["approval_status"] == ApprovalStatusEnum.APPROVED.value
        assert group_map[other_group.group_id]["group_name"] == other_group.name
        assert group_map[other_group.group_id]["group_short_name"] == other_group.short_name
        assert group_map[other_group.group_id]["approval_status"] == ApprovalStatusEnum.PENDING.value
        assert auth0_route.called


def test_get_platforms(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of platforms"""
    user = BiocommonsUserFactory.create_sync()
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.GALAXY, approval_status=ApprovalStatusEnum.APPROVED)
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.BPA_DATA_PORTAL, approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/platforms", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    ids = [platform["platform_id"] for platform in data]
    assert PlatformEnum.GALAXY in ids
    assert PlatformEnum.BPA_DATA_PORTAL in ids


def test_get_approved_platforms(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of approved platforms"""
    user = BiocommonsUserFactory.create_sync()
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.GALAXY, approval_status=ApprovalStatusEnum.APPROVED)
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.BPA_DATA_PORTAL, approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/platforms/approved", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    ids = [platform["platform_id"] for platform in data]
    assert PlatformEnum.GALAXY in ids
    assert data[0]["approval_status"] == "approved"


def test_get_pending_platforms(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of pending platforms"""
    user = BiocommonsUserFactory.create_sync()
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.GALAXY, approval_status=ApprovalStatusEnum.APPROVED)
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.BPA_DATA_PORTAL, approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/platforms/pending", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    ids = [platform["platform_id"] for platform in data]
    assert PlatformEnum.BPA_DATA_PORTAL in ids
    assert data[0]["approval_status"] == "pending"


@respx.mock
def test_request_group_membership(test_client_with_email, normal_user, as_normal_user, mock_auth0_client, test_db_session, persistent_factories, mocker):
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
        "/me/groups/request",
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
    # Check approval email is queued for admin review
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == admin_info.email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


@respx.mock
def test_request_group_membership_after_rejection(
        test_client_with_email,
        normal_user,
        as_normal_user,
        mock_auth0_client,
        test_db_session,
        persistent_factories,
):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi", admin_roles=[admin_role])
    user = BiocommonsUserFactory.create_sync(group_memberships=[], id=normal_user.access_token.sub)
    membership = GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.REJECTED.value,
        rejection_reason="Incomplete application",
    )
    test_db_session.commit()

    admin_info = Auth0UserDataFactory.build(email="admin@example.com")
    admin_stub = RoleUserDataFactory.build(user_id=admin_info.user_id, email=admin_info.email)
    mock_auth0_client.get_all_role_users.return_value = [admin_stub]
    mock_auth0_client.get_user.return_value = admin_info

    resp = test_client_with_email.post(
        "/me/groups/request",
        json={
            "group_id": group.group_id,
        }
    )

    assert resp.status_code == 200
    assert resp.json()["message"] == f"Group membership for {group.group_id} requested successfully."

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.PENDING
    assert membership.rejection_reason is None
    assert membership.updated_by is None

    history = GroupMembershipHistory.get_by_user_id_and_group_id(
        user_id=normal_user.access_token.sub,
        group_id=group.group_id,
        session=test_db_session,
    )
    assert history[-1].approval_status == ApprovalStatusEnum.PENDING

    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == admin_info.email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


def test_request_group_membership_revoked_returns_conflict(
    test_client_with_email,
    normal_user,
    as_normal_user,
    test_db_session,
    persistent_factories,
):
    group_id = GroupEnum.TSI.value
    group = BiocommonsGroupFactory.create_sync(group_id=group_id)
    user = BiocommonsUserFactory.create_sync(group_memberships=[], id=normal_user.access_token.sub)
    GroupMembershipFactory.create_sync(
        group=group,
        user=user,
        approval_status=ApprovalStatusEnum.REVOKED.value,
    )
    test_db_session.commit()

    resp = test_client_with_email.post(
        "/me/groups/request",
        json={"group_id": group_id},
    )

    expected_group_name = group.name
    assert resp.status_code == 409
    assert resp.json()["detail"] == (
        "Your account has been revoked access to "
        f"{expected_group_name}, please contact support to access."
    )


def test_get_groups(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of groups"""
    user = BiocommonsUserFactory.create_sync()
    groups = BiocommonsGroupFactory.create_batch_sync(size=2)
    GroupMembershipFactory.create_sync(user=user, group=groups[0], approval_status=ApprovalStatusEnum.APPROVED)
    GroupMembershipFactory.create_sync(user=user, group=groups[1], approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/groups", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    ids = [group["group_id"] for group in data]
    assert all(group.group_id in ids for group in groups)
    names = [group["group_name"] for group in data]
    assert all(group.name in names for group in groups)


def test_get_approved_groups(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of approved groups"""
    user = BiocommonsUserFactory.create_sync()
    groups = BiocommonsGroupFactory.create_batch_sync(size=2)
    approved_group = GroupMembershipFactory.create_sync(user=user, group=groups[0], approval_status=ApprovalStatusEnum.APPROVED)
    GroupMembershipFactory.create_sync(user=user, group=groups[1], approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/groups/approved", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    ids = [group["group_id"] for group in data]
    assert approved_group.group_id in ids


def test_get_pending_groups(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of pending groups"""
    user = BiocommonsUserFactory.create_sync()
    groups = BiocommonsGroupFactory.create_batch_sync(size=2)
    GroupMembershipFactory.create_sync(user=user, group=groups[0], approval_status=ApprovalStatusEnum.APPROVED)
    pending_group = GroupMembershipFactory.create_sync(user=user, group=groups[1], approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/groups/pending", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    ids = [group["group_id"] for group in data]
    assert pending_group.group_id in ids


def test_get_all_pending(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns combined list of pending groups and platforms"""
    user = BiocommonsUserFactory.create_sync()
    groups = BiocommonsGroupFactory.create_batch_sync(size=2)
    GroupMembershipFactory.create_sync(user=user, group=groups[0], approval_status=ApprovalStatusEnum.APPROVED)
    pending_group = GroupMembershipFactory.create_sync(user=user, group=groups[1], approval_status=ApprovalStatusEnum.PENDING)
    PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.GALAXY, approval_status=ApprovalStatusEnum.APPROVED)
    pending_platform = PlatformMembershipFactory.create_sync(user=user, platform_id=PlatformEnum.BPA_DATA_PORTAL, approval_status=ApprovalStatusEnum.PENDING)
    test_db_session.flush()
    _act_as_user(mocker, user)
    response = test_client.get("/me/all/pending", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data["groups"]) == 1
    group_ids = [group["group_id"] for group in data["groups"]]
    assert pending_group.group_id in group_ids
    assert len(data["platforms"]) == 1
    platform_ids = [platform["platform_id"] for platform in data["platforms"]]
    assert pending_platform.platform_id in platform_ids


def test_get_admin_platforms(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of platforms the user is an admin for"""
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    other_platform_role = Auth0RoleFactory.create_sync(name="Other Platform Role")
    user = BiocommonsUserFactory.create_sync()
    valid_platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY, admin_roles=[admin_role])
    invalid_platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL, admin_roles=[other_platform_role])
    test_db_session.flush()
    _act_as_user(mocker, user, roles=[admin_role.name])
    response = test_client.get("/me/platforms/admin-roles", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == valid_platform.id
    assert data[0]["name"] == valid_platform.name
    # Should not include relationships or other fields
    assert "admin_roles" not in data[0]
    assert "platform_role" not in data[0]
    returned_ids = [p["id"] for p in data]
    assert invalid_platform.id not in returned_ids


def test_get_admin_groups(test_client, test_db_session, mocker, persistent_factories):
    """Test that endpoint returns list of groups the user is an admin for"""
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/test_group/admin")
    other_group_role = Auth0RoleFactory.create_sync(name="Other Group Role")
    user = BiocommonsUserFactory.create_sync()
    valid_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/test_group",
        name="Test Group",
        short_name="testgrp",
        admin_roles=[admin_role]
    )
    invalid_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/other",
        name="Other Group",
        short_name="other",
        admin_roles=[other_group_role]
    )
    test_db_session.flush()
    _act_as_user(mocker, user, roles=[admin_role.name])
    response = test_client.get("/me/groups/admin-roles", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == valid_group.group_id
    assert data[0]["name"] == valid_group.name
    assert data[0]["short_name"] == valid_group.short_name
    assert "admin_roles" not in data[0]
    assert "members" not in data[0]
    returned_ids = [g["id"] for g in data]
    assert invalid_group.group_id not in returned_ids


def test_update_username(test_client, test_db_session, mocker, persistent_factories):
    user = BiocommonsUserFactory.create_sync(username="old_username")
    mock_data = Auth0UserDataFactory.build(sub=user.id, username="new_username")
    mocker.patch("routers.user.Auth0Client.update_user", return_value=mock_data)
    _act_as_user(mocker, user)
    response = test_client.post(
        "/me/profile/username/update",
        headers={"Authorization": "Bearer valid_token"},
        json={"username": "new_username"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "new_username"
    test_db_session.refresh(user)
    assert user.username == "new_username"


def test_update_username_auth0_error(test_client, test_db_session, mocker, persistent_factories):
    """Test that update_username handles 400 error from Auth0 correctly."""

    user = BiocommonsUserFactory.create_sync(username="old_username")

    # Mock the Auth0 client to raise a 400 error
    error_response = Response(400, json={"message": "Username already exists"})
    mock_error = HTTPStatusError(
        message="400 Bad Request",
        request=Request("PATCH", "url"),
        response=error_response
    )
    mocker.patch("routers.user.Auth0Client.update_user", side_effect=mock_error)

    _act_as_user(mocker, user)

    response = test_client.post(
        "/me/profile/username/update",
        headers={"Authorization": "Bearer valid_token"},
        json={"username": "duplicate_username"},
    )

    assert response.status_code == 400
    assert response.json()["message"] == "Username already exists"

    # Verify DB user was not updated
    test_db_session.refresh(user)
    assert user.username == "old_username"


def test_update_name(test_client, mocker, persistent_factories):
    """Test updating user's first and last name."""
    user = BiocommonsUserFactory.create_sync()
    mock_data = Auth0UserDataFactory.build(
        sub=user.id,
        name="Jane Smith",
        given_name="Jane",
        family_name="Smith"
    )
    mock_update = mocker.patch("routers.user.Auth0Client.update_user", return_value=mock_data)
    _act_as_user(mocker, user)

    response = test_client.post(
        "/me/profile/name/update",
        headers={"Authorization": "Bearer valid_token"},
        json={"first_name": "Jane", "last_name": "Smith"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Jane Smith"
    assert data["given_name"] == "Jane"
    assert data["family_name"] == "Smith"

    call_args = mock_update.call_args
    update_data = call_args.kwargs["update_data"]
    assert update_data.given_name == "Jane"
    assert update_data.family_name == "Smith"
    assert update_data.name == "Jane Smith"


def test_update_name_requires_both_fields(test_client, mocker, persistent_factories):
    """Test that name update requires both first_name and last_name."""
    user = BiocommonsUserFactory.create_sync()
    _act_as_user(mocker, user)

    response = test_client.post(
        "/me/profile/name/update",
        headers={"Authorization": "Bearer valid_token"},
        json={},
    )

    assert response.status_code == 422
    # FastAPI will return validation error for missing required fields


def test_email_update_sends_otp(test_client, test_db_session, mocker, persistent_factories, mock_email_service):
    user = BiocommonsUserFactory.create_sync(email="old@example.com", email_verified=True)
    test_db_session.flush()
    _act_as_user(mocker, user)

    spy = mocker.spy(mock_email_service, "send")
    response = test_client.post(
        "/me/profile/email/update",
        headers={"Authorization": "Bearer valid_token"},
        json={"email": "new@example.com"},
    )

    assert response.status_code == 200
    entry = test_db_session.exec(
        select(EmailChangeOtp).where(
            EmailChangeOtp.user_id == user.id,
            EmailChangeOtp.is_active.is_(True),
        )
    ).one_or_none()
    assert entry is not None
    assert entry.target_email == "new@example.com"
    assert spy.call_count == 1


def test_email_continue_updates_user(test_client, test_db_session, mocker, persistent_factories):
    user = BiocommonsUserFactory.create_sync(email="old@example.com", email_verified=True)
    test_db_session.flush()
    _act_as_user(mocker, user)

    code = "123456"
    hashed = hashlib.sha256(code.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    otp_entry = EmailChangeOtp(
        user_id=user.id,
        target_email="new@example.com",
        otp_hash=hashed,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        window_start=now,
    )
    test_db_session.add(otp_entry)
    test_db_session.commit()

    updated_user = Auth0UserDataFactory.build(
        sub=user.id,
        email="new@example.com",
        email_verified=True,
        app_metadata=BiocommonsAppMetadata(registration_from="biocommons"),
    )
    current_auth0_user = Auth0UserDataFactory.build(
        sub=user.id,
        email=user.email,
        app_metadata=BiocommonsAppMetadata(registration_from="biocommons"),
    )
    mocker.patch("routers.user.Auth0Client.update_user", return_value=updated_user)
    mocker.patch("routers.user.Auth0Client.get_user", return_value=current_auth0_user)

    response = test_client.post(
        "/me/profile/email/continue",
        headers={"Authorization": "Bearer valid_token"},
        json={"otp": code},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "new@example.com"

    test_db_session.refresh(user)
    assert user.email == "new@example.com"
    assert user.email_verified

    history = test_db_session.exec(
        select(BiocommonsUserHistory).where(BiocommonsUserHistory.user_id == user.id)
    ).one()
    assert history.email == "old@example.com"
    assert history.change == "email_update"

    remaining_active = test_db_session.exec(
        select(EmailChangeOtp).where(
            EmailChangeOtp.user_id == user.id,
            EmailChangeOtp.is_active.is_(True),
        )
    ).one_or_none()
    assert remaining_active is None


def _make_auth0_identity(connection: str, user_id: str) -> Auth0Identity:
    return Auth0Identity(
        connection=connection,
        provider="auth0",
        user_id=user_id,
        isSocial=False,
    )


def _mock_password_change_user(mocker, db_user, connection: str = "Username-Password-Authentication"):
    """
    Helper to patch get_user_data and set the authenticated user context.
    """
    _act_as_user(mocker, db_user)
    auth0_user = Auth0UserDataFactory.build(
        user_id=db_user.id,
        email=db_user.email,
        username=db_user.username,
        identities=[_make_auth0_identity(connection=connection, user_id=db_user.id)],
    )
    mocker.patch("routers.user.get_user_data", new=AsyncMock(return_value=auth0_user))
    mocker.patch("routers.user.get_management_token", return_value="mgmt-token")
    return auth0_user


def test_change_password_success(test_client, test_db_session, mocker, persistent_factories):
    """Password change succeeds when Auth0 accepts the new password."""
    user = BiocommonsUserFactory.create_sync(email="test@example.com")
    test_db_session.flush()
    auth0_user =  _mock_password_change_user(mocker, user)

    with respx.mock:
        respx.post("https://mock-domain/oauth/token").mock(
            return_value=Response(200, json={"access_token": "access", "token_type": "Bearer"})
        )
        respx.patch(f"https://mock-domain/api/v2/users/{user.id}").mock(
            return_value=Response(200, json=auth0_user.model_dump(mode="json"))
        )

        response = test_client.post(
            "/me/profile/password/update",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "CurrentPass123!",
                "new_password": "NewPass123!",
            },
        )

    assert response.status_code == 200


def test_change_password_invalid_current_password(test_client, test_db_session, mocker, persistent_factories):
    """Password change fails when the current password is wrong."""
    user = BiocommonsUserFactory.create_sync()
    test_db_session.flush()
    _mock_password_change_user(mocker, user)

    with respx.mock:
        respx.post("https://mock-domain/oauth/token").mock(
            return_value=Response(403, json={"error": "invalid_grant"})
        )

        response = test_client.post(
            "/me/profile/password/update",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "WrongPass123!",
                "new_password": "AnotherPass123!",
            },
        )

    assert response.status_code == 400
    response_data = response.json()
    assert response_data["message"] == "Current password is incorrect"
    assert len(response_data["field_errors"]) == 1
    assert response_data["field_errors"][0]["field"] == "currentPassword"


def test_change_password_disallows_external_identity(test_client, mocker, persistent_factories):
    """Accounts without the configured connection cannot change their password."""
    user = BiocommonsUserFactory.create_sync()
    _act_as_user(mocker, user)
    auth0_user = Auth0UserDataFactory.build(
        user_id=user.id,
        email=user.email,
        username=user.username,
        identities=[_make_auth0_identity(connection="google-oauth2", user_id=user.id)],
    )
    mocker.patch("routers.user.get_user_data", new=AsyncMock(return_value=auth0_user))
    mocker.patch("routers.user.get_management_token", return_value="mgmt-token")

    response = test_client.post(
        "/me/profile/password/update",
        headers={"Authorization": "Bearer valid_token"},
        json={
            "current_password": "CurrentPass123!",
            "new_password": "BrandNew123!",
        },
    )

    assert response.status_code == 400
    assert "not supported" in response.json()["message"]


def test_migrate_password_success(
        test_client,
        mock_verify_action_token,
        mock_auth0_client,
        mock_settings
):
    """
    Test that migrate_password successfully triggers password change when token is valid.
    """
    # Setup mocks
    mock_verify_action_token.return_value = {"email": "user@example.com", "sub": "auth0|123"}

    payload = {
        "session_token": "valid_token",
        "client_id": "test_client_id"
    }

    response = test_client.post("/me/migration/update-password", json=payload)

    # Assertions
    assert response.status_code == 200
    assert response.json() == {"message": "Password change initiated successfully"}

    mock_verify_action_token.assert_called_once_with("valid_token", settings=mock_settings)
    mock_auth0_client.trigger_password_change.assert_called_once_with(
        user_email="user@example.com",
        client_id="test_client_id",
        settings=mock_settings
    )


def test_migrate_password_invalid_token(
        test_client,
        mock_verify_action_token,
        mock_auth0_client
):
    """
    Test that migrate_password fails when verify_action_token raises an exception.
    """
    # Setup mock to raise 401 (mimicking verify_action_token behavior)
    mock_verify_action_token.side_effect = HTTPException(status_code=401, detail="invalid session_token")

    payload = {
        "session_token": "invalid_token",
        "client_id": "test_client_id"
    }

    response = test_client.post("/me/migration/update-password", json=payload)

    # Assertions
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid session_token"
    mock_auth0_client.trigger_password_change.assert_not_called()


def test_migrate_password_auth0_error(
        test_client,
        mock_verify_action_token,
        mock_auth0_client,
):
    """
    Test that errors from Auth0 client are propagated (if not handled explicitly in endpoint).
    """
    mock_verify_action_token.return_value = {"email": "user@example.com", "sub": "auth0|123"}
    mock_auth0_client.trigger_password_change.side_effect = Exception("Auth0 connection error")

    payload = {
        "session_token": "valid_token",
        "client_id": "test_client_id"
    }

    with pytest.raises(Exception) as excinfo:
        test_client.post("/me/migration/update-password", json=payload)

    assert str(excinfo.value) == "Auth0 connection error"


def test_migrate_password_missing_claims(
        test_client,
        mock_verify_action_token,
        mock_auth0_client
):
    """
    Test that migrate_password raises 400 when sub or email is missing in the payload.
    """
    # Payload missing 'email'
    mock_verify_action_token.return_value = {"sub": "auth0|123"}

    payload = {
        "session_token": "token_missing_email",
        "client_id": "test_client_id"
    }

    response = test_client.post("/me/migration/update-password", json=payload)
    assert response.status_code == 400
    assert "Invalid session token" in response.json()["detail"]
    mock_auth0_client.trigger_password_change.assert_not_called()


def test_finish_migrate_password_success(
    test_client,
    mock_verify_action_token,
    mock_auth0_client,
    mock_settings
):
    """
    Test that finish_migrate_password updates user metadata and redirects correctly.
    """
    user_id = "auth0|migrate-me"
    state = "some_auth0_state"
    mock_verify_action_token.return_value = {"sub": user_id}
    mock_settings.auth0_custom_domain = "https://auth.example.com"

    params = {
        "state": state,
        "session_token": "valid_finish_token"
    }

    # Use follow_redirects=False to inspect the RedirectResponse
    response = test_client.get("/me/migration/password-changed", params=params, follow_redirects=False)
    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert response.headers["location"] == f"https://auth.example.com/continue?state={state}"
    # Verify Auth0 update call
    mock_auth0_client.update_user.assert_called_once()
    call_args = mock_auth0_client.update_user.call_args
    assert call_args.kwargs["user_id"] == user_id
    assert call_args.kwargs["update_data"].app_metadata.user_needs_migration is False


def test_finish_migrate_password_invalid_token(
    test_client,
    mock_verify_action_token,
    mock_auth0_client
):
    """
    Test that finish_migrate_password fails when the token is invalid.
    """
    mock_verify_action_token.side_effect = HTTPException(status_code=401, detail="invalid session_token")

    params = {
        "state": "state",
        "session_token": "expired_token"
    }

    response = test_client.get("/me/migration/password-changed", params=params)

    assert response.status_code == 401
    mock_auth0_client.update_user.assert_not_called()


def test_finish_migrate_password_missing_sub(
    test_client,
    mock_verify_action_token,
    mock_auth0_client
):
    """
    Test that finish_migrate_password raises 400 when sub is missing in the payload.
    """
    # Payload missing 'sub'
    mock_verify_action_token.return_value = {"email": "user@example.com"}

    params = {
        "state": "some_state",
        "session_token": "token_missing_sub"
    }

    response = test_client.get("/me/migration/password-changed", params=params)
    assert response.status_code == 400
    assert "Invalid session token" in response.json()["detail"]
    mock_auth0_client.update_user.assert_not_called()
