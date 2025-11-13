import pytest
from unittest.mock import AsyncMock
import respx
from fastapi import HTTPException
from httpx import Response

from db.types import ApprovalStatusEnum, PlatformEnum
from routers.user import get_user_data, update_user_metadata
from schemas.biocommons import Auth0Identity, BiocommonsAppMetadata
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
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
    assert data[0] == valid_platform.model_dump(mode="json")
    returned_ids = [p["id"] for p in data]
    assert invalid_platform.id not in returned_ids


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


def test_change_password_success(test_client, test_db_session, mocker):
    """Password change succeeds when Auth0 accepts the new password."""
    user = BiocommonsUserFactory.create_sync()
    test_db_session.flush()
    _mock_password_change_user(mocker, user)

    with respx.mock:
        respx.post("https://mock-domain/oauth/token").mock(
            return_value=Response(200, json={"access_token": "access", "token_type": "Bearer"})
        )
        respx.patch(f"https://mock-domain/api/v2/users/{user.id}").mock(
            return_value=Response(200, json={"user_id": user.id})
        )

        response = test_client.post(
            "/me/password",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "CurrentPass123!",
                "new_password": "NewPass123!",
            },
        )

    assert response.status_code == 204


def test_change_password_invalid_current_password(test_client, test_db_session, mocker):
    """Password change fails when the current password is wrong."""
    user = BiocommonsUserFactory.create_sync()
    test_db_session.flush()
    _mock_password_change_user(mocker, user)

    with respx.mock:
        respx.post("https://mock-domain/oauth/token").mock(
            return_value=Response(403, json={"error": "invalid_grant"})
        )

        response = test_client.post(
            "/me/password",
            headers={"Authorization": "Bearer valid_token"},
            json={
                "current_password": "WrongPass123!",
                "new_password": "AnotherPass123!",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Current password is incorrect."


def test_change_password_missing_configuration(test_client, mock_settings, mocker):
    """Service returns 503 when password change is not configured."""
    mock_settings.auth0_management_id = None
    mock_settings.auth0_management_secret = None
    user = BiocommonsUserFactory.create_sync()
    _act_as_user(mocker, user)

    response = test_client.post(
        "/me/password",
        headers={"Authorization": "Bearer valid_token"},
        json={
            "current_password": "CurrentPass123!",
            "new_password": "BrandNew123!",
        },
    )

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_change_password_disallows_external_identity(test_client, mocker):
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
        "/me/password",
        headers={"Authorization": "Bearer valid_token"},
        json={
            "current_password": "CurrentPass123!",
            "new_password": "BrandNew123!",
        },
    )

    assert response.status_code == 400
    assert "not supported" in response.json()["detail"]
