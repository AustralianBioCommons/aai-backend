import pytest
import respx
from fastapi import HTTPException
from httpx import Response

from db.types import ApprovalStatusEnum, PlatformEnum
from routers.user import get_user_data, update_user_metadata
from schemas.biocommons import BiocommonsAppMetadata
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


def test_get_profile_returns_user_profile(test_client, test_db_session, mocker, mock_auth0_client, persistent_factories):
    """Ensure the profile endpoint combines Auth0 data with DB memberships."""
    auth0_data = Auth0UserDataFactory.build(
        user_id="auth0|profile-user",
        email="profile.user@example.com",
        username="profile_user",
        name="Profile User",
    )
    db_user = BiocommonsUserFactory.create_sync(
        id=auth0_data.user_id,
        email=auth0_data.email,
        username=auth0_data.username,
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
    bpa_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/bpa_galaxy",
        name="Bioplatforms Australia & Galaxy Australia",
        short_name="BPA-GA",
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
        group=bpa_group,
        group_id=bpa_group.group_id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    test_db_session.flush()
    test_db_session.refresh(db_user)

    mock_auth0_client.get_user.return_value = auth0_data

    _act_as_user(mocker, db_user)

    response = test_client.get("/me/profile", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
    data = response.json()

    assert data["user_id"] == auth0_data.user_id
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
    assert group_map[bpa_group.group_id]["group_name"] == bpa_group.name
    assert group_map[bpa_group.group_id]["group_short_name"] == bpa_group.short_name
    assert group_map[bpa_group.group_id]["approval_status"] == ApprovalStatusEnum.PENDING.value

    mock_auth0_client.get_user.assert_called_once_with(db_user.id)


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
