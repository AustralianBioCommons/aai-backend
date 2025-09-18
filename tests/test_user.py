import pytest

from db.types import ApprovalStatusEnum, PlatformEnum
from schemas.biocommons import BiocommonsAppMetadata
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
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


# --- Authentication Tests (GET) ---
@pytest.mark.parametrize(
    "endpoint",
    [
        "/me/is-admin",
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


def test_check_is_admin_with_admin_role(test_client, mock_settings, mocker):
    """Test that admin check returns True for users with admin role"""
    from tests.datagen import SessionUserFactory

    admin_token = AccessTokenPayloadFactory.build(
        biocommons_roles=["Admin"]
    )
    admin_user = SessionUserFactory.build(access_token=admin_token)

    mocker.patch("auth.validator.verify_jwt", return_value=admin_token)
    mocker.patch("auth.validator.get_current_user", return_value=admin_user)

    response = test_client.get(
        "/me/is-admin",
        headers={"Authorization": "Bearer valid_token"}
    )

    assert response.status_code == 200
    assert response.json() == {"is_admin": True}


def test_check_is_admin_with_non_admin_role(test_client, mock_settings, mocker):
    """Test that admin check returns False for users without admin role"""
    from tests.datagen import SessionUserFactory

    user_token = AccessTokenPayloadFactory.build(
        biocommons_roles=["User"]
    )
    user = SessionUserFactory.build(access_token=user_token)

    mocker.patch("auth.validator.verify_jwt", return_value=user_token)
    mocker.patch("auth.validator.get_current_user", return_value=user)

    response = test_client.get(
        "/me/is-admin",
        headers={"Authorization": "Bearer valid_token"}
    )

    assert response.status_code == 200
    assert response.json() == {"is_admin": False}


def test_check_is_admin_without_authentication(test_client):
    """Test that admin check requires authentication"""
    response = test_client.get("/me/is-admin")
    assert response.status_code == 401


def _act_as_user(mocker, db_user):
    """
    Set up mocks so that the test client authenticates as the given user
    """
    access_token = AccessTokenPayloadFactory.build(sub=db_user.id)
    auth0_user = SessionUserFactory.build(access_token=access_token)
    mocker.patch("auth.validator.verify_jwt", return_value=access_token)
    mocker.patch("auth.validator.get_current_user", return_value=auth0_user)
    return auth0_user


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
