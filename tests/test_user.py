import pytest

from schemas.biocommons import BiocommonsAppMetadata
from tests.datagen import AccessTokenPayloadFactory, Auth0UserDataFactory


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
