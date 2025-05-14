from contextlib import ExitStack
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from auth.config import Settings
from main import app
from schemas.galaxy import GalaxyRegistrationData, Auth0CreateUserData, Auth0UserMetadata
from tests.datagen import AccessTokenPayloadFactory, GalaxyRegistrationDataFactory

client = TestClient(app)


@pytest.fixture
def mock_settings():
    """Fixture that returns mocked Settings object."""
    return Settings(
        auth0_domain="mock-domain",
        auth0_management_id="mock-id",
        auth0_management_secret="mock-secret",
        auth0_audience="mock-audience",
        jwt_secret_key="mock-secret-key",
        auth0_algorithms=["HS256"]
    )


@pytest.fixture(autouse=True)
def patch_get_settings(mock_settings):
    """Globally patch get_settings() and override in FastAPI dependency injection."""
    import auth.config  # where get_settings is defined

    auth.config.get_settings.cache_clear()

    # Need to use ExitStack to patch multiple targets
    patch_targets = [
        "register.tokens.get_settings",
        "auth.config.get_settings",
        "auth.management.get_settings",
    ]
    with ExitStack() as stack:
        # Override FastAPI dependency
        app.dependency_overrides[auth.config.get_settings] = lambda: mock_settings
        for path in patch_targets:
            stack.enter_context(patch(path, return_value=mock_settings))
        yield
        app.dependency_overrides.clear()


@pytest.fixture
def mock_auth_token(mocker):
    """Fixture to mock authentication token"""
    token = AccessTokenPayloadFactory.build(
        sub="auth0|123456789",
        biocommons_roles=["acdc/indexd_admin"],
    )
    mocker.patch("auth.validator.verify_jwt", return_value=token)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    mocker.patch("routers.galaxy_register.get_management_token", return_value="mock_token")
    return token


@pytest.fixture
def mock_verify_token(mocker):
    mocker.patch("routers.galaxy_register.verify_registration_token", return_value=None)


def test_get_registration_token(mock_settings):
    """
    Test get-registration-token endpoint returns a valid JWT token.
    """
    response = client.get("/galaxy/get-registration-token")
    assert response.status_code == 200
    decoded = jwt.decode(response.json()["token"], mock_settings.jwt_secret_key,
                         algorithms=mock_settings.auth0_algorithms)


def test_to_auth0_create_user_data_valid():
    """
    Test we can convert GalaxyRegistrationData to the data expected by Auth0
    """
    data = GalaxyRegistrationData(
        email="user@example.com",
        password="securepassword",
        password_confirmation="securepassword",
        public_name="valid_username"
    )

    auth0_data = data.to_auth0_create_user_data()

    assert auth0_data.email == "user@example.com"
    assert auth0_data.password == "securepassword"
    assert auth0_data.connection == "Username-Password-Authentication"
    assert not auth0_data.email_verified
    assert auth0_data.user_metadata.galaxy_username == "valid_username"


def test_register(mocker, mock_auth_token, mock_settings):
    """
    Try to test our register endpoint. Since we don't want to call
    an actual Auth0 API, test that:

    * The post request is made with the correct data
    * The response from our endpoint looks like we expect
    """
    mock_resp = MagicMock()
    # Dummy user data: doesn't currently resemble response from Auth0
    mock_resp.json.return_value = {"user_id": "abc123"}
    mock_post = mocker.patch("httpx.post", return_value=mock_resp)
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = client.get("/galaxy/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    resp = client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200
    assert resp.json()["message"] == "User registered successfully"
    assert resp.json()["user"] == {"user_id": "abc123"}

    url = f"https://{mock_settings.auth0_domain}/api/v2/users/"
    headers = {"Authorization": f"Bearer mock_token"}
    mock_post.assert_called_once_with(
        url,
        json=user_data.to_auth0_create_user_data().model_dump(),
        headers=headers
    )

