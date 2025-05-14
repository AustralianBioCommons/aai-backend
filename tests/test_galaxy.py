from unittest.mock import MagicMock

import pytest
from jose import jwt

from schemas.galaxy import GalaxyRegistrationData
from tests.datagen import AccessTokenPayloadFactory, GalaxyRegistrationDataFactory


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


def test_get_registration_token(client_with_settings_override, mock_settings):
    """
    Test get-registration-token endpoint returns a valid JWT token.
    """
    response = client_with_settings_override.get("/galaxy/get-registration-token")
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


def test_register(mocker, mock_auth_token, mock_settings, client_with_settings_override):
    """
    Try to test our register endpoint. Since we don't want to call
    an actual Auth0 API, test that:

    * The post request is made with the correct data
    * The response from our endpoint looks like we expect
    """
    mock_resp = MagicMock()
    # Dummy user data: doesn't currently resemble response from Auth0
    mock_resp.json.return_value = {"user_id": "abc123"}
    mock_resp.status_code = 201
    mock_post = mocker.patch("httpx.post", return_value=mock_resp)
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = client_with_settings_override.get("/galaxy/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    resp = client_with_settings_override.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200
    assert resp.json()["message"] == "User registered successfully"
    assert resp.json()["user"] == {"user_id": "abc123"}

    url = f"https://{mock_settings.auth0_domain}/api/v2/users"
    headers = {"Authorization": f"Bearer mock_token"}
    mock_post.assert_called_once_with(
        url,
        json=user_data.to_auth0_create_user_data().model_dump(),
        headers=headers
    )

