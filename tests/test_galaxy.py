from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from jose import jwt
from pydantic import ValidationError

import register
from register.tokens import verify_registration_token
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


def test_galaxy_registration_data_password_match():
    with pytest.raises(ValidationError, match="Passwords do not match"):
        GalaxyRegistrationData(email="user@example.com",
                               password="securepassword",
                               password_confirmation="insecurepassword",
                               public_name="valid_username")


def test_get_registration_token(test_client, mock_settings):
    """
    Test get-registration-token endpoint returns a valid JWT token.
    """
    response = test_client.get("/galaxy/get-registration-token")
    assert response.status_code == 200
    jwt.decode(response.json()["token"], mock_settings.jwt_secret_key,
               algorithms=mock_settings.auth0_algorithms)


def test_registration_token_invalid_purpose(mock_settings):
    """
    Test registration token is invalid if purpose is not "register"
    """
    expire = datetime.now(UTC) + timedelta(minutes=5)
    payload = {
        "purpose": "evil",
        "exp": expire,
        "iat": datetime.now(UTC)
    }
    token = jwt.encode(payload, key=mock_settings.jwt_secret_key, algorithm=register.tokens.ALGORITHM)
    with pytest.raises(HTTPException, match="Invalid or expired token"):
        verify_registration_token(token, mock_settings)


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


def test_register(mocker, mock_auth_token, mock_settings, test_client):
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
    token_resp = test_client.get("/galaxy/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    resp = test_client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200
    assert resp.json()["message"] == "User registered successfully"
    assert resp.json()["user"] == {"user_id": "abc123"}

    url = f"https://{mock_settings.auth0_domain}/api/v2/users"
    headers = {"Authorization": "Bearer mock_token"}
    mock_post.assert_called_once_with(
        url,
        json=user_data.to_auth0_create_user_data().model_dump(),
        headers=headers
    )


def test_register_requires_token(test_client):
    user_data = GalaxyRegistrationDataFactory.build()
    resp = test_client.post("/galaxy/register", json=user_data.model_dump())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Missing registration token"
