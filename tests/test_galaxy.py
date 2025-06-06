from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from freezegun import freeze_time
from httpx import Response
from jose import jwt
from pydantic import ValidationError

import register
from register.tokens import verify_registration_token
from schemas.biocommons import BiocommonsRegisterData
from schemas.galaxy import GalaxyRegistrationData
from tests.datagen import (
    AccessTokenPayloadFactory,
    BiocommonsAuth0UserFactory,
    GalaxyRegistrationDataFactory,
)


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


def test_to_biocommons_register_data():
    """
    Test we can convert GalaxyRegistrationData to the data expected by Auth0
    """
    data = GalaxyRegistrationData(
        email="user@example.com",
        password="securepassword",
        password_confirmation="securepassword",
        public_name="valid_username"
    )

    auth0_data = BiocommonsRegisterData.from_galaxy_registration(data)

    assert auth0_data.email == "user@example.com"
    assert auth0_data.password == "securepassword"
    assert auth0_data.connection == "Username-Password-Authentication"
    assert not auth0_data.email_verified
    assert auth0_data.user_metadata.galaxy_username == "valid_username"


def test_to_biocommons_register_data_empty_fields():
    """
    Test 'username' and 'name' are left out of dumped data,
    since we don't use these in Galaxy registration,
    and the Auth0 API doesn't like them being included
    """
    data = GalaxyRegistrationData(
        email="user@example.com",
        password="securepassword",
        password_confirmation="securepassword",
        public_name="valid_username"
    )

    auth0_data = BiocommonsRegisterData.from_galaxy_registration(data)
    dumped = auth0_data.model_dump(mode="json", exclude_none=True)
    assert "username" not in dumped
    assert "name" not in dumped


@freeze_time("2025-01-01")
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
    register_data = BiocommonsRegisterData.from_galaxy_registration(user_data)
    mock_post.assert_called_once_with(
        url,
        json=register_data.model_dump(mode="json", exclude_none=True),
        headers=headers
    )


@pytest.mark.respx(base_url="https://mock-domain")
def test_register_json_types(respx_mock, mock_auth_token, mock_settings, test_client):
    """
    Test how we handle datetimes in the response data: if we don't
    use model_dump(mode="json") when providing json data, we can get errors
    """
    url = f"https://{mock_settings.auth0_domain}/api/v2/users"
    # Generate user data to be returned in the response
    # (doesn't have to match the registration data for now)
    user = BiocommonsAuth0UserFactory.build(created_at=datetime.now(UTC))
    respx_mock.post(url).mock(return_value=Response(
        status_code=201,
        json=user.model_dump(mode="json"))
    )
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = test_client.get("/galaxy/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    resp = test_client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200


def test_register_requires_token(test_client):
    user_data = GalaxyRegistrationDataFactory.build()
    resp = test_client.post("/galaxy/register", json=user_data.model_dump())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Missing registration token"
