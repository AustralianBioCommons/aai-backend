from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import HTTPException
from freezegun import freeze_time
from httpx import HTTPStatusError, Request, Response
from jose import jwt
from pydantic import ValidationError
from sqlmodel import select

import register
from db.models import BiocommonsUser, PlatformEnum, PlatformMembership
from db.types import ApprovalStatusEnum, AuditActionEnum
from register.tokens import verify_registration_token
from schemas.biocommons import BiocommonsRegisterData
from schemas.galaxy import GalaxyRegistrationData
from tests.datagen import (
    Auth0UserDataFactory,
    GalaxyRegistrationDataFactory,
)


def test_galaxy_registration_data_password_match():
    with pytest.raises(ValidationError, match="Passwords do not match"):
        GalaxyRegistrationData(email="user@example.com",
                               password="SecurePassword123!",
                               confirmPassword="OtherPassword123!",
                               username="valid_username")


def test_get_registration_token(test_client, mock_settings):
    """
    Test get-registration-token endpoint returns a valid JWT token.
    """
    from register.tokens import ALGORITHM
    response = test_client.get("/galaxy/register/get-registration-token")
    assert response.status_code == 200
    jwt.decode(response.json()["token"], mock_settings.jwt_secret_key,
               algorithms=ALGORITHM)


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
        password="SecurePassword123!",
        confirmPassword="SecurePassword123!",
        username="valid_username"
    )

    auth0_data = BiocommonsRegisterData.from_galaxy_registration(data)

    assert auth0_data.email == "user@example.com"
    assert auth0_data.password == "SecurePassword123!"
    assert auth0_data.connection == "Username-Password-Authentication"
    assert not auth0_data.email_verified
    assert auth0_data.username == "valid_username"
    assert auth0_data.app_metadata.registration_from == "galaxy"


def test_to_biocommons_register_data_empty_fields():
    """
    Test 'username' and 'name' are left out of dumped data,
    since we don't use these in Galaxy registration,
    and the Auth0 API doesn't like them being included
    """
    data = GalaxyRegistrationData(
        email="user@example.com",
        password="SecurePassword123!",
        confirmPassword="SecurePassword123!",
        username="valid_username"
    )

    auth0_data = BiocommonsRegisterData.from_galaxy_registration(data)
    dumped = auth0_data.model_dump(mode="json", exclude_none=True)
    assert "user_metadata" not in dumped
    assert "name" not in dumped


@freeze_time("2025-01-01")
def test_register(mock_settings, test_client, mock_auth0_client, test_db_session):
    """
    Try to test our register endpoint. Since we don't want to call
    an actual Auth0 API, test that:

    * The post request is made with the correct data
    * The response from our endpoint looks like we expect
    * A user is created in the DB
    * A PlatformMembership record is created for Galaxy
    """
    auth0_user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = auth0_user_data
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    resp = test_client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200
    assert resp.json()["message"] == "User registered successfully"
    assert resp.json()["user"] == auth0_user_data.model_dump(mode="json")
    # Check data used to register is correct
    register_data = BiocommonsRegisterData.from_galaxy_registration(user_data)
    mock_auth0_client.create_user.assert_called_once_with(register_data)
    # Check user is created in the database with membership and history
    db_user = test_db_session.get(BiocommonsUser, auth0_user_data.user_id)
    assert db_user is not None
    assert db_user.id == auth0_user_data.user_id
    galaxy_membership = test_db_session.exec(select(PlatformMembership).where(
        PlatformMembership.user_id == db_user.id,
        PlatformMembership.platform_id == PlatformEnum.GALAXY.value
    )).one()
    assert galaxy_membership.approval_status == ApprovalStatusEnum.APPROVED
    history_entries = PlatformMembership.get_history_by_user_id_and_platform_id(
        db_user.id,
        PlatformEnum.GALAXY,
        test_db_session,
    )
    assert len(history_entries) == 1
    history_entry = history_entries[0]
    assert history_entry.approval_status == ApprovalStatusEnum.APPROVED
    assert history_entry.action == AuditActionEnum.CREATED


@pytest.mark.respx(base_url="https://mock-domain")
def test_register_json_types(mock_auth0_client, mock_settings, test_client, mock_galaxy_client, test_db_session):
    """
    Test how we handle datetimes in the response data: if we don't
    use model_dump(mode="json") when providing json data, we can get errors
    """
    # Generate user data to be returned in the response
    # (doesn't have to match the registration data for now)
    auth0_user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = auth0_user_data
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    mock_galaxy_client.username_exists.return_value = False
    resp = test_client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200


def test_register_requires_token(test_client):
    user_data = GalaxyRegistrationDataFactory.build()
    resp = test_client.post("/galaxy/register", json=user_data.model_dump())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Missing registration token"


def test_register_duplicate_auth0_username(test_client, mock_galaxy_client, mock_auth0_client):
    """Test registration with duplicate Auth0 username"""
    user_data = GalaxyRegistrationDataFactory.build()
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="Registration failed: User already exists"),
    )
    mock_galaxy_client.username_exists.return_value = False
    mock_auth0_client.create_user.side_effect = error
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    response = test_client.post("/galaxy/register", json=user_data.model_dump(mode="json"), headers=headers)

    assert response.status_code == 400
    assert response.json()["message"] == "Username or email already in use"


def test_register_generic_auth0_error(test_client, mock_galaxy_client, mock_auth0_client):
    """Test registration error when Auth0 returns a generic error (that we don't have special handling for)"""
    user_data = GalaxyRegistrationDataFactory.build()
    error = httpx.HTTPStatusError(
        "Generic error",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(400, text="generic error"),
    )
    mock_galaxy_client.username_exists.return_value = False
    mock_auth0_client.create_user.side_effect = error
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    response = test_client.post("/galaxy/register", json=user_data.model_dump(mode="json"), headers=headers)

    assert response.status_code == 400
    assert response.json()["message"] == "Auth0 error: generic error"


def test_register_invalid_email(test_client):
    user_data = GalaxyRegistrationDataFactory.build()
    user_data.email = "invalid-email"
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    response = test_client.post("/galaxy/register", json=user_data.model_dump(mode="json"), headers=headers)

    assert response.status_code == 400
    assert response.json()["message"] == "Invalid data submitted"
    field_errors = response.json()["field_errors"]
    assert field_errors[0]["field"] == "email"


def test_register_galaxy_error(test_client, mock_galaxy_client, mock_auth0_client, test_db_session):
    """
    Test registration can continue if there's an error with the Galaxy API - don't
    want this to block registration
    """
    # Generate user data to be returned in the response
    # (doesn't have to match the registration data for now)
    auth0_user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = auth0_user_data
    user_data = GalaxyRegistrationDataFactory.build()
    token_resp = test_client.get("/galaxy/register/get-registration-token")
    headers = {"registration-token": token_resp.json()["token"]}
    mock_galaxy_client.username_exists.side_effect = HTTPStatusError(
        message="Galaxy error",
        request=Request(method="get", url="http://galaxy.example.com"),
        response=Response(status_code=500)
    )
    resp = test_client.post("/galaxy/register", json=user_data.model_dump(), headers=headers)
    assert resp.status_code == 200
