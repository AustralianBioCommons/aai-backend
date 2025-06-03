from unittest.mock import MagicMock

import pytest

from tests.datagen import AccessTokenPayloadFactory, BPARegistrationDataFactory


@pytest.fixture
def valid_registration_data():
    """Fixture that provides valid BPA registration data."""
    return BPARegistrationDataFactory.build(
        username="testuser",
        fullname="Test User",
        email="test@example.com",
        reason="Need access to BPA resources",
        password="SecurePass123!",
        organizations=BPARegistrationDataFactory.get_default_organizations(),
    ).model_dump()


@pytest.fixture
def mock_auth_token(mocker):
    token = AccessTokenPayloadFactory.build(
        sub="auth0|123456789",
        biocommons_roles=["acdc/indexd_admin"],
    )
    mocker.patch("auth.validator.verify_jwt", return_value=token)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    mocker.patch("routers.bpa_register.get_management_token", return_value="mock_token")
    return token


def test_successful_registration(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test successful user registration with BPA service"""
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

    called_data = mock_post.call_args[1]["json"]
    assert called_data["email"] == valid_registration_data["email"]
    assert called_data["username"] == valid_registration_data["username"]
    assert called_data["name"] == valid_registration_data["fullname"]

    app_metadata = called_data["app_metadata"]
    assert len(app_metadata["services"]) == 1
    bpa_service = app_metadata["services"][0]
    assert bpa_service["name"] == "BPA"
    assert bpa_service["status"] == "pending"
    assert len(bpa_service["resources"]) == 2

    user_metadata = called_data["user_metadata"]
    assert "bpa" in user_metadata
    assert user_metadata["bpa"]["registration_reason"] == valid_registration_data["reason"]
    assert user_metadata["bpa"]["username"] == valid_registration_data["username"]


def test_registration_duplicate_user(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with duplicate user"""
    mock_response = MagicMock()
    mock_response.status_code = 409
    mock_response.json.return_value = {"message": "User already exists"}

    mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post(
        "/bpa/register", json=valid_registration_data
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Registration failed: User already exists"


def test_registration_auth0_error(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with Auth0 API error"""
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"message": "Invalid request"}

    mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post(
        "/bpa/register", json=valid_registration_data
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Registration failed: Invalid request"


def test_registration_with_invalid_organization(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with invalid organization ID"""
    data = valid_registration_data.copy()
    data["organizations"] = {"invalid-org-id": True}

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 400
    assert "Invalid organization ID" in response.json()["detail"]


def test_registration_request_validation(test_client):
    """Test request validation"""
    invalid_data = {
        "username": "testuser",
        "email": "invalid-email",
        "organizations": {},
    }

    response = test_client.post("/bpa/register", json=invalid_data)

    assert response.status_code == 422


def test_no_selected_organizations(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with no organizations selected"""
    data = valid_registration_data.copy()
    data["organizations"] = {
        "bpa-bioinformatics-workshop": False,
        "cipps": False,
        "ausarg": False,
    }

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == 0


def test_empty_organizations_dict(
        test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with empty organizations dictionary"""
    data = valid_registration_data.copy()
    data["organizations"] = {}

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == 0


def test_registration_email_format(
        test_client, valid_registration_data
):
    """Test email format validation"""
    data = valid_registration_data.copy()
    data["email"] = "invalid-email"

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]


def test_all_organizations_selected(
        test_client,
    mock_auth_token,
    mock_settings,
    mocker,
    valid_registration_data,
):
    """Test registration with all organizations selected"""
    data = valid_registration_data.copy()
    data["organizations"] = {k: True for k in mock_settings.organizations.keys()}

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == len(mock_settings.organizations)
