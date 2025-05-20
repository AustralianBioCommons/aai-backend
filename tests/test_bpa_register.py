from unittest.mock import MagicMock

import pytest

from tests.datagen import AccessTokenPayloadFactory

VALID_REGISTRATION_DATA = {
    "username": "testuser",
    "fullname": "Test User",
    "email": "test@example.com",
    "reason": "Need access to BPA resources",
    "password": "SecurePass123!",
    "organizations": {
        "bpa-bioinformatics-workshop": True,
        "cipps": False,
        "ausarg": True,
    },
}


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
    client_with_settings_override, mock_auth_token, mocker
):
    """Test successful user registration with BPA service"""
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post(
        "/bpa/register", json=VALID_REGISTRATION_DATA
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

    called_data = mock_post.call_args[1]["json"]
    assert called_data["email"] == VALID_REGISTRATION_DATA["email"]
    assert called_data["username"] == VALID_REGISTRATION_DATA["username"]
    assert called_data["name"] == VALID_REGISTRATION_DATA["fullname"]

    app_metadata = called_data["app_metadata"]
    assert len(app_metadata["services"]) == 1
    bpa_service = app_metadata["services"][0]
    assert bpa_service["name"] == "BPA"
    assert bpa_service["status"] == "pending"
    assert len(bpa_service["resources"]) == 2

    assert (
        called_data["user_metadata"]["bpa"]["registration_reason"]
        == VALID_REGISTRATION_DATA["reason"]
    )


def test_registration_duplicate_user(
    client_with_settings_override, mock_auth_token, mocker
):
    """Test registration with duplicate user"""
    mock_response = MagicMock()
    mock_response.status_code = 409
    mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post(
        "/bpa/register", json=VALID_REGISTRATION_DATA
    )

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_registration_auth0_error(
    client_with_settings_override, mock_auth_token, mocker
):
    """Test registration with Auth0 API error"""
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Invalid request"
    mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post(
        "/bpa/register", json=VALID_REGISTRATION_DATA
    )

    assert response.status_code == 400
    assert "Failed to create user" in response.json()["detail"]


def test_registration_with_invalid_organization(
    client_with_settings_override, mock_auth_token, mocker
):
    """Test registration with invalid organization ID"""
    data = VALID_REGISTRATION_DATA.copy()
    data["organizations"] = {"invalid-org-id": True}

    response = client_with_settings_override.post("/bpa/register", json=data)

    assert response.status_code == 400
    assert "Invalid organization ID" in response.json()["detail"]


def test_registration_request_validation(client_with_settings_override):
    """Test request validation"""
    invalid_data = {
        "username": "testuser",
        "email": "invalid-email",
        "organizations": {},
    }

    response = client_with_settings_override.post("/bpa/register", json=invalid_data)

    assert response.status_code == 422


def test_no_selected_organizations(
    client_with_settings_override, mock_auth_token, mocker
):
    """Test registration with no organizations selected"""
    data = VALID_REGISTRATION_DATA.copy()
    data["organizations"] = {
        "bpa-bioinformatics-workshop": False,
        "cipps": False,
        "ausarg": False,
    }

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == 0


def test_empty_organizations_dict(
    client_with_settings_override, mock_auth_token, mocker
):
    """Test registration with empty organizations dictionary"""
    data = VALID_REGISTRATION_DATA.copy()
    data["organizations"] = {}

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == 0


def test_registration_email_format(client_with_settings_override):
    """Test email format validation"""
    data = VALID_REGISTRATION_DATA.copy()
    data["email"] = "invalid-email"

    response = client_with_settings_override.post("/bpa/register", json=data)

    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]


def test_all_organizations_selected(
    client_with_settings_override, mock_auth_token, mock_settings, mocker
):
    """Test registration with all organizations selected"""
    data = VALID_REGISTRATION_DATA.copy()
    data["organizations"] = {k: True for k in mock_settings.organizations.keys()}

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = client_with_settings_override.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == len(mock_settings.organizations)
