from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from schemas import Service
from schemas.biocommons import BiocommonsRegisterData
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


def test_to_biocommons_register_data(valid_registration_data):
    bpa_data = BPARegistrationDataFactory.build()
    bpa_service = Service(
        name="Bioplatforms Australia",
        id="bpa",
        status="approved",
        last_updated=datetime.now(UTC),
        updated_by="system",
    )
    register_data = BiocommonsRegisterData.from_bpa_registration(
        bpa_data, bpa_service=bpa_service
    )
    assert register_data.username == bpa_data.username
    assert register_data.name == bpa_data.fullname
    assert register_data.app_metadata.registration_from == "bpa"


def test_successful_registration(
    test_client_with_email, mock_auth_token, mocker, valid_registration_data,
):
    """Test successful user registration with BPA service"""
    test_client = test_client_with_email
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    mock_email_cls = mocker.patch("routers.bpa_register.EmailService", autospec=True)
    mock_email_cls.return_value.send.return_value = None

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

    mock_email_cls.return_value.send.assert_called_once()

    called_data = mock_post.call_args[1]["json"]
    assert called_data["email"] == valid_registration_data["email"]
    assert called_data["username"] == valid_registration_data["username"]
    assert called_data["name"] == valid_registration_data["fullname"]

    app_metadata = called_data["app_metadata"]
    assert len(app_metadata["services"]) == 1
    bpa_service = app_metadata["services"][0]
    assert bpa_service["name"] == "Bioplatforms Australia Data Portal"
    assert bpa_service["status"] == "pending"
    assert "last_updated" in bpa_service
    assert "updated_by" in bpa_service
    assert bpa_service["updated_by"] == "system"
    assert len(bpa_service["resources"]) == 2

    for resource in bpa_service["resources"]:
        assert "last_updated" in resource
        assert "updated_by" in resource
        assert "initial_request_time" in resource
        assert resource["updated_by"] == "system"

    assert (
        called_data["user_metadata"]["bpa"]["registration_reason"]
        == valid_registration_data["reason"]
    )

def test_service_and_resources_have_updated_by_system():
    service = Service(
        name="Test Service",
        id="svc1",
        status="pending",
        last_updated=datetime.now(UTC),
        updated_by="system",
        resources=[
            {
                "id": "res1",
                "name": "Test Resource",
                "status": "pending",
                "last_updated": datetime.now(UTC),
                "updated_by": "system",
                "initial_request_time": datetime.now(UTC),
            }
        ],
    )
    assert service.updated_by == "system"
    assert service.resources[0].updated_by == "system"
    assert hasattr(service.resources[0], "initial_request_time")
    assert isinstance(service.resources[0].initial_request_time, datetime)

def test_registration_duplicate_user(
    test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test registration with duplicate user"""
    mock_response = MagicMock()
    mock_response.status_code = 409
    mock_response.json.return_value = {"message": "User already exists"}

    mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=valid_registration_data)

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

    response = test_client.post("/bpa/register", json=valid_registration_data)

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


def test_registration_email_format(test_client, valid_registration_data):
    """Test email format validation"""
    data = valid_registration_data.copy()
    data["email"] = "invalid-email"

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]


def test_all_organizations_selected(
    test_client_with_email,
    mock_auth_token,
    mock_settings,
    mocker,
    valid_registration_data,
):
    """Test registration with all organizations selected"""
    test_client = test_client_with_email
    data = valid_registration_data.copy()
    data["organizations"] = {k: True for k in mock_settings.organizations.keys()}

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}
    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    email_service_cls = mocker.patch("routers.bpa_register.EmailService", autospec=True)
    email_service_cls.return_value.send.return_value = True

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_post.call_args[1]["json"]
    bpa_service = called_data["app_metadata"]["services"][0]
    assert len(bpa_service["resources"]) == len(mock_settings.organizations)

    email_service_cls.return_value.send.assert_called_once()
