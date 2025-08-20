from datetime import UTC, datetime

import httpx
import pytest
from sqlmodel import select

from db.models import (
    BiocommonsUser,
    PlatformEnum,
    PlatformMembership,
    PlatformMembershipHistory,
)
from schemas import Service
from schemas.biocommons import BiocommonsRegisterData
from tests.datagen import (
    Auth0UserDataFactory,
    BPARegistrationDataFactory,
    random_auth0_id,
)


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
    test_client_with_email, mocker, valid_registration_data,
        mock_auth0_client, test_db_session
):
    """Test successful user registration with BPA service"""
    test_client = test_client_with_email
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(user_id=user_id)
    mock_email_cls = mocker.patch("routers.bpa_register.EmailService", autospec=True)
    mock_email_cls.return_value.send.return_value = None

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

    mock_email_cls.return_value.send.assert_called_once()
    # Check user is created in the database
    db_user = test_db_session.get(BiocommonsUser, user_id)
    assert db_user is not None
    assert db_user.id == user_id
    # Check platform membership and history is created
    bpa_membership = test_db_session.exec(select(PlatformMembership).where(
        PlatformMembership.user_id == db_user.id,
        PlatformMembership.platform_id == PlatformEnum.BPA_DATA_PORTAL.value
    )).one()
    assert bpa_membership.approval_status == "approved"
    membership_history = test_db_session.exec(select(PlatformMembershipHistory).where(
        PlatformMembershipHistory.user_id == db_user.id,
        PlatformMembershipHistory.platform_id == PlatformEnum.BPA_DATA_PORTAL.value
    )).one()
    assert membership_history.approval_status == "approved"

    called_data = mock_auth0_client.create_user.call_args[0][0]
    assert called_data.email == valid_registration_data["email"]
    assert called_data.username == valid_registration_data["username"]
    assert called_data.name == valid_registration_data["fullname"]
    assert not called_data.email_verified

    app_metadata = called_data.app_metadata
    assert len(app_metadata.services) == 1
    bpa_service = app_metadata.services[0]
    assert bpa_service.name == "Bioplatforms Australia Data Portal"
    assert bpa_service.status == "pending"
    assert bpa_service.last_updated is not None
    assert bpa_service.updated_by == "system"
    assert len(bpa_service.resources) == 2

    for resource in bpa_service.resources:
        assert resource.last_updated is not None
        assert resource.initial_request_time is not None
        assert resource.updated_by == "system"

    assert (
        called_data.user_metadata.bpa.registration_reason
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
    test_client, valid_registration_data, mock_auth0_client
):
    """Test registration with duplicate user"""
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="Registration failed: User already exists"),
    )
    mock_auth0_client.create_user.side_effect = error

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Username or email already in use"


def test_registration_auth0_error(
    test_client, mock_auth0_client, valid_registration_data
):
    """Test registration with Auth0 API error"""
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(400, text="Something went wrong"),
    )
    mock_auth0_client.create_user.side_effect = error

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Auth0 error: Something went wrong"


def test_registration_with_invalid_organization(
    test_client, valid_registration_data
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

    assert response.status_code == 400
    error_data = response.json()
    assert error_data["message"] == "Invalid data submitted"
    assert any(error["field"] == "email" for error in error_data["field_errors"])


def test_no_selected_organizations(
    test_client, test_db_session, mock_auth0_client, valid_registration_data
):
    """Test registration with no organizations selected"""
    data = valid_registration_data.copy()
    data["organizations"] = {
        "bpa-bioinformatics-workshop": False,
        "cipps": False,
        "ausarg": False,
    }
    user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = user_data

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    # Check user data sent to Auth0
    called_data = mock_auth0_client.create_user.call_args[0][0]
    bpa_service = called_data.app_metadata.services[0]
    assert len(bpa_service.resources) == 0


def test_empty_organizations_dict(
    test_client, test_db_session, mock_auth0_client, valid_registration_data
):
    """Test registration with empty organizations dictionary"""
    data = valid_registration_data.copy()
    data["organizations"] = {}
    user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = user_data

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_auth0_client.create_user.call_args[0][0]
    bpa_service = called_data.app_metadata.services[0]
    assert len(bpa_service.resources) == 0


def test_registration_email_format(test_client, valid_registration_data):
    """Test email format validation"""
    data = valid_registration_data.copy()
    data["email"] = "invalid-email"

    response = test_client.post("/bpa/register", json=data)

    assert response.status_code == 400
    details = response.json()
    errors = details["field_errors"]
    assert "email" in [error["field"] for error in errors]


def test_all_organizations_selected(
    test_client_with_email,
    test_db_session,
    mock_settings,
    mocker,
    mock_auth0_client,
    valid_registration_data,
):
    """Test registration with all organizations selected"""
    data = valid_registration_data.copy()
    data["organizations"] = {k: True for k in mock_settings.organizations.keys()}

    user_data = Auth0UserDataFactory.build()
    mock_auth0_client.create_user.return_value = user_data

    email_service_cls = mocker.patch("routers.bpa_register.EmailService", autospec=True)
    email_service_cls.return_value.send.return_value = True

    response = test_client_with_email.post("/bpa/register", json=data)

    assert response.status_code == 200
    called_data = mock_auth0_client.create_user.call_args[0][0]
    bpa_service = called_data.app_metadata.services[0]
    assert len(bpa_service.resources) == len(mock_settings.organizations)

    email_service_cls.return_value.send.assert_called_once()
