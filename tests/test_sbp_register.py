
import httpx
import pytest
from sqlmodel import select

from db.models import (
    BiocommonsUser,
    PlatformEnum,
    PlatformMembership,
    PlatformMembershipHistory,
)
from schemas.biocommons import BiocommonsRegisterData
from tests.datagen import (
    Auth0UserDataFactory,
    SBPRegistrationDataFactory,
    random_auth0_id,
)


@pytest.fixture
def valid_registration_data():
    """Fixture that provides valid SBP registration data."""
    return SBPRegistrationDataFactory.build(
        username="testuser",
        first_name="Test",
        last_name="User",
        email="test@example.com",
        reason="Need access to SBP resources",
        password="SecurePass123!",
    ).model_dump()


def test_to_biocommons_register_data(valid_registration_data):
    sbp_data = SBPRegistrationDataFactory.build()
    register_data = BiocommonsRegisterData.from_sbp_registration(sbp_data)
    assert register_data.username == sbp_data.username
    assert register_data.name == f"{sbp_data.first_name} {sbp_data.last_name}"
    assert register_data.app_metadata.registration_from == "sbp"


def test_successful_registration(
    test_client, valid_registration_data, mock_auth0_client, test_db_session
):
    """Test successful user registration with SBP service"""
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(
        user_id=user_id,
        email=valid_registration_data["email"],
        username=valid_registration_data["username"]
    )

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "Approval pending" in data["message"]
    assert "user" in data

    # Check that user exists in database
    user = test_db_session.exec(select(BiocommonsUser).where(BiocommonsUser.id == user_id)).first()
    assert user is not None
    assert user.email == valid_registration_data["email"]
    assert user.username == valid_registration_data["username"]

    # Check that SBP membership is created but not approved
    membership = test_db_session.exec(
        select(PlatformMembership).where(
            PlatformMembership.user_id == user_id,
            PlatformMembership.platform_id == PlatformEnum.SBP
        )
    ).first()
    assert membership is not None
    assert membership.approval_status == "pending"  # Should be pending, not approved

    # Check that membership history is created
    history = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.user_id == user_id,
            PlatformMembershipHistory.platform_id == PlatformEnum.SBP
        )
    ).first()
    assert history is not None
    assert history.approval_status == "pending"


def test_registration_duplicate_user(
    test_client, valid_registration_data, mock_auth0_client
):
    """Test registration with duplicate username/email"""
    # Mock Auth0 to return 409 Conflict
    error_response = httpx.Response(409, text="User already exists")
    mock_auth0_client.create_user.side_effect = httpx.HTTPStatusError(
        "User exists", request=None, response=error_response
    )

    response = test_client.post("/sbp/register", json=valid_registration_data)
    assert response.status_code == 400
    data = response.json()
    assert "Username or email already in use" in data["message"]


def test_registration_auth0_error(
    test_client, mock_auth0_client, valid_registration_data
):
    """Test registration with Auth0 server error"""
    error_response = httpx.Response(500, text="Internal server error")
    mock_auth0_client.create_user.side_effect = httpx.HTTPStatusError(
        "Server error", request=None, response=error_response
    )

    response = test_client.post("/sbp/register", json=valid_registration_data)
    assert response.status_code == 400
    data = response.json()
    assert "Auth0 error" in data["message"]


def test_registration_request_validation(test_client):
    """Test registration with invalid data"""
    invalid_data = {
        "username": "",  # Invalid: too short
        "first_name": "",  # Invalid: empty
        "last_name": "",  # Invalid: empty
        "email": "invalid-email",  # Invalid: not an email
        "reason": "",  # Invalid: empty
        "password": "weak",  # Invalid: doesn't meet requirements
    }

    response = test_client.post("/sbp/register", json=invalid_data)
    assert response.status_code == 400  # Validation error handled by RegistrationRoute


def test_registration_email_format(test_client, valid_registration_data):
    """Test registration with invalid email format"""
    valid_registration_data["email"] = "not-an-email"

    response = test_client.post("/sbp/register", json=valid_registration_data)
    assert response.status_code == 400


def test_registration_password_validation(test_client, valid_registration_data):
    """Test registration with weak password"""
    valid_registration_data["password"] = "weak"

    response = test_client.post("/sbp/register", json=valid_registration_data)
    assert response.status_code == 400


def test_registration_username_validation(test_client, valid_registration_data):
    """Test registration with invalid username"""
    valid_registration_data["username"] = "invalid username!"  # Contains invalid characters

    response = test_client.post("/sbp/register", json=valid_registration_data)
    assert response.status_code == 400


def test_successful_registration_with_email_enabled(
    test_client_with_email, valid_registration_data, mock_auth0_client, test_db_session, mocker
):
    """Test successful registration when email sending is enabled"""
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(user_id=user_id)

    # Mock email service
    mock_email_service = mocker.patch('routers.sbp_register.EmailService')

    response = test_client_with_email.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 200
    data = response.json()
    assert "Approval pending" in data["message"]

    # Verify email service was called (it's called as a background task)
    # Note: In a real test, you might need to wait for background tasks to complete
    assert mock_email_service.called


def test_sbp_metadata_stored_correctly(
    test_client, valid_registration_data, mock_auth0_client, test_db_session
):
    """Test that SBP metadata is stored correctly in Auth0 user data"""
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(user_id=user_id)

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 200

    # Verify the user_data passed to Auth0 contains SBP metadata
    call_args = mock_auth0_client.create_user.call_args[0][0]
    assert call_args.user_metadata.sbp.registration_reason == valid_registration_data["reason"]
    assert call_args.app_metadata.registration_from == "sbp"
