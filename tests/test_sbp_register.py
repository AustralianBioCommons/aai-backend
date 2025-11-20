import httpx
import pytest
from sqlmodel import select

from db.models import (
    BiocommonsUser,
    EmailNotification,
    PlatformEnum,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.types import EmailStatusEnum
from routers.sbp_register import validate_sbp_email_domain
from schemas.biocommons import BiocommonsRegisterData
from tests.datagen import (
    Auth0UserDataFactory,
    SBPRegistrationDataFactory,
    random_auth0_id,
)
from tests.db.datagen import Auth0RoleFactory, PlatformFactory


@pytest.fixture
def valid_registration_data(mock_settings):
    allowed_domain = mock_settings.sbp_allowed_email_domains[0]
    return SBPRegistrationDataFactory.build(
        username="testuser",
        first_name="Test",
        last_name="User",
        email=f"testuser@{allowed_domain}",
        reason="Need access to SBP resources",
        password="SecurePass123!",
    ).model_dump()


@pytest.fixture
def sbp_platform(persistent_factories):
    """
    Set up a SBP platform with the associated platform role
    """
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/sbp")
    return PlatformFactory.create_sync(
        id=PlatformEnum.SBP,
        role_id=platform_role.id,
        name="Structural Biology Platform",
    )


def test_to_biocommons_register_data():
    sbp_data = SBPRegistrationDataFactory.build()
    register_data = BiocommonsRegisterData.from_sbp_registration(sbp_data)
    assert register_data.username == sbp_data.username
    assert register_data.name == f"{sbp_data.first_name} {sbp_data.last_name}"
    assert register_data.app_metadata.registration_from == "sbp"


def test_validate_sbp_email_domain_function():
    from unittest.mock import Mock
    mock_settings = Mock()
    mock_settings.sbp_allowed_email_domains = [
        "unsw.edu.au", "ad.unsw.edu.au", "student.unsw.edu.au",
        "biocommons.org.au",
        "sydney.edu.au", "uni.sydney.edu.au",
        "wehi.edu.au",
        "monash.edu", "student.monash.edu",
        "griffith.edu.au", "griffithuni.edu.au",
        "unimelb.edu.au", "student.unimelb.edu.au"
    ]

    # Test approved domains
    assert validate_sbp_email_domain("user@unsw.edu.au", mock_settings)
    assert validate_sbp_email_domain("user@biocommons.org.au", mock_settings)
    assert validate_sbp_email_domain("user@sydney.edu.au", mock_settings)
    assert validate_sbp_email_domain("USER@UNSW.EDU.AU", mock_settings)

    # Test rejected domains
    assert not validate_sbp_email_domain("user@gmail.com", mock_settings)
    assert not validate_sbp_email_domain("user@unsw.com", mock_settings)
    assert not validate_sbp_email_domain("user@biocommons.org", mock_settings)
    assert not validate_sbp_email_domain("user@evilunsw.edu.au", mock_settings)
    assert not validate_sbp_email_domain("user@malicious.biocommons.org.au", mock_settings)
    assert not validate_sbp_email_domain("user@fakeunimelb.edu.au", mock_settings)


def test_successful_registration(
    test_client, valid_registration_data, mock_auth0_client, sbp_platform, test_db_session
):
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(
        user_id=user_id,
        email=valid_registration_data["email"],
        username=valid_registration_data["username"]
    )

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 200
    assert "Approval pending" in response.json()["message"]

    user = test_db_session.get(BiocommonsUser, user_id)
    assert user is not None
    assert user.email == valid_registration_data["email"]
    assert user.username == valid_registration_data["username"]

    membership = test_db_session.exec(
        select(PlatformMembership).where(
            PlatformMembership.user_id == user_id,
            PlatformMembership.platform_id == PlatformEnum.SBP
        )
    ).first()
    assert membership is not None
    assert membership.approval_status == "pending"

    history = test_db_session.exec(
        select(PlatformMembershipHistory).where(
            PlatformMembershipHistory.user_id == user_id,
            PlatformMembershipHistory.platform_id == PlatformEnum.SBP
        )
    ).first()
    assert history is not None
    assert history.approval_status == "pending"

    called_data = mock_auth0_client.create_user.call_args[0][0]
    assert called_data.user_metadata.sbp.registration_reason == valid_registration_data["reason"]
    assert called_data.app_metadata.registration_from == "sbp"
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == "aai-dev@biocommons.org.au"
    assert queued_emails[0].status == EmailStatusEnum.PENDING


def test_registration_duplicate_user(
    test_client, valid_registration_data, mock_auth0_client
):
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="User already exists"),
    )
    mock_auth0_client.create_user.side_effect = error

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Username or email already in use"


def test_registration_auth0_error(
    test_client, mock_auth0_client, valid_registration_data
):
    error = httpx.HTTPStatusError(
        "Server error",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(400, text="Something went wrong"),
    )
    mock_auth0_client.create_user.side_effect = error

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Auth0 error: Something went wrong"


def test_registration_request_validation(test_client):
    invalid_data = {
        "username": "testuser",
        "email": "invalid-email",
    }

    response = test_client.post("/sbp/register", json=invalid_data)

    assert response.status_code == 400
    error_data = response.json()
    assert error_data["message"] == "Invalid data submitted"
    assert any(error["field"] == "email" for error in error_data["field_errors"])


def test_registration_email_format(test_client, valid_registration_data):
    data = valid_registration_data.copy()
    data["email"] = "invalid-email"

    response = test_client.post("/sbp/register", json=data)

    assert response.status_code == 400
    details = response.json()
    errors = details["field_errors"]
    assert "email" in [error["field"] for error in errors]


def test_registration_rejected_email_domains(test_client, valid_registration_data, mock_auth0_client):
    data = valid_registration_data.copy()
    data["email"] = "user@unapproved-domain.com"

    response = test_client.post("/sbp/register", json=data)

    assert response.status_code == 400
    assert "Email domain not approved for SBP registration" in response.json()["message"]
    assert not mock_auth0_client.create_user.called
