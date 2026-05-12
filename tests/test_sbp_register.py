import httpx
import pytest
from sqlmodel import select

from db.models import (
    BiocommonsUser,
    BiocommonsUserHistory,
    GroupMembership,
    PlatformMembership,
)
from db.types import ApprovalStatusEnum, GroupEnum, PlatformEnum
from routers.sbp_register import validate_sbp_email_domain
from schemas.biocommons import BiocommonsRegisterData
from tests.datagen import (
    Auth0UserDataFactory,
    SBPRegistrationDataFactory,
    random_auth0_id,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    PlatformFactory,
)


@pytest.fixture
def valid_registration_data(mock_settings):
    allowed_domain = mock_settings.sbp_allowed_email_domains[0]
    return SBPRegistrationDataFactory.build(
        username="testuser",
        first_name="Test",
        last_name="User",
        email=f"testuser@{allowed_domain}",
        request_reason="Need access to SBP resources",
        password="SecurePass123!",
    ).model_dump()


@pytest.fixture
def sbp_platform(persistent_factories):
    """
    Set up the SBP platform with the associated platform role
    """
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/sbp")
    return PlatformFactory.create_sync(
        id=PlatformEnum.SBP,
        role_id=platform_role.id,
        name="Structural Biology Platform",
    )


@pytest.fixture
def sbp_group(persistent_factories):
    """
    Set up the SBP group with the associated admin role
    """
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/sbp/admin")
    return BiocommonsGroupFactory.create_sync(
        group_id=GroupEnum.SBP.value,
        name="Structural Biology Platform Bundle",
        short_name="SBP",
        admin_roles=[admin_role],
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
    test_client, valid_registration_data, mock_auth0_client, sbp_group, sbp_platform, test_db_session
):
    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(
        user_id=user_id,
        email=valid_registration_data["email"],
        username=valid_registration_data["username"]
    )

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully."

    user = test_db_session.get(BiocommonsUser, user_id)
    assert user is not None
    assert user.email == valid_registration_data["email"]
    assert user.username == valid_registration_data["username"]

    group_membership = test_db_session.exec(
        select(GroupMembership).where(
            GroupMembership.user_id == user_id,
            GroupMembership.group_id == GroupEnum.SBP.value,
        )
    ).first()
    assert group_membership is not None
    assert group_membership.approval_status == ApprovalStatusEnum.APPROVED

    # SBP platform membership is auto-approved at registration so the user can log into the platform
    platform_membership = test_db_session.exec(
        select(PlatformMembership).where(
            PlatformMembership.user_id == user_id,
            PlatformMembership.platform_id == PlatformEnum.SBP,
        )
    ).first()
    assert platform_membership is not None
    assert platform_membership.approval_status == ApprovalStatusEnum.APPROVED

    called_data = mock_auth0_client.create_user.call_args[0][0]
    assert called_data.user_metadata.sbp.registration_reason == valid_registration_data["request_reason"]
    assert called_data.app_metadata.registration_from == "sbp"

    # Auth0 platform role is granted immediately; bundle role is not granted until admin approves
    assert mock_auth0_client.add_roles_to_user.call_count == 1


def test_registration_duplicate_user(
    test_client, valid_registration_data, mock_auth0_client, test_db_session,
):
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="User already exists"),
    )
    mock_auth0_client.create_user.side_effect = error

    mock_auth0_client.get_users.return_value = []
    mock_auth0_client.search_users_by_email.return_value = [Auth0UserDataFactory.build()]

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Email is already taken"


def test_registration_username_history_conflict(
    test_client, valid_registration_data, test_db_session, mock_auth0_client
):
    """Test handling of username conflict when username is in history"""
    # Create a user to attach history to
    user = BiocommonsUserFactory.build()
    test_db_session.add(user)
    test_db_session.commit()

    # Create a history entry for the username
    history = BiocommonsUserHistory(
        user_id=user.id,
        username=valid_registration_data["username"],
        email="old@example.com",
        change="username_change"
    )
    test_db_session.add(history)
    test_db_session.commit()

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Username is already taken"
    assert not mock_auth0_client.create_user.called


def test_registration_duplicate_username(
    test_client, valid_registration_data, mock_auth0_client, test_db_session
):
    """Test that duplicate username returns specific error message"""
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="User already exists"),
    )
    mock_auth0_client.create_user.side_effect = error

    mock_auth0_client.get_users.return_value = [Auth0UserDataFactory.build(username=valid_registration_data["username"])]
    mock_auth0_client.search_users_by_email.return_value = []

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Username is already taken"


def test_registration_duplicate_both(
    test_client, valid_registration_data, mock_auth0_client, test_db_session
):
    """Test that duplicate username and email returns specific error message"""
    error = httpx.HTTPStatusError(
        "User already exists",
        request=httpx.Request("POST", "https://api.example.com/data"),
        response=httpx.Response(409, text="User already exists"),
    )
    mock_auth0_client.create_user.side_effect = error

    mock_auth0_client.get_users.return_value = [Auth0UserDataFactory.build(username=valid_registration_data["username"])]
    mock_auth0_client.search_users_by_email.return_value = [Auth0UserDataFactory.build(email=valid_registration_data["email"])]

    response = test_client.post("/sbp/register", json=valid_registration_data)

    assert response.status_code == 400
    assert response.json()["message"] == "Username and email are already taken"


def test_registration_auth0_error(
    test_client, mock_auth0_client, valid_registration_data, test_db_session
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
