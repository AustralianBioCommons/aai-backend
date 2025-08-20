import pytest

from schemas.biocommons import BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest
from tests.datagen import Auth0UserDataFactory


def test_biocommons_registration_data_excludes_null_user_metadata():
    """Test that user_metadata is excluded when None and basic Auth0 data is correct"""
    req = BiocommonsRegistrationRequest(
        first_name="Test",
        last_name="User",
        email="test@example.com",
        username="testuser",
        password="StrongPass1!",
        bundle="bpa-galaxy",
    )

    user_data = BiocommonsRegisterData.from_biocommons_registration(req)

    assert user_data.user_metadata is None

    dumped = user_data.model_dump(mode="json")
    assert "user_metadata" not in dumped

    assert dumped["email"] == "test@example.com"
    assert dumped["username"] == "testuser"
    assert dumped["name"] == "Test User"
    assert dumped["password"] == "StrongPass1!"
    assert dumped["connection"] == "Username-Password-Authentication"
    assert dumped["email_verified"] is False

    assert "app_metadata" in dumped
    app_metadata = dumped["app_metadata"]
    assert app_metadata["registration_from"] == "biocommons"
    assert app_metadata.get("services", []) == []
    assert app_metadata.get("groups", []) == []


def test_biocommons_registration_tsi_bundle():
    """Test TSI bundle registration creates correct basic Auth0 data"""
    req = BiocommonsRegistrationRequest(
        first_name="TSI",
        last_name="User",
        email="tsi@example.com",
        username="tsiuser",
        password="StrongPass1!",
        bundle="tsi",
    )

    user_data = BiocommonsRegisterData.from_biocommons_registration(req)
    dumped = user_data.model_dump(mode="json")

    assert dumped["name"] == "TSI User"
    assert dumped["app_metadata"]["registration_from"] == "biocommons"
    assert dumped["app_metadata"].get("groups", []) == []
    assert dumped["app_metadata"].get("services", []) == []


def test_create_biocommons_user_record_bpa_galaxy_bundle(test_db_session):
    """Test database record creation for bpa-galaxy bundle"""
    from db.models import BiocommonsGroup, PlatformEnum
    from routers.biocommons_register import _create_biocommons_user_record

    group = BiocommonsGroup(
        group_id="biocommons/group/bpa_galaxy",
        name="BPA Data Portal & Galaxy Access",
        admin_roles=[],
    )
    test_db_session.add(group)
    test_db_session.commit()

    registration = BiocommonsRegistrationRequest(
        first_name="BPA",
        last_name="Galaxy",
        email="bpa.galaxy@example.com",
        username="bpagalaxy",
        password="StrongPass1!",
        bundle="bpa-galaxy",
    )

    auth0_data = Auth0UserDataFactory.build(
        email="bpa.galaxy@example.com",
        username="bpagalaxy",
        name="BPA Galaxy",
        user_id="auth0|bpagalaxy123",
    )

    user = _create_biocommons_user_record(auth0_data, registration, test_db_session)

    assert user.username == "bpagalaxy"
    assert user.email == "bpa.galaxy@example.com"
    assert user.id == "auth0|bpagalaxy123"

    assert len(user.group_memberships) == 1
    group_membership = user.group_memberships[0]
    assert group_membership.group_id == "biocommons/group/bpa_galaxy"
    assert group_membership.approval_status.value == "pending"

    assert len(user.platform_memberships) == 2
    platform_ids = {pm.platform_id for pm in user.platform_memberships}
    assert PlatformEnum.BPA_DATA_PORTAL in platform_ids
    assert PlatformEnum.GALAXY in platform_ids

    for pm in user.platform_memberships:
        assert pm.approval_status.value == "pending"


def test_create_biocommons_user_record_tsi_bundle(test_db_session):
    """Test database record creation for tsi bundle"""
    from db.models import BiocommonsGroup, PlatformEnum
    from routers.biocommons_register import _create_biocommons_user_record

    group = BiocommonsGroup(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        admin_roles=[],
    )
    test_db_session.add(group)
    test_db_session.commit()

    registration = BiocommonsRegistrationRequest(
        first_name="TSI",
        last_name="User",
        email="tsi.user@example.com",
        username="tsiuser",
        password="StrongPass1!",
        bundle="tsi",
    )

    auth0_data = Auth0UserDataFactory.build(
        email="tsi.user@example.com",
        username="tsiuser",
        name="TSI User",
        user_id="auth0|tsiuser123",
    )

    user = _create_biocommons_user_record(auth0_data, registration, test_db_session)

    assert user.username == "tsiuser"
    assert user.email == "tsi.user@example.com"

    assert len(user.group_memberships) == 1
    group_membership = user.group_memberships[0]
    assert group_membership.group_id == "biocommons/group/tsi"
    assert group_membership.approval_status.value == "pending"

    assert len(user.platform_memberships) == 2
    platform_ids = {pm.platform_id for pm in user.platform_memberships}
    assert PlatformEnum.BPA_DATA_PORTAL in platform_ids
    assert PlatformEnum.GALAXY in platform_ids


def test_biocommons_group_must_exist(test_db_session):
    """Test that registration fails when the required group doesn't exist"""
    import pytest

    from routers.biocommons_register import _create_biocommons_user_record

    registration = BiocommonsRegistrationRequest(
        first_name="New",
        last_name="User",
        email="new.user@example.com",
        username="newuser",
        password="StrongPass1!",
        bundle="bpa-galaxy",
    )

    auth0_data = Auth0UserDataFactory.build(
        email="new.user@example.com", username="newuser", user_id="auth0|newuser123"
    )

    with pytest.raises(
        ValueError, match="Group 'biocommons/group/bpa_galaxy' not found"
    ):
        _create_biocommons_user_record(auth0_data, registration, test_db_session)


def test_biocommons_group_membership_with_existing_group(test_db_session):
    """Test that user is assigned to group when group exists"""
    from db.models import BiocommonsGroup
    from routers.biocommons_register import _create_biocommons_user_record

    group = BiocommonsGroup(
        group_id="biocommons/group/bpa_galaxy",
        name="BPA Data Portal & Galaxy Access",
        admin_roles=[],
    )
    test_db_session.add(group)
    test_db_session.commit()

    registration = BiocommonsRegistrationRequest(
        first_name="Test",
        last_name="User",
        email="test.user@example.com",
        username="testuser",
        password="StrongPass1!",
        bundle="bpa-galaxy",
    )

    auth0_data = Auth0UserDataFactory.build(
        email="test.user@example.com", username="testuser", user_id="auth0|testuser123"
    )

    user = _create_biocommons_user_record(auth0_data, registration, test_db_session)

    assert len(user.group_memberships) == 1
    assert user.group_memberships[0].group_id == "biocommons/group/bpa_galaxy"
    assert user.group_memberships[0].approval_status.value == "pending"


def test_bundle_validation():
    """Test that only valid bundles are accepted"""
    with pytest.raises(ValueError):
        BiocommonsRegistrationRequest(
            first_name="Test",
            last_name="Bundle",
            email="test@example.com",
            username="test",
            password="StrongPass1!",
            bundle="invalid-bundle",
        )


def test_biocommons_registration_name_formatting():
    """Test that first_name and last_name are properly combined"""
    req = BiocommonsRegistrationRequest(
        first_name="John",
        last_name="Doe-Smith",
        email="john.doe@example.com",
        username="johndoe",
        password="StrongPass1!",
        bundle="tsi",
    )

    user_data = BiocommonsRegisterData.from_biocommons_registration(req)
    assert user_data.name == "John Doe-Smith"


def test_successful_biocommons_registration_endpoint(
    test_client_with_email, mock_auth0_client, test_db_session, mocker
):
    """Test successful biocommons registration via HTTP endpoint"""
    from db.models import BiocommonsGroup, BiocommonsUser, PlatformEnum
    from tests.datagen import random_auth0_id

    group = BiocommonsGroup(
        group_id="biocommons/group/bpa_galaxy",
        name="BPA Data Portal & Galaxy Access",
        admin_roles=[],
    )
    test_db_session.add(group)
    test_db_session.commit()

    user_id = random_auth0_id()
    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build(
        user_id=user_id, email="test@example.com", username="testuser"
    )

    mock_email_cls = mocker.patch(
        "routers.biocommons_register.EmailService", autospec=True
    )
    mock_email_cls.return_value.send.return_value = None

    registration_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": "StrongPass1!",
        "bundle": "bpa-galaxy",
    }

    response = test_client_with_email.post(
        "/biocommons/register", json=registration_data
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"
    assert "user" in response.json()

    db_user = test_db_session.get(BiocommonsUser, user_id)
    assert db_user is not None
    assert db_user.username == "testuser"
    assert db_user.email == "test@example.com"

    assert len(db_user.group_memberships) == 1
    assert db_user.group_memberships[0].group_id == "biocommons/group/bpa_galaxy"

    assert len(db_user.platform_memberships) == 2
    platform_ids = {pm.platform_id for pm in db_user.platform_memberships}
    assert PlatformEnum.BPA_DATA_PORTAL in platform_ids
    assert PlatformEnum.GALAXY in platform_ids

    mock_email_cls.return_value.send.assert_called_once()


def test_biocommons_registration_auth0_conflict_error(
    test_client, mock_auth0_client, test_db_session
):
    """Test handling of Auth0 conflict error (user already exists)"""
    from httpx import HTTPStatusError, Request, Response

    from db.models import BiocommonsGroup

    group = BiocommonsGroup(
        group_id="biocommons/group/bpa_galaxy",
        name="BPA Data Portal & Galaxy Access",
        admin_roles=[],
    )
    test_db_session.add(group)
    test_db_session.commit()

    response = Response(409, json={"error": "user_exists"})
    request = Request("POST", "https://example.com")
    mock_auth0_client.create_user.side_effect = HTTPStatusError(
        "User already exists", request=request, response=response
    )

    registration_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "existing@example.com",
        "username": "existinguser",
        "password": "StrongPass1!",
        "bundle": "bpa-galaxy",
    }

    response = test_client.post("/biocommons/register", json=registration_data)

    assert response.status_code == 409
    assert response.json()["detail"] == "User already exists"


def test_biocommons_registration_missing_group_error(test_client, mock_auth0_client):
    """Test error when required group doesn't exist in database"""
    registration_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": "StrongPass1!",
        "bundle": "bpa-galaxy",
    }

    mock_auth0_client.create_user.return_value = Auth0UserDataFactory.build()

    response = test_client.post("/biocommons/register", json=registration_data)

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"
