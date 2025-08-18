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

    # Test that all required fields are present
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
    from db.models import PlatformEnum
    from routers.biocommons_register import _create_biocommons_user_record

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

    # Create user record
    user = _create_biocommons_user_record(auth0_data, registration, test_db_session)

    # Verify user basic data
    assert user.username == "bpagalaxy"
    assert user.email == "bpa.galaxy@example.com"
    assert user.id == "auth0|bpagalaxy123"

    # Verify group membership
    assert len(user.group_memberships) == 1
    group_membership = user.group_memberships[0]
    assert group_membership.group_id == "biocommons/group/bpa_galaxy"
    assert group_membership.approval_status.value == "pending"

    # Verify platform memberships (should have both BPA and Galaxy)
    assert len(user.platform_memberships) == 2
    platform_ids = {pm.platform_id for pm in user.platform_memberships}
    assert PlatformEnum.BPA_DATA_PORTAL in platform_ids
    assert PlatformEnum.GALAXY in platform_ids

    # Verify all platform memberships are pending
    for pm in user.platform_memberships:
        assert pm.approval_status.value == "pending"


def test_create_biocommons_user_record_tsi_bundle(test_db_session):
    """Test database record creation for tsi bundle"""
    from db.models import PlatformEnum
    from routers.biocommons_register import _create_biocommons_user_record

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

    # Create user record
    user = _create_biocommons_user_record(auth0_data, registration, test_db_session)

    # Verify user basic data
    assert user.username == "tsiuser"
    assert user.email == "tsi.user@example.com"

    # Verify group membership (should be TSI group)
    assert len(user.group_memberships) == 1
    group_membership = user.group_memberships[0]
    assert group_membership.group_id == "biocommons/group/tsi"
    assert group_membership.approval_status.value == "pending"

    # Verify platform memberships (should still have both BPA and Galaxy)
    assert len(user.platform_memberships) == 2
    platform_ids = {pm.platform_id for pm in user.platform_memberships}
    assert PlatformEnum.BPA_DATA_PORTAL in platform_ids
    assert PlatformEnum.GALAXY in platform_ids


def test_biocommons_group_creation(test_db_session):
    """Test that BiocommonsGroup records are created when they don't exist"""
    from db.models import BiocommonsGroup
    from routers.biocommons_register import _create_biocommons_user_record

    registration = BiocommonsRegistrationRequest(
        first_name="New",
        last_name="Group",
        email="new.group@example.com",
        username="newgroup",
        password="StrongPass1!",
        bundle="bpa-galaxy",
    )

    auth0_data = Auth0UserDataFactory.build(
        email="new.group@example.com", username="newgroup", user_id="auth0|newgroup123"
    )

    # Verify group doesn't exist initially
    group = test_db_session.get(BiocommonsGroup, "biocommons/group/bpa_galaxy")
    assert group is None

    # Create user record (should create group)
    _create_biocommons_user_record(auth0_data, registration, test_db_session)

    # Verify group was created
    group = test_db_session.get(BiocommonsGroup, "biocommons/group/bpa_galaxy")
    assert group is not None
    assert group.group_id == "biocommons/group/bpa_galaxy"
    assert group.name == "BPA Data Portal & Galaxy Access"
    assert group.admin_roles == []


def test_bundle_validation():
    """Test that only valid bundles are accepted"""
    with pytest.raises(ValueError):
        BiocommonsRegistrationRequest(
            first_name="Invalid",
            last_name="Bundle",
            email="invalid@example.com",
            username="invalid",
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
