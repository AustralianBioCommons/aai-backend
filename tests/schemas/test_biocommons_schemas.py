import pytest
from pydantic import TypeAdapter

from db.types import ApprovalStatusEnum, PlatformEnum
from schemas.biocommons import (
    ALLOWED_SPECIAL_CHARS,
    PASSWORD_FORMAT_MESSAGE,
    BiocommonsEmail,
    BiocommonsPassword,
    BiocommonsUsername,
    UserProfileData,
)
from tests.datagen import UserInfoFactory
from tests.db.datagen import (
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)


@pytest.mark.parametrize("password", [
   "V6Zs^B8E",
   "k$M2FZa@",
   "6*@s&#5Z",
   "Jd9sugcfjgWXY@Dzje^83!mcfM@A$YZ8be^bUhrBZ8s$KjbbNwAHr*bdiEhmLyMPyPowFU@rX4k8h5KCh#qm9bYS5RUmtjaLmVds",
   *[f"Password1{x}" for x in ALLOWED_SPECIAL_CHARS]
])
def test_valid_password(password: str):
    password_adapter = TypeAdapter(BiocommonsPassword)
    result = password_adapter.validate_python(password)
    assert result == password


@pytest.mark.parametrize("password,expected_error", [
    # Too short
    ("aB1!", "Password must be at least 8 characters."),
    ("Abc12!", "Password must be at least 8 characters."),
    ("", "Password must be at least 8 characters."),
    # Too long (more than 128 characters)
    ("A" * 129 + "bc123!", "Password must be 128 characters or less."),
    # Missing uppercase letter
    ("abcd1234!", PASSWORD_FORMAT_MESSAGE),
    # Missing lowercase letter
    ("ABCD1234!", PASSWORD_FORMAT_MESSAGE),
    # Missing number
    ("AbcdEfgh!", PASSWORD_FORMAT_MESSAGE),
    # Missing special character
    ("abCD1234", PASSWORD_FORMAT_MESSAGE),
    # Invalid special characters
    ("Password123.", PASSWORD_FORMAT_MESSAGE),
])
def test_invalid_password(password: str, expected_error: str):
    """Test that invalid passwords raise appropriate validation errors."""
    password_adapter = TypeAdapter(BiocommonsPassword)
    with pytest.raises(ValueError) as exc_info:
        password_adapter.validate_python(password)

    # Check that the error message contains our custom message
    assert expected_error in str(exc_info.value)


def test_user_profile_data_with_memberships(test_db_session, persistent_factories):
    auth0_user = UserInfoFactory.build()
    db_user = BiocommonsUserFactory.create_sync(
        id=auth0_user.sub,
        email=auth0_user.email,
        username="test-user",
        platform_memberships=[],
        group_memberships=[],
    )

    galaxy_platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Galaxy Australia",
    )
    sbp_platform = PlatformFactory.create_sync(
        id=PlatformEnum.SBP,
        name="SBP",
    )
    bpa_platform = PlatformFactory.create_sync(
        id=PlatformEnum.BPA_DATA_PORTAL,
        name="BPA Data Portal",
    )
    tsi_group = BiocommonsGroupFactory.create_sync(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        short_name="TSI",
    )

    PlatformMembershipFactory.create_sync(
        user=db_user,
        platform=galaxy_platform,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    PlatformMembershipFactory.create_sync(
        user=db_user,
        platform=sbp_platform,
        platform_id=sbp_platform.id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    PlatformMembershipFactory.create_sync(
        user=db_user,
        platform=bpa_platform,
        approval_status=ApprovalStatusEnum.REVOKED,
    )
    GroupMembershipFactory.create_sync(
        user=db_user,
        group=tsi_group,
        group_id=tsi_group.group_id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )

    test_db_session.flush()
    test_db_session.refresh(db_user)

    profile = UserProfileData.from_db_user(db_user, auth0_user)

    assert profile.user_id == auth0_user.sub
    assert profile.email == db_user.email
    assert profile.username == db_user.username
    platform_map = {membership.platform_id: membership for membership in profile.platform_memberships}
    assert platform_map[PlatformEnum.GALAXY].platform_name == "Galaxy Australia"
    assert platform_map[PlatformEnum.GALAXY].approval_status == ApprovalStatusEnum.APPROVED
    assert platform_map[PlatformEnum.SBP].platform_name == "SBP"
    assert platform_map[PlatformEnum.SBP].approval_status == ApprovalStatusEnum.PENDING
    # Revoked platforms should not be included
    assert PlatformEnum.BPA_DATA_PORTAL not in platform_map

    group_map = {membership.group_id: membership for membership in profile.group_memberships}

    tsi_membership = group_map["biocommons/group/tsi"]
    assert tsi_membership.group_name == "Threatened Species Initiative"
    assert tsi_membership.group_short_name == "TSI"
    assert tsi_membership.approval_status == ApprovalStatusEnum.APPROVED



@pytest.mark.parametrize("username", [
    "abc",
    "a_c",
    "user_n-ame"
])
def test_valid_username(username: str):
    username_adapter = TypeAdapter(BiocommonsUsername)
    result = username_adapter.validate_python(username)
    assert result == username


@pytest.mark.parametrize("username,expected_error", [
    # Too short (less than 3 characters)
    ("ab", "Username must be at least 3 characters."),
    # Too long (more than 128 characters)
    ("x" * 129, "Username must be 128 characters or less."),
    # Invalid characters
    ("a.b", "Username must only contain lowercase letters, numbers, hyphens and underscores."),
    ("user name", "Username must only contain lowercase letters, numbers, hyphens and underscores."),
    ("User123", "Username must only contain lowercase letters, numbers, hyphens and underscores."),
    # Unicode characters
    ("usér123", "Username must only contain lowercase letters, numbers, hyphens and underscores."),
    ("user™", "Username must only contain lowercase letters, numbers, hyphens and underscores."),
])
def test_invalid_username(username: str, expected_error: str):
    """Test that invalid usernames raise appropriate validation errors."""
    username_adapter = TypeAdapter(BiocommonsUsername)
    with pytest.raises(ValueError) as exc_info:
        username_adapter.validate_python(username)

    # Check that the error message contains our custom message
    assert expected_error in str(exc_info.value)


@pytest.mark.parametrize("email", [
    "user@example.com",
    "first.last+label@mail.co",
    "user.name@subdomain.example.com",
])
def test_valid_email(email: str):
    email_adapter = TypeAdapter(BiocommonsEmail)
    result = email_adapter.validate_python(email)
    assert result == email


@pytest.mark.parametrize("email,expected_error", [
    (
        "a" * 65 + "@example.com",
        "Email local part must be 64 characters or less.",
    ),
    (
        "user@" + "a" * 251 + ".com",
        "Email domain must be 254 characters or less.",
    ),
    (
        "user@bücher.de",
        "Email domain must be ASCII and already transcoded.",
    ),
])
def test_invalid_email(email: str, expected_error: str):
    email_adapter = TypeAdapter(BiocommonsEmail)
    with pytest.raises(ValueError) as exc_info:
        email_adapter.validate_python(email)
    assert expected_error in str(exc_info.value)
