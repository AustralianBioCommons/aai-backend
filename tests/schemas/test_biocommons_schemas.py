import pytest
from pydantic import TypeAdapter

from schemas.biocommons import (
    ALLOWED_SPECIAL_CHARS,
    PASSWORD_FORMAT_MESSAGE,
    BiocommonsPassword,
    BiocommonsUsername,
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
