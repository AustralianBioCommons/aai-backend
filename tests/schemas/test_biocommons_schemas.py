import pytest
from pydantic import TypeAdapter

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


@pytest.mark.parametrize("password", [
   "V6Zs^B8E",
   "k$M2FZa@",
   "6*@s&#5Z",
   "Jd9sugcfjgWXY@Dzje^83!mcfM@A$YZ8be^bUhrBZ8s$KjbbNwAHr*bdiEhmLyMPyPowFU@rX4k8h5KCh#qm9bYS5RUmtjaLmVds",
])
def test_valid_password(password: str):
    password_adapter = TypeAdapter(BiocommonsPassword)
    result = password_adapter.validate_python(password)
    assert result == password



@pytest.mark.parametrize("password", [
    # No lowercase
    "ABCD1234!",
    # No capital
    "abcd1234!",
    # Too short
    "aB1!",
    # No special character
    "abCD1234"
])
def test_invalid_password(password: str):
    password_adapter = TypeAdapter(BiocommonsPassword)
    with pytest.raises(ValueError):
        password_adapter.validate_python(password)


@pytest.mark.parametrize("username", [
    "abc",
    "a_c",
    "user_n-ame"
])
def test_valid_username(username: str):
    username_adapter = TypeAdapter(BiocommonsUsername)
    result = username_adapter.validate_python(username)
    assert result == username


@pytest.mark.parametrize("username", [
    "ab",
    "a.b",
    "x" * 129  # Too long
])
def test_invalid_username(username: str):
    username_adapter = TypeAdapter(BiocommonsUsername)
    with pytest.raises(ValueError):
        username_adapter.validate_python(username)
