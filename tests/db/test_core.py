import pytest

from db.models import BiocommonsUser


def test_coerce_primary_key_map_succeeds_with_identity_as_map():
    identity = {"id": "auth0|123"}

    assert BiocommonsUser._coerce_primary_key_map(identity) is identity


def test_coerce_primary_key_map_when_primary_key_not_defined(mocker):
    mapper = mocker.Mock(primary_key=[])
    mocker.patch("db.core.sa_inspect", return_value=mapper)

    with pytest.raises(ValueError, match="BiocommonsUser does not have a primary key defined"):
        BiocommonsUser._coerce_primary_key_map("auth0|missing")


def test_coerce_primary_key_map_raises_when_tuple_length_mismatch(mocker):
    mapper = mocker.Mock(
        primary_key=[mocker.Mock(key="first"), mocker.Mock(key="second")]
    )
    mocker.patch("db.core.sa_inspect", return_value=mapper)

    with pytest.raises(ValueError, match="Identity length 1 does not match primary key length 2"):
        BiocommonsUser._coerce_primary_key_map(("only-one-value",))


def test_coerce_primary_key_map_succeeds_with_composite_key_values(mocker):
    mapper = mocker.Mock(
        primary_key=[mocker.Mock(key="first"), mocker.Mock(key="second")]
    )
    mocker.patch("db.core.sa_inspect", return_value=mapper)

    result = BiocommonsUser._coerce_primary_key_map(("value-a", "value-b"))

    assert result == {"first": "value-a", "second": "value-b"}


def test_coerce_primary_key_map_raises_for_invalid_identity_type(mocker):
    mapper = mocker.Mock(
        primary_key=[mocker.Mock(key="first"), mocker.Mock(key="second")]
    )
    mocker.patch("db.core.sa_inspect", return_value=mapper)

    with pytest.raises(ValueError, match="Identity must be scalar, tuple/list, or dict matching the primary key."):
        BiocommonsUser._coerce_primary_key_map("invalid-composite-identity")
