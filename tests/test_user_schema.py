from schemas.user import User
from tests.datagen import AccessTokenPayloadFactory


def test_is_admin_true(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    user = User(access_token=payload)
    assert user.is_admin(settings=mock_settings) is True


def test_is_admin_false(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
    user = User(access_token=payload)
    assert user.is_admin(settings=mock_settings) is False


def test_is_admin_empty_roles(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=[])
    user = User(access_token=payload)
    assert user.is_admin(settings=mock_settings) is False


def test_is_admin_multiple_roles_with_admin(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin", "Editor"])
    user = User(access_token=payload)
    assert user.is_admin(settings=mock_settings) is True
