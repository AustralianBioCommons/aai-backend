import pytest
from fastapi import HTTPException

from auth.validator import get_current_user, user_is_admin
from main import app
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserResponseFactory,
    UserFactory,
)


@pytest.fixture
def mock_auth0_client(mocker):
    mock_client = mocker.patch("routers.admin.Auth0Client")
    return mock_client()


def test_get_users_requires_admin_unauthorized(test_client, mocker):
    def get_nonadmin_user():
        payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
        return UserFactory.build(access_token=payload)

    app.dependency_overrides[get_current_user] = get_nonadmin_user
    mocker.patch("routers.admin.get_management_token", return_value="mock_token")
    resp = test_client.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json() == {"detail": "You must be an admin to access this endpoint."}
    app.dependency_overrides.clear()


def test_user_is_admin(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    admin_user = UserFactory.build(access_token=payload)
    assert user_is_admin(current_user=admin_user, settings=mock_settings)


def test_user_is_admin_nonadmin_user(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
    user = UserFactory.build(access_token=payload)
    with pytest.raises(HTTPException, match="You must be an admin to access this endpoint."):
        user_is_admin(current_user=user, settings=mock_settings)


def test_get_users(test_client, as_admin_user, mock_auth0_client):
    users = Auth0UserResponseFactory.batch(3)
    mock_auth0_client.get_users.return_value = users
    resp = test_client.get("/admin/users")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_get_user(test_client, as_admin_user, mock_auth0_client):
    user = Auth0UserResponseFactory.build()
    mock_auth0_client.get_user.return_value = user
    resp = test_client.get(f"/admin/users/{user.user_id}")
    assert resp.status_code == 200
    assert resp.json() == user.model_dump(mode='json')
