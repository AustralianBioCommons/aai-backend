import pytest

from auth0.client import get_auth0_client
from main import app
from routers import utils
from tests.datagen import AppMetadataFactory, Auth0UserDataFactory


@pytest.fixture
def override_auth0_client(mocker):
    def override_auth0_client():
        return mock_client

    mock_client = mocker.patch("routers.utils.Auth0Client")()
    app.dependency_overrides[get_auth0_client] = override_auth0_client
    yield mock_client
    app.dependency_overrides.clear()


def test_get_registration_info(override_auth0_client, test_client):
    """
    Test we can look up a user by email, and return their
    app_metadata.registration_from value, if available.
    """
    app_metadata = AppMetadataFactory.build(registration_from="galaxy")
    user = Auth0UserDataFactory.build(email="user@example.com",
                                      app_metadata=app_metadata)
    override_auth0_client.search_users_by_email.return_value = [user]
    resp = test_client.get("/utils/register/registration-info", params={"user_email": user.email})
    assert resp.status_code == 200
    data = resp.json()
    assert data["app"] == "galaxy"


def test_get_registration_info_no_registration_from(override_auth0_client, test_client):
    """
    Test the default of 'biocommons' is returned if registration_from isn't set.
    """
    app_metadata = AppMetadataFactory.build(registration_from=None)
    user = Auth0UserDataFactory.build(email="user@example.com",
                                      app_metadata=app_metadata)
    override_auth0_client.search_users_by_email.return_value = [user]
    resp = test_client.get("/utils/register/registration-info", params={"user_email": user.email})
    assert resp.status_code == 200
    data = resp.json()
    assert data["app"] == "biocommons"


def test_get_registration_info_no_user(override_auth0_client, test_client):
    """
    Test the default of 'biocommons' is returned if the user doesn't exist.
    (we don't want an endpoint that allows easily checking if a user
    exists or not)
    """
    override_auth0_client.search_users_by_email.return_value = []
    resp = test_client.get("/utils/register/registration-info", params={"user_email": "notfound@example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["app"] == "biocommons"


def test_check_username_exists_exact_match_only(override_auth0_client, test_client):
    """Test that username check only matches exact usernames, not partial matches"""
    user1 = Auth0UserDataFactory.build(username="testuser")
    user2 = Auth0UserDataFactory.build(username="testuser123")
    override_auth0_client.get_users.return_value = [user1, user2]

    resp = test_client.get("/utils/register/check-username-availability", params={"username": "testuser"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is False
    assert data["field_errors"][0]["message"] == "Username is already taken"

    resp = test_client.get("/utils/register/check-username-availability", params={"username": "testuser99"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is True
    assert data["field_errors"] == []


def test_check_email_availability_endpoint(override_auth0_client, test_client):
    override_auth0_client.search_users_by_email.return_value = [Auth0UserDataFactory.build()]
    resp = test_client.get(
        "/utils/register/check-email-availability",
        params={"email": "existing@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is False
    assert data["field_errors"][0]["field"] == "email"

    override_auth0_client.search_users_by_email.return_value = []
    resp = test_client.get(
        "/utils/register/check-email-availability",
        params={"email": "new@example.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is True
    assert data["field_errors"] == []


def test_check_username_exists_handles_exceptions(mocker):
    auth0_client = mocker.Mock()
    auth0_client.get_users.side_effect = RuntimeError("boom")
    assert utils._check_username_exists("testuser", auth0_client) is False


def test_check_email_exists_handles_exceptions(mocker):
    auth0_client = mocker.Mock()
    auth0_client.search_users_by_email.side_effect = RuntimeError("boom")
    assert utils._check_email_exists("user@example.com", auth0_client) is False


def test_check_existing_user_all_branches(mocker):
    auth0_client = mocker.Mock()
    mocker.patch("routers.utils._check_username_exists", return_value=True)
    mocker.patch("routers.utils._check_email_exists", return_value=True)
    assert utils.check_existing_user("u", "e@example.com", auth0_client) == "both"

    mocker.patch("routers.utils._check_username_exists", return_value=True)
    mocker.patch("routers.utils._check_email_exists", return_value=False)
    assert utils.check_existing_user("u", "e@example.com", auth0_client) == "username"

    mocker.patch("routers.utils._check_username_exists", return_value=False)
    mocker.patch("routers.utils._check_email_exists", return_value=True)
    assert utils.check_existing_user("u", "e@example.com", auth0_client) == "email"

    mocker.patch("routers.utils._check_username_exists", return_value=False)
    mocker.patch("routers.utils._check_email_exists", return_value=False)
    assert utils.check_existing_user("u", "e@example.com", auth0_client) is None
