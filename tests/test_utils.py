import pytest

from auth0.client import get_auth0_client
from main import app
from tests.datagen import AppMetadataFactory, BiocommonsAuth0UserFactory


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
    user = BiocommonsAuth0UserFactory.build(email="user@example.com",
                                            app_metadata=app_metadata)
    override_auth0_client.search_users_by_email.return_value = [user]
    resp = test_client.get("/utils/registration_info", params={"user_email": user.email})
    assert resp.status_code == 200
    data = resp.json()
    assert data["app"] == "galaxy"


def test_get_registration_info_no_registration_from(override_auth0_client, test_client):
    """
    Test the default of 'biocommons' is returned if registration_from isn't set.
    """
    app_metadata = AppMetadataFactory.build(registration_from=None)
    user = BiocommonsAuth0UserFactory.build(email="user@example.com",
                                            app_metadata=app_metadata)
    override_auth0_client.search_users_by_email.return_value = [user]
    resp = test_client.get("/utils/registration_info", params={"user_email": user.email})
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
    resp = test_client.get("/utils/registration_info", params={"user_email": "notfound@example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["app"] == "biocommons"
