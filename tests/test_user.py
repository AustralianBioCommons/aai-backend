import pytest
from fastapi.testclient import TestClient

from auth.config import Settings
from main import app
from tests.datagen import AccessTokenPayloadFactory

client = TestClient(app)


@pytest.fixture
def mock_auth_settings(mocker):
    """Fixture to mock auth settings"""
    return mocker.patch(
        "auth.config.get_settings",
        return_value=Settings(
            auth0_domain="mock-domain",
            auth0_audience="mock-audience",
            auth0_management_id="mock-id",
            auth0_management_secret="mock-secret",
            auth0_algorithms=["RS256"],
        ),
    )


@pytest.fixture
def mock_auth_token(mocker):
    """Fixture to mock authentication token"""
    token = AccessTokenPayloadFactory.build(
        sub="auth0|123456789",
        biocommons_roles=["acdc/indexd_admin"],
    )
    mocker.patch("auth.validator.verify_jwt", return_value=token)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    return token


@pytest.fixture
def auth_headers():
    """Fixture to provide auth headers"""
    return {"Authorization": "Bearer valid_token"}


@pytest.fixture
def mock_user_data():
    """Fixture to provide mock user data"""
    return {
        "app_metadata": {
            "services": [
                {
                    "id": "service1",
                    "name": "Service 1",
                    "status": "approved",
                    "resources": [
                        {"id": "resource1", "name": "Resource 1", "status": "approved"},
                        {"id": "resource2", "name": "Resource 2", "status": "pending"},
                    ],
                },
                {
                    "id": "service2",
                    "name": "Service 2",
                    "status": "pending",
                    "resources": [
                        {"id": "resource3", "name": "Resource 3", "status": "pending"},
                    ],
                },
            ]
        }
    }


@pytest.mark.parametrize(
    "endpoint",
    [
        "/me/services",
        "/me/services/approved",
        "/me/services/pending",
        "/me/resources",
        "/me/resources/approved",
        "/me/resources/pending",
        "/me/all/pending",
    ],
)
def test_endpoints_require_auth(endpoint):
    """Test that all endpoints require authentication"""
    response = client.get(endpoint)
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_get_all_services(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all services"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": mock_user_data["app_metadata"]["services"]}


def test_get_approved_services(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting approved services"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    response = client.get("/me/services/approved", headers=auth_headers)
    assert response.status_code == 200
    approved_services = [
        s
        for s in mock_user_data["app_metadata"]["services"]
        if s["status"] == "approved"
    ]
    assert response.json() == {"approved_services": approved_services}


def test_get_pending_services(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting pending services"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    response = client.get("/me/services/pending", headers=auth_headers)
    assert response.status_code == 200
    pending_services = [
        s
        for s in mock_user_data["app_metadata"]["services"]
        if s["status"] == "pending"
    ]
    assert response.json() == {"pending_services": pending_services}


def test_get_all_resources(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all resources"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 200
    all_resources = [
        resource
        for service in mock_user_data["app_metadata"]["services"]
        for resource in service["resources"]
    ]
    assert response.json() == {"resources": all_resources}


def test_get_services_failed_fetch(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of failed API calls"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(
            status_code=403, json=lambda: {"error": "Unauthorized"}
        ),
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Failed to fetch user data"}


def test_get_services_empty_metadata(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of empty metadata"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: {"app_metadata": {}}),
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


def test_get_services_no_metadata(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of missing metadata"""
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: {}),
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}
