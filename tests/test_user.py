from fastapi import HTTPException
import pytest

from auth.config import Settings
from fastapi.testclient import TestClient
from main import app
from tests.datagen import AccessTokenPayloadFactory

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_auth_settings(mocker):
    """Fixture to mock auth settings globally"""
    mock_settings = Settings(
        auth0_domain="mock-domain.com",
        auth0_audience="mock-audience",
        auth0_management_id="mock-id",
        auth0_management_secret="mock-secret",
        auth0_algorithms=["RS256"],
    )
    mocker.patch("auth.config.get_settings", return_value=mock_settings)
    mocker.patch("auth.management.get_settings", return_value=mock_settings)
    return mock_settings


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


# Authentication Tests (GET)
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


# Service Tests (GET)
def test_get_all_services(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all services"""
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": mock_user_data["app_metadata"]["services"]}


def test_get_approved_services(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting approved services"""
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
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
        "routers.user.fetch_user_data",
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services/pending", headers=auth_headers)
    assert response.status_code == 200
    pending_services = [
        s
        for s in mock_user_data["app_metadata"]["services"]
        if s["status"] == "pending"
    ]
    assert response.json() == {"pending_services": pending_services}


def test_get_services_failed_fetch(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of failed API calls"""
    mocker.patch(
        "routers.user.fetch_user_data",
        side_effect=HTTPException(status_code=403, detail="Failed to fetch user data"),
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Failed to fetch user data"}


def test_get_services_empty_metadata(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of empty metadata"""
    mocker.patch("routers.user.fetch_user_data", return_value={"app_metadata": {}})
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


def test_get_services_no_metadata(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of missing metadata"""
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value={},
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


# Resource Tests (GET)
def test_get_all_resources(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all resources"""

    # Patch token fetch
    mocker.patch(
        "httpx.post",
        return_value=mocker.Mock(
            status_code=200, json=lambda: {"access_token": "test-token"}
        ),
    )

    # Patch user metadata fetch
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


def test_get_approved_resources(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting approved resources"""
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources/approved", headers=auth_headers)
    assert response.status_code == 200
    approved_resources = [
        resource
        for service in mock_user_data["app_metadata"]["services"]
        for resource in service["resources"]
        if resource["status"] == "approved"
    ]
    assert response.json() == {"approved_resources": approved_resources}


def test_get_pending_resources(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting pending resources"""
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources/pending", headers=auth_headers)
    assert response.status_code == 200
    pending_resources = [
        resource
        for service in mock_user_data["app_metadata"]["services"]
        for resource in service["resources"]
        if resource["status"] == "pending"
    ]
    assert response.json() == {"pending_resources": pending_resources}


def test_get_resources_failed_fetch(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of failed resource API calls"""
    mocker.patch(
        "routers.user.fetch_user_data",
        side_effect=HTTPException(status_code=403, detail="Failed to fetch user data"),
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Failed to fetch user data"}


def test_get_resources_empty_metadata(
    mock_auth_settings, mock_auth_token, auth_headers, mocker
):
    """Test handling of empty resource metadata"""
    mocker.patch(
        "routers.user.fetch_user_data", return_value={"app_metadata": {"services": []}}
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"resources": []}


# Service Request Tests (POST)
def test_request_service_success(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test successful service request"""
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )
    mocker.patch("routers.user.update_user_metadata", return_value={})

    new_service = {
        "name": "New Service",
        "id": "service3",
        "user_id": mock_auth_token.sub,
    }

    response = client.post("/request/service", json=new_service, headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Service request submitted successfully"
    assert response.json()["service"]["id"] == "service3"


def test_request_service_duplicate(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test duplicate service request"""
    mocker.patch(
        "httpx.post",
        return_value=mocker.Mock(
            status_code=200, json=lambda: {"access_token": "test-token"}
        ),
    )
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    existing_service = {
        "name": "Service 1",
        "id": "service1",
        "user_id": mock_auth_token.sub,
    }

    response = client.post(
        "/request/service", json=existing_service, headers=auth_headers
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"] == "Service request with ID service1 already exists"
    )


def test_request_service_user_mismatch(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test service request with mismatched user"""
    request_payload = {
        "name": "Service Mismatch",
        "id": "svc-mismatch",
        "user_id": "auth0|WRONG_USER",
    }

    response = client.post(
        "/request/service", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "User ID in request does not match authenticated user"
    )


# Resource Request Tests (POST)
def test_request_resource_success(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test successful resource request"""
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )
    mocker.patch("routers.user.update_user_metadata", return_value={})

    request_payload = {
        "name": "New Resource",
        "id": "resource-new",
        "user_id": mock_auth_token.sub,
        "service_id": "service1",
    }

    response = client.post(
        "/request/service1/resource-new", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["resource"]["id"] == "resource-new"


def test_request_resource_user_mismatch(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test resource request with mismatched user"""
    request_payload = {
        "name": "Invalid Resource",
        "id": "res-invalid",
        "user_id": "wrong-user",
        "service_id": "service1",
    }

    response = client.post(
        "/request/service1/res-invalid", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "User ID in request does not match authenticated user"
    )


def test_request_resource_non_approved_service(
    mock_auth_settings, mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test resource request for non-approved service"""
    # Set service2 to be requested
    service = mock_user_data["app_metadata"]["services"][1]

    mocker.patch(
        "httpx.post",
        return_value=mocker.Mock(
            status_code=200, json=lambda: {"access_token": "test-token"}
        ),
    )
    mocker.patch(
        "httpx.AsyncClient.get",
        return_value=mocker.Mock(status_code=200, json=lambda: mock_user_data),
    )

    request_payload = {
        "name": "Blocked Resource",
        "id": "blocked-resource",
        "user_id": mock_auth_token.sub,
        "service_id": "service2",
    }

    response = client.post(
        "/request/service2/blocked-resource", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "Cannot request resources for a service that is not approved"
    )
