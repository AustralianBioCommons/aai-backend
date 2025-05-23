from datetime import datetime

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import app
from schemas.service import AppMetadata, Group, Resource, Service
from tests.datagen import AccessTokenPayloadFactory, Auth0UserFactory

client = TestClient(app)


# --- Test Fixtures ---
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
    return Auth0UserFactory.build(
        app_metadata=AppMetadata(
            groups=[Group(name="Australian University", id="AU")],
            services=[
                Service(
                    id="service1",
                    name="Service 1",
                    status="approved",
                    last_updated=datetime.now(),
                    updated_by="test@example.com",
                    resources=[
                        Resource(id="resource1", name="Resource 1", status="approved"),
                        Resource(id="resource2", name="Resource 2", status="pending"),
                    ],
                ),
                Service(
                    id="service2",
                    name="Service 2",
                    status="pending",
                    last_updated=datetime.now(),
                    updated_by="test@example.com",
                    resources=[
                        Resource(id="resource3", name="Resource 3", status="pending")
                    ],
                ),
            ],
        ),
    )


# --- Authentication Tests (GET) ---
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


# --- Service Endpoints (GET) ---
def test_get_all_services(
    mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all services"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200

    expected_services = [
        s.model_dump(mode="json") for s in mock_user_data.app_metadata.services
    ]
    assert response.json() == {"services": expected_services}


def test_get_approved_services(
    mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting approved services"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services/approved", headers=auth_headers)
    assert response.status_code == 200

    approved_services = [
        s.model_dump(mode="json")
        for s in mock_user_data.app_metadata.services
        if s.status == "approved"
    ]
    assert response.json() == {"approved_services": approved_services}


def test_get_pending_services(
    mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting pending services"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services/pending", headers=auth_headers)
    assert response.status_code == 200

    pending_services = [
        s.model_dump(mode="json")
        for s in mock_user_data.app_metadata.services
        if s.status == "pending"
    ]
    assert response.json() == {"pending_services": pending_services}


def test_get_services_failed_fetch(
    mock_auth_token, auth_headers, mocker
):
    """Test handling of failed API calls"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        side_effect=HTTPException(status_code=403, detail="Failed to fetch user data"),
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Failed to fetch user data"}


def test_get_services_empty_metadata(
    mock_auth_token, auth_headers, mocker
):
    """Test handling of empty metadata"""
    empty_user = Auth0UserFactory.build(
        app_metadata=AppMetadata(services=[], groups=[]),
    )
    mocker.patch("routers.user.get_user_data", return_value=empty_user)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


def test_get_services_no_metadata(
    mock_auth_token, auth_headers, mocker
):
    """Test handling of missing metadata"""
    no_metadata_user = Auth0UserFactory.build(app_metadata=AppMetadata())
    mocker.patch("routers.user.get_user_data", return_value=no_metadata_user)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/services", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


# --- Resource Endpoints (GET) ---
def test_get_all_resources(
    mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting all resources"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 200
    all_resources = [
        r.model_dump()
        for s in mock_user_data.app_metadata.services
        for r in s.resources
    ]
    assert response.json() == {"resources": all_resources}


def test_get_approved_resources(
    mock_auth_token, auth_headers, mock_user_data, mocker
):
    """Test getting approved resources"""
    mocker.patch(
        "routers.user.get_user_data",  # Changed from fetch_user_data
        return_value=mock_user_data,
    )
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources/approved", headers=auth_headers)
    assert response.status_code == 200
    approved_resources = [
        r.model_dump()
        for s in mock_user_data.app_metadata.services
        for r in s.resources
        if r.status == "approved"
    ]
    assert response.json() == {"approved_resources": approved_resources}


def test_get_resources_empty_metadata(
    mock_auth_token, auth_headers, mocker
):
    """Test handling of empty resource metadata"""
    empty_user = Auth0UserFactory.build(app_metadata=AppMetadata(services=[], groups=[]),
    )
    mocker.patch("routers.user.get_user_data", return_value=empty_user)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"resources": []}


def test_get_resources_no_metadata(
    mock_auth_token, auth_headers, mocker
):
    """Test handling of missing resource metadata"""
    no_metadata_user = Auth0UserFactory.build(app_metadata=AppMetadata())
    mocker.patch("routers.user.get_user_data", return_value=no_metadata_user)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    response = client.get("/me/resources", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"resources": []}


# --- Service Request Endpoints (POST) ---
def test_request_service_success(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test successful service request"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )
    mocker.patch("routers.user.update_user_metadata", return_value={})

    new_service = {
        "name": "New Service",
        "id": "service3",
        "user_id": mock_auth_token.sub,
    }

    response = test_client.post(
        "/me/request/service", json=new_service, headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Service request submitted successfully"
    assert response.json()["service"]["id"] == "service3"


def test_request_service_duplicate(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test duplicate service request"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    existing_service = {
        "name": "Service 1",
        "id": "service1",
        "user_id": mock_auth_token.sub,
    }

    response = test_client.post(
        "/me/request/service", json=existing_service, headers=auth_headers
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"] == "Service request with ID service1 already exists"
    )


def test_request_service_user_mismatch(
    mock_auth_token, auth_headers, mock_user_data,
        test_client
):
    """Test service request with mismatched user"""
    request_payload = {
        "name": "Service Mismatch",
        "id": "svc-mismatch",
        "user_id": "auth0|WRONG_USER",
    }

    response = test_client.post(
        "/me/request/service", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "User ID in request does not match authenticated user"
    )


# --- Resource Request Endpoints (POST) ---
def test_request_resource_success(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test successful resource request"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
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

    response = test_client.post(
        "/me/request/service1/resource-new", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["resource"]["id"] == "resource-new"


def test_request_resource_user_mismatch(
    mock_auth_token, auth_headers, mock_user_data,
        test_client
):
    """Test resource request with mismatched user"""
    request_payload = {
        "name": "Invalid Resource",
        "id": "res-invalid",
        "user_id": "wrong-user",
        "service_id": "service1",
    }

    response = test_client.post(
        "/me/request/service1/res-invalid", json=request_payload, headers=auth_headers
    )
    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "User ID in request does not match authenticated user"
    )


def test_request_resource_non_approved_service(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test resource request for non-approved service"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    request_payload = {
        "name": "Blocked Resource",
        "id": "blocked-resource",
        "user_id": mock_auth_token.sub,
        "service_id": "service2",
    }

    response = test_client.post(
        "/me/request/service2/blocked-resource",
        json=request_payload,
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "Cannot request resources for a service that is not approved"
    )


def test_request_resource_duplicate(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test duplicate resource request"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    existing_resource = {
        "name": "Resource 1",
        "id": "resource1",
        "user_id": mock_auth_token.sub,
        "service_id": "service1",
    }

    response = test_client.post(
        "/me/request/service1/resource1", json=existing_resource, headers=auth_headers
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"] == "Resource request with ID resource1 already exists"
    )


def test_request_resource_invalid_service(
    mock_auth_token, auth_headers, mock_user_data, mocker,
        test_client
):
    """Test resource request for non-existent service"""
    mocker.patch("routers.user.get_user_data", return_value=mock_user_data)
    mocker.patch(
        "routers.user.get_management_token", return_value="mock_management_token"
    )

    request_payload = {
        "name": "Invalid Service Resource",
        "id": "resource-invalid",
        "user_id": mock_auth_token.sub,
        "service_id": "non-existent-service",
    }

    response = test_client.post(
        "/me/request/non-existent-service/resource-invalid",
        json=request_payload,
        headers=auth_headers,
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Service with ID non-existent-service not found"
