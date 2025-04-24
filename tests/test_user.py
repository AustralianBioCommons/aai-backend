import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException

from main import app


client = TestClient(app)


@pytest.fixture
def mock_user():
    return {
        "sub": "auth0|123456789",
        "biocommons.org.au/roles": ["user"]
    }


@pytest.fixture
def mock_user_data():
    return {
        "app_metadata": {
            "services": [
                {
                    "name": "Service 1",
                    "status": "approved",
                    "resources": [{"name": "Resource 1", "status": "approved", "id": "res1"}]
                },
                {
                    "name": "Service 2",
                    "status": "pending",
                    "resources": [{"name": "Resource 2", "status": "pending", "id": "res2"}]
                }
            ]
        }
    }


@pytest.fixture(autouse=True)
def mock_dependencies(mocker, mock_user):
    mocker.patch(
        "auth.validator.verify_jwt",
        return_value={
            "sub": "auth0|123456789",
            "biocommons.org.au/roles": ["user"]
        }
    )
    
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    
    async def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            
            def json(self):
                return mock_user_data()
            
            def raise_for_status(self):
                pass
        
        return MockResponse()
    
    mocker.patch("httpx.AsyncClient.get", side_effect=mock_get)


# Authentication tests
@pytest.mark.parametrize("endpoint", [
    "/me/services",
    "/me/services/approved",
    "/me/services/pending",
    "/me/resources",
    "/me/resources/approved",
    "/me/resources/pending",
    "/me/all/pending"
])
def test_endpoints_require_auth(endpoint):
    """Test that all endpoints require authentication."""
    response = client.get(endpoint)
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


# Service endpoint tests
def test_get_all_services(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"services": mock_user_data["app_metadata"]["services"]}


def test_get_approved_services(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services/approved", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "approved_services": [
            {"name": "Service 1", "status": "approved", "resources": [{"name": "Resource 1", "status": "approved", "id": "res1"}]}
        ]
    }


def test_get_pending_services(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services/pending", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "pending_services": [
            {"name": "Service 2", "status": "pending", "resources": [{"name": "Resource 2", "status": "pending", "id": "res2"}]}
        ]
    }


# Resource endpoint tests
def test_get_all_resources(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/resources", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "resources": [
            {"name": "Resource 1", "status": "approved", "id": "res1"},
            {"name": "Resource 2", "status": "pending", "id": "res2"}
        ]
    }


def test_get_approved_resources(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/resources/approved", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "approved_resources": [
            {"name": "Resource 1", "status": "approved", "id": "res1"}
        ]
    }


def test_get_pending_resources(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/resources/pending", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "pending_resources": [
            {"name": "Resource 2", "status": "pending", "id": "res2"}
        ]
    }


# Combined endpoint tests
def test_get_all_pending(mocker, mock_user_data):
    mocker.patch("routers.user.fetch_user_data", return_value=mock_user_data)
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/all/pending", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "pending_services": [
            {"name": "Service 2", "status": "pending", "resources": [{"name": "Resource 2", "status": "pending", "id": "res2"}]}
        ],
        "pending_resources": [
            {"name": "Resource 2", "status": "pending", "id": "res2"}
        ]
    }


# Error handling tests
def test_get_services_unauthorized():
    response = client.get("/me/services")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_get_services_failed_fetch(mocker):
    mocker.patch(
        "routers.user.fetch_user_data",
        side_effect=HTTPException(status_code=500, detail="Failed to fetch user data")
    )
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services", headers=headers)
    assert response.status_code == 500
    assert response.json() == {"detail": "Failed to fetch user data"}


def test_get_services_empty_metadata(mocker):
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value={"app_metadata": {}}
    )
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}


def test_get_services_no_metadata(mocker):
    mocker.patch(
        "routers.user.fetch_user_data",
        return_value={}
    )
    headers = {"Authorization": "Bearer mock_token"}
    response = client.get("/me/services", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"services": []}