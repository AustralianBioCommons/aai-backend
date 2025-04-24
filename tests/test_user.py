import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from routers.user import router
from main import app

client = TestClient(app)

@pytest.fixture
def mock_user():
    return {"sub": "auth0|123456789"}

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
    mocker.patch("auth.validator.get_current_user", return_value=mock_user)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    mocker.patch("auth.validator.verify_jwt", return_value={
        "sub": "auth0|123456789",
        "biocommons.org.au/roles": ["user"]
    })

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