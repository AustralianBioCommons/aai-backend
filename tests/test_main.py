from fastapi import HTTPException
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_public():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Public route"}

def test_private_valid_token(mocker):
    mocker.patch("main.verify_jwt", return_value={
        "sub": "auth0|123456789",
        "biocommons.org.au/roles": ["acdc/indexd_admin"]
    })
    mocker.patch("main.get_management_token", return_value="mock_management_token")
    headers = {"Authorization": "Bearer valid_token"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "message": "Private route",
        "user_claims": {
            "sub": "auth0|123456789",
            "biocommons.org.au/roles": ["acdc/indexd_admin"]
        },
        "management_token": "mock_management_token"
    }

def test_private_missing_token():
    response = client.get("/private")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

def test_private_invalid_token(mocker):
    mocker.patch("auth.validator.verify_jwt", side_effect=Exception("Invalid token: Error decoding token headers."))
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token: Error decoding token headers."}

def test_private_insufficient_permissions(mocker):
    mocker.patch("main.verify_jwt", side_effect=HTTPException(
        status_code=403, detail="Access denied: Insufficient permissions"
    ))
    headers = {"Authorization": "Bearer insufficient_permissions_token"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied: Insufficient permissions"}
