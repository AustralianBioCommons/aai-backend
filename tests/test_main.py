from fastapi import HTTPException
from fastapi.testclient import TestClient

from auth.config import Settings
from main import app


client = TestClient(app)


def test_public():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Public route"}


def test_private_valid_admin_token(mocker):
    mocker.patch(
        "auth.config.get_settings",
        return_value=Settings(
            auth0_domain="mock-domain",
            auth0_audience="mock-audience",
            auth0_management_id="mock-id",
            auth0_management_secret="mock-secret",
            auth0_algorithms=["RS256"]
        )
    )

    mock_user_claims = {
        "sub": "auth0|123456789",
        "biocommons.org.au/roles": ["admin"]
    }
    mocker.patch(
        "auth.validator.verify_jwt",
        return_value=mock_user_claims
    )

    mock_token = "mock_management_token"
    mocker.patch(
        "main.get_management_token",
        return_value=mock_token
    )

    headers = {"Authorization": "Bearer valid_token"}
    response = client.get("/private", headers=headers)
    
    assert response.status_code == 200
    
    response_data = response.json()
    assert "message" in response_data
    assert "user_claims" in response_data
    assert "management_token" in response_data
    
    assert response_data["message"] == "Private route"
    assert response_data["user_claims"] == mock_user_claims
    

    assert isinstance(response_data["management_token"], str)
    assert response_data["management_token"] == mock_token


def test_private_missing_token():
    response = client.get("/private")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_private_invalid_token(mocker):
    mocker.patch(
        "auth.validator.verify_jwt",
        side_effect=HTTPException(status_code=401, detail="Invalid token: Error decoding token headers.")
    )

    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token: Error decoding token headers."}


def test_private_non_admin_token(mocker):
    mocker.patch(
        "auth.validator.verify_jwt",
        side_effect=HTTPException(
            status_code=403,
            detail="Access denied: Admin privileges required"
        )
    )
    headers = {"Authorization": "Bearer non_admin_token"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied: Admin privileges required"}


def test_private_missing_roles(mocker):
    mocker.patch(
        "auth.validator.verify_jwt",
        side_effect=HTTPException(
            status_code=403,
            detail="Missing required claim: biocommons.org.au/roles"
        )
    )
    headers = {"Authorization": "Bearer token_without_roles"}
    response = client.get("/private", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing required claim: biocommons.org.au/roles"}
