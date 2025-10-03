from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_root(test_client):
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "AAI Backend API"
    assert response.json().keys() == {"message", "version"}
