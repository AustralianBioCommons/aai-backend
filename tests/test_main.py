from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_root(client_with_settings_override):
    response = client_with_settings_override.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "AAI Backend API"}
