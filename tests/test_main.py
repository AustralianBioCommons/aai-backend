from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_public():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Public route"}
