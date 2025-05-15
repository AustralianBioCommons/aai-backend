from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

def test_get_users_with_filter():
    response = client.get("/users/?email=test@example.com")
    assert response.status_code in [200, 404]  # Depending on data presence

def test_get_user_by_id_not_found():
    response = client.get("/users/999999")
    assert response.status_code == 404

def test_put_user_not_found():
    response = client.put("/users/999999", json={"email": "new@example.com"})
    assert response.status_code in [404, 422]

def test_delete_user_not_found():
    response = client.delete("/users/999999")
    assert response.status_code in [404, 422]
