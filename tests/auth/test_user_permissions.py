from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from auth.user_permissions import get_db_user, get_db_user_or_404


def test_get_db_user_or_404_missing_user():
    app = FastAPI()
    app.dependency_overrides[get_db_user] = lambda: None

    @app.get("/dummy", dependencies=[Depends(get_db_user_or_404)])
    def dummy_endpoint():
        return {"result": "ok"}

    with TestClient(app) as client:
        response = client.get("/dummy")

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}
