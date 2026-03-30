import importlib

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_root(test_client):
    response = test_client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "AAI Backend API"
    assert response.json().keys() == {"message", "version"}


def _reload_main_with_environment(monkeypatch, environment: str):
    monkeypatch.setenv("ENVIRONMENT", environment)

    import main
    importlib.reload(main)
    return main


def test_sbp_router_not_mounted_in_production(monkeypatch):
    main = _reload_main_with_environment(monkeypatch, "prod")

    paths = {route.path for route in main.app.routes}
    assert "/sbp/register" not in paths


def test_sbp_router_mounted_in_non_production(monkeypatch):
    main = _reload_main_with_environment(monkeypatch, "dev")

    paths = {route.path for route in main.app.routes}
    assert "/sbp/register" in paths
