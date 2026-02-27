import importlib

from fastapi.testclient import TestClient

import main as main_module
from auth.management import get_management_token
from config import get_settings
from galaxy.config import get_galaxy_settings


def test_metrics_endpoint_disabled(test_client):
    response = test_client.get("/metrics")
    assert response.status_code == 404


def test_metrics_endpoint_enabled(monkeypatch, mock_settings, mock_galaxy_settings):
    monkeypatch.setenv("ENABLE_PROMETHEUS_METRICS", "1")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:4200")
    monkeypatch.setenv("RECAPTCHA_SECRET", "test-recaptcha-secret")
    monkeypatch.setattr("db.st_admin.setup_starlette_admin", lambda app: None)
    instrumented_main = importlib.reload(main_module)
    app = instrumented_main.app

    app.dependency_overrides[get_settings] = lambda: mock_settings
    app.dependency_overrides[get_galaxy_settings] = lambda: mock_galaxy_settings
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    try:
        with TestClient(app) as client:
            response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "http_requests_total" in response.text
    finally:
        app.dependency_overrides.clear()
        monkeypatch.delenv("ENABLE_PROMETHEUS_METRICS", raising=False)
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
        monkeypatch.delenv("RECAPTCHA_SECRET", raising=False)
        importlib.reload(main_module)
