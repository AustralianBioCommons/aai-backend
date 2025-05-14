import pytest
from fastapi.testclient import TestClient

from auth.config import Settings, get_settings
from main import app


@pytest.fixture
def client_with_settings_override():
    # Define override
    def override_settings():
        return Settings(
            auth0_domain="mock-domain",
            auth0_management_id="mock-id",
            auth0_management_secret="mock-secret",
            auth0_audience="mock-audience",
            jwt_secret_key="mock-secret-key",
            cors_allowed_origins=["http://test"],
            auth0_algorithms=["HS256"]
        )

    # Apply override
    app.dependency_overrides[get_settings] = override_settings

    # Create client
    client = TestClient(app)
    yield client

    # Reset override
    app.dependency_overrides.clear()