import pytest
from fastapi.testclient import TestClient

from auth.config import Settings, get_settings
from auth.validator import get_current_user
from main import app
from tests.datagen import AccessTokenPayloadFactory, UserFactory


def pytest_configure(config: pytest.Config) -> None:
    """
    Force the app to ignore the .env file while testing.
    Otherwise we get different results when the .env
    file is present or not.
    """
    Settings.model_config["env_file"] = ""


@pytest.fixture
def mock_settings():
    """Fixture that returns mocked Settings object."""
    return Settings(
        auth0_domain="mock-domain",
        auth0_management_id="mock-id",
        auth0_management_secret="mock-secret",
        auth0_audience="mock-audience",
        jwt_secret_key="mock-secret-key",
        cors_allowed_origins="https://test",
        admin_roles=["Admin"],
        auth0_algorithms=["HS256"]
    )

@pytest.fixture
def test_client(mock_settings):
    """
    Override the get_settings dependency to return a mocked Settings object.
    """
    # Define override
    def override_settings():
        return mock_settings

    # Apply override
    app.dependency_overrides[get_settings] = override_settings

    # Create client
    client = TestClient(app)
    yield client

    # Reset override
    app.dependency_overrides.clear()


@pytest.fixture
def as_admin_user():
    """
    Override the get_current_user dependency to return a User object with admin role,
    so admin check will pass.
    """
    def override_user():
        token = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
        return UserFactory.build(access_token=token)
    app.dependency_overrides[get_current_user] = override_user
    yield
    app.dependency_overrides.clear()
