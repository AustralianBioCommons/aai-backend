from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, StaticPool, create_engine

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import get_current_user
from auth0.client import Auth0Client
from db.core import BaseModel
from db.setup import get_db_session
from galaxy.client import GalaxyClient, get_galaxy_client
from galaxy.config import GalaxySettings, get_galaxy_settings
from main import app
from tests.datagen import AccessTokenPayloadFactory, SessionUserFactory


@pytest.fixture()
def test_db_engine():
    from db import models  # noqa: F401
    engine = create_engine(
        # Use in-memory DB by default
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    BaseModel.metadata.create_all(engine)
    return engine


@pytest.fixture(name="session")
def session_fixture(test_db_engine):
    with Session(test_db_engine) as session:
        yield session


@pytest.fixture(autouse=True)
def use_test_db():
    """
    Ensure we always use the test database
    """
    def get_db_session_override():
        from db import models  # noqa: F401
        engine = create_engine(
            # Use in-memory DB by default
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        BaseModel.metadata.create_all(engine)
        with Session(engine) as session:
            yield session
    app.dependency_overrides[get_db_session] = get_db_session_override
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def ignore_env_file():
    """
    Always ignore the .env file when running tests,
    so we get the same behaviour when the .env file is present or not.
    """
    def get_settings_no_env_file():
        return Settings(_env_file=None)
    def get_galaxy_settings_no_env_file():
        return GalaxySettings(_env_file=None)
    app.dependency_overrides[get_settings] = get_settings_no_env_file
    app.dependency_overrides[get_galaxy_settings] = get_galaxy_settings_no_env_file


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
def mock_galaxy_settings():
    """Dummy settings values for GalaxySettings"""
    return GalaxySettings(galaxy_url="http://mock-url", galaxy_api_key="mock-key")


@pytest.fixture
def test_client(mock_settings, mock_galaxy_settings):
    """
    Override the get_settings dependency to return a mocked Settings object.
    """
    # Define override
    def override_settings():
        return mock_settings

    # Apply override
    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_galaxy_settings] = lambda: mock_galaxy_settings

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
        return SessionUserFactory.build(access_token=token)

    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_management_token] = lambda: "mock_token"
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def mock_galaxy_client():
    client = MagicMock(GalaxyClient)
    app.dependency_overrides[get_galaxy_client] = lambda: client
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def auth0_client():
    return Auth0Client(domain="example.auth0.com", management_token="dummy-token")
