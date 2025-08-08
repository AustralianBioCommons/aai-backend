import os
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from moto import mock_aws
from moto.core import patch_client
from sqlmodel import Session, StaticPool, create_engine

from auth.management import get_management_token
from auth.ses import EmailService, get_email_service
from auth.validator import get_current_user
from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.core import BaseModel
from db.setup import get_db_session
from galaxy.client import GalaxyClient, get_galaxy_client
from galaxy.config import GalaxySettings, get_galaxy_settings
from main import app
from tests.datagen import AccessTokenPayloadFactory, SessionUserFactory
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
)


@pytest.fixture(scope="function")
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
    connection = test_db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def test_db_session(session):
    """
    Override the get_db_session dependency to return the test DB.
    """
    def get_db_session_override():
        yield session
    app.dependency_overrides[get_db_session] = get_db_session_override
    yield session
    app.dependency_overrides.clear()
    session.close()


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
    # Make sure we always use in-memory DB for test DB
    os.environ.pop("DB_HOST", None)
    os.environ["DB_URL"] = "sqlite://"


@pytest.fixture
def mock_settings():
    """Fixture that returns mocked Settings object."""
    return Settings(
        auth0_domain="mock-domain",
        auth0_issuer=None,
        auth0_management_id="mock-id",
        auth0_management_secret="mock-secret",
        auth0_audience="mock-audience",
        jwt_secret_key="mock-secret-key",
        cors_allowed_origins="https://test",
        send_email=False,
        admin_roles=["Admin"],
        auth0_algorithms=["RS256"]
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
def test_client_with_email(mock_settings, mock_galaxy_settings):
    """
    Create a test client with email sending enabled.
    """
    mock_settings.send_email = True
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
def normal_user():
    """
    Non-admin user with no special privileges
    """
    token = AccessTokenPayloadFactory.build(biocommons_roles=[])
    return SessionUserFactory.build(access_token=token)


@pytest.fixture
def as_normal_user(normal_user):
    """
    Override the get_current_user dependency to return a normal user
    """
    def override_user():
        return normal_user

    app.dependency_overrides[get_current_user] = override_user
    yield
    app.dependency_overrides.clear()

@pytest.fixture
def admin_user():
    token = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    return SessionUserFactory.build(access_token=token)


@pytest.fixture
def as_admin_user(admin_user):
    """
    Override the get_current_user dependency to return a User object with admin role,
    so admin check will pass.
    """
    def override_user():
        return admin_user

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
    return Auth0Client(domain="auth0.example.com", management_token="dummy-token")


@pytest.fixture
def mock_auth0_client(mocker):
    mock_client = mocker.patch("auth0.client.Auth0Client")
    app.dependency_overrides[get_auth0_client] = lambda: mock_client
    yield mock_client
    app.dependency_overrides.clear()


@pytest.fixture
def persistent_factories(test_db_session):
    """
    Set the __session__ attribute of the factories to the test DB session
    """
    factories = [
        Auth0RoleFactory,
        BiocommonsGroupFactory,
        BiocommonsUserFactory,
        GroupMembershipFactory,
    ]
    for factory in factories:
        factory.__session__ = test_db_session
    yield
    for factory in factories:
        factory.__session__ = None

@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-2"


@pytest.fixture(scope="function")
def mock_email_service(aws_credentials):
    with mock_aws():
        email_service = EmailService(region_name="us-east-1")
        patch_client(email_service.client)
        email_service.client.verify_email_identity(EmailAddress="amanda@biocommons.org.au")
        app.dependency_overrides[get_email_service] = lambda: email_service
        yield email_service
        app.dependency_overrides.clear()
