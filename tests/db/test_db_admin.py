import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from itsdangerous import URLSafeSerializer
from starlette.requests import Request

from db.admin import AdminAuth, DatabaseAdmin
from main import app


@pytest.fixture
def mock_request():
    """Create a mock request object"""
    request = Mock(spec=Request)
    request.session = {}
    request.url_for = Mock(return_value="http://test.com/login")
    return request


def create_signed_session_cookie(data: dict, secret_key: str) -> str:
    serializer = URLSafeSerializer(secret_key, salt="starlette.sessions")
    return serializer.dumps(data)


@pytest.fixture
def enable_db_admin(mocker, mock_settings):
    mocker.patch("db.admin.get_settings", return_value=mock_settings)
    dummy_oauth_client = mocker.Mock()
    mocker.patch("db.admin.setup_oauth", return_value=dummy_oauth_client)
    DatabaseAdmin.setup(app=app, secret_key="test-secret")
    yield


def test_admin_auth_authenticate_with_admin_role_returns_true(mock_settings):
    """Test that authenticate returns True when user has admin role"""
    mock_auth0_client = Mock()
    admin_auth = AdminAuth(secret_key="test-secret", auth0_client=mock_auth0_client)

    mock_request = Mock()
    mock_request.session = {"biocommons_roles": ["Admin"]}

    with patch("db.admin.get_settings", return_value=mock_settings):
        result = asyncio.run(admin_auth.authenticate(mock_request))

    assert result is True


def test_admin_auth_authenticate_no_roles_redirects_to_auth0(mock_settings):
    """Test that authenticate redirects to Auth0 when no roles in session"""
    mock_auth0_client = Mock()
    mock_auth0_client.authorize_redirect = AsyncMock()
    admin_auth = AdminAuth(secret_key="test-secret", auth0_client=mock_auth0_client)

    mock_request = Mock()
    mock_request.session = {}
    mock_request.url_for = Mock(return_value="http://test.com/login")

    with patch("db.admin.get_settings", return_value=mock_settings):
        asyncio.run(admin_auth.authenticate(mock_request))

    mock_auth0_client.authorize_redirect.assert_called_once_with(
        mock_request, mock_request.url_for.return_value
    )


def test_admin_auth_authenticate_empty_roles_list_redirects(mock_settings):
    """Test that authenticate redirects when roles list is empty"""
    mock_auth0_client = Mock()
    mock_auth0_client.authorize_redirect = AsyncMock(return_value="redirect_response")
    admin_auth = AdminAuth(secret_key="test-secret", auth0_client=mock_auth0_client)

    mock_request = Mock()
    mock_request.session = {"biocommons_roles": []}
    mock_request.url_for = Mock(return_value="http://test.com/login")

    with patch("db.admin.get_settings", return_value=mock_settings):
        result = asyncio.run(admin_auth.authenticate(mock_request))

    mock_auth0_client.authorize_redirect.assert_called_once()
    assert result == "redirect_response"


def test_admin_panel_access_with_valid_admin_session(test_client, mock_settings, test_db_engine):
    """Test that admin panel is accessible with valid admin session"""
    with patch("db.admin.get_settings", return_value=mock_settings), \
            patch("db.admin.setup_oauth") as mock_setup_oauth, \
            patch("db.admin.get_engine", return_value=test_db_engine):
        mock_oauth_client = Mock()
        mock_oauth_client.authorize_redirect = AsyncMock()
        mock_oauth_client.authorize_access_token = AsyncMock()
        mock_setup_oauth.return_value = mock_oauth_client

        DatabaseAdmin.setup(app=test_client.app, secret_key="test-secret")

        roles_data = {"biocommons_roles": ["Admin"]}
        cookie_value = create_signed_session_cookie(roles_data, "test-secret")
        test_client.cookies.set("session", cookie_value)

        resp = test_client.get('/db_admin/')
        assert resp.status_code == 200
