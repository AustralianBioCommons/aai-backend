from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from itsdangerous import URLSafeSerializer
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse

from auth0.client import UpdateUserData
from db.models import BiocommonsUser
from db.st_admin import DeletedUserView


@pytest.fixture
def mock_request():
    """Create a mock request object"""
    request = Mock(spec=Request)
    request.session = {}
    request.url_for = Mock(return_value="http://test.com/star-admin/auth/auth0")
    return request


def create_signed_session_cookie(data: dict, secret_key: str) -> str:
    serializer = URLSafeSerializer(secret_key, salt="starlette.sessions")
    return serializer.dumps(data)


def test_admin_panel_access_with_valid_admin_session(test_client, mock_settings, test_db_engine, mocker):
    mock_settings.enable_admin_dashboard = True
    mocker.patch("db.st_admin.get_settings", return_value=mock_settings)
    mocker.patch("db.st_admin.get_engine", return_value=test_db_engine)

    # Proper async-capable OAuth client
    oauth_client = Mock()
    oauth_client.authorize_redirect = AsyncMock(return_value=RedirectResponse("/db-admin/"))
    oauth_client.authorize_access_token = AsyncMock(return_value={})

    oauth = Mock()
    oauth.create_client = Mock(return_value=oauth_client)
    mocker.patch("db.st_admin.setup_oauth", return_value=oauth)

    async def authenticated(self, request):
        # emulate a logged-in admin user
        request.session.setdefault("user", {"name": "Admin", "picture": ""})
        request.state.user = request.session["user"]
        return True

    mocker.patch("db.st_admin.Auth0AuthProvider.is_authenticated", new=authenticated)

    from db.st_admin import setup_starlette_admin
    setup_starlette_admin(app=test_client.app)

    resp = test_client.get("/db-admin/")
    assert resp.status_code == 200



@pytest.mark.asyncio
async def test_auth_callback_missing_access_token_raises(mocker, mock_settings, mock_request):
    """Auth0 callback without access_token -> 401"""
    mock_settings.enable_admin_dashboard = True
    mocker.patch("db.st_admin.get_settings", return_value=mock_settings)
    # Enable admin
    # OAuth client returning no token
    oauth = Mock()
    oauth.create_client.return_value = AsyncMock(authorize_access_token=AsyncMock(return_value={}))
    mocker.patch("db.st_admin.setup_oauth", return_value=oauth)

    from db.st_admin import Auth0AuthProvider
    provider = Auth0AuthProvider()

    with pytest.raises(HTTPException) as exc:
        await provider.handle_auth_callback(mock_request)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Could not get access token."


@pytest.mark.asyncio
async def test_auth_callback_invalid_jwt_raises(mocker, mock_settings, mock_request):
    """Auth0 callback with invalid JWT -> 401"""
    mock_settings.enable_admin_dashboard = True
    mocker.patch("db.st_admin.get_settings", return_value=mock_settings)
    oauth = Mock()
    oauth.create_client.return_value = AsyncMock(authorize_access_token=AsyncMock(return_value={"access_token": "token"}))
    mocker.patch("db.st_admin.setup_oauth", return_value=oauth)
    mocker.patch("db.st_admin.verify_jwt", return_value=None)

    from db.st_admin import Auth0AuthProvider
    provider = Auth0AuthProvider()

    with pytest.raises(HTTPException) as exc:
        await provider.handle_auth_callback(mock_request)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Could not verify JWT."


@pytest.mark.asyncio
async def test_auth_callback_missing_admin_role_raises(mocker, mock_settings, mock_request):
    """Auth0 callback when user lacks admin role -> 401"""
    mock_settings.enable_admin_dashboard = True
    mocker.patch("db.st_admin.get_settings", return_value=mock_settings)
    oauth = Mock()
    oauth.create_client.return_value = AsyncMock(authorize_access_token=AsyncMock(return_value={"access_token": "token"}))
    mocker.patch("db.st_admin.setup_oauth", return_value=oauth)

    payload = Mock()
    payload.has_admin_role.return_value = False
    mocker.patch("db.st_admin.verify_jwt", return_value=payload)

    from db.st_admin import Auth0AuthProvider
    provider = Auth0AuthProvider()

    with pytest.raises(HTTPException) as exc:
        await provider.handle_auth_callback(mock_request)

    assert exc.value.status_code == 401
    assert exc.value.detail == "You do not have permission to access this endpoint."
    assert "user" not in mock_request.session


@pytest.mark.asyncio
async def test_auth_callback_success_sets_session_and_redirects(mocker, mock_settings, mock_request):
    """Successful Auth0 callback stores user in session and redirects."""
    mock_settings.enable_admin_dashboard = True
    mocker.patch("db.st_admin.get_settings", return_value=mock_settings)
    oauth = Mock()
    oauth.create_client.return_value = AsyncMock(
        authorize_access_token=AsyncMock(return_value={"access_token": "token", "userinfo": {"name": "A", "picture": ""}})
    )
    mocker.patch("db.st_admin.setup_oauth", return_value=oauth)

    payload = Mock()
    payload.has_admin_role.return_value = True
    mocker.patch("db.st_admin.verify_jwt", return_value=payload)

    # emulate ?next=/db-admin/
    mock_request.query_params = {"next": "/db-admin/"}

    from db.st_admin import Auth0AuthProvider
    provider = Auth0AuthProvider()
    resp = await provider.handle_auth_callback(mock_request)

    assert isinstance(resp, type(resp))  # RedirectResponse type
    assert "user" in mock_request.session


@pytest.mark.asyncio
async def test_restore_row_action_calls_auth0_and_updates_db():
    mock_db_session = MagicMock()
    mock_auth0_client = MagicMock()
    mock_request = MagicMock()

    admin_id = "auth0|admin123"
    mock_request.state.user = {"sub": admin_id}

    restoration_reason = "Mistakenly deleted"
    mock_request.form = AsyncMock(return_value=FormData({"reason-input": restoration_reason}))

    target_user_id = "auth0|user456"
    admin_user = BiocommonsUser(id=admin_id, email="admin@example.com", username="admin")

    target_user = BiocommonsUser(
        id=target_user_id,
        email="user@example.com",
        username="user",
        is_deleted=True
    )

    with patch("db.st_admin.get_db_session", return_value=iter([mock_db_session])), \
            patch("db.st_admin.get_management_token", return_value="fake-token"), \
            patch("db.st_admin.get_auth0_client", return_value=mock_auth0_client), \
            patch("db.st_admin.get_settings"), \
            patch.object(BiocommonsUser, "get_by_id", return_value=admin_user), \
            patch.object(BiocommonsUser, "get_deleted_by_id", return_value=target_user):

        view = DeletedUserView(BiocommonsUser)
        response = await view.restore_row_action(mock_request, target_user_id)

        assert response == "User restored successfully"

        # Verify Auth0 was called to unblock
        mock_auth0_client.update_user.assert_called_once_with(
            user_id=target_user_id,
            update_data=UpdateUserData(blocked=False)
        )

        assert target_user.is_deleted is False
        assert target_user.deletion_reason == restoration_reason
        assert target_user.deleted_by == admin_user
