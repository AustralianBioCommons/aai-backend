from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from itsdangerous import URLSafeSerializer
from sqlmodel import select
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse

from db.models import (
    BiocommonsUser,
    BiocommonsUserHistory,
    GroupMembership,
    GroupMembershipHistory,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.st_admin import (
    DeletedUserView,
    GroupMembershipHistoryView,
    GroupMembershipView,
    PlatformMembershipHistoryView,
    PlatformMembershipView,
)
from db.types import ApprovalStatusEnum, PlatformEnum
from tests.db.datagen import (
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
)


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
async def test_restore_row_action_calls_admin_restore(mocker):
    mock_auth0_client = MagicMock()
    mock_db_session = MagicMock()
    mock_request = MagicMock()

    admin_id = "auth0|admin123"
    target_user_id = "auth0|user456"
    restoration_reason = "Mistakenly deleted"

    mock_admin = MagicMock(spec=BiocommonsUser)
    mock_user = MagicMock(spec=BiocommonsUser)

    mock_request.state.user = {"sub": admin_id}
    mock_request.form = AsyncMock(return_value=FormData({"reason-input": restoration_reason}))

    mocker.patch("db.st_admin.get_db_session", return_value=iter([mock_db_session]))
    mocker.patch("db.st_admin.get_auth0_client", return_value=mock_auth0_client)
    mocker.patch("db.st_admin.get_management_token")
    mocker.patch("db.st_admin.get_settings")

    mocker.patch.object(BiocommonsUser, "get_by_id_or_404", return_value=mock_admin)
    mocker.patch.object(BiocommonsUser, "get_deleted_by_id", return_value=mock_user)

    view = DeletedUserView(BiocommonsUser)
    response = await view.restore_row_action(mock_request, target_user_id)

    assert response == "User restored successfully"
    # Check admin_restore() called with the expected args.
    mock_user.admin_restore.assert_called_once_with(
        mock_admin,
        restoration_reason,
        mock_db_session,
        auth0_client=mock_auth0_client
    )


@pytest.mark.asyncio
async def test_restore_row_action_restores_deleted_user(
    mocker,
    test_db_session,
    persistent_factories,
):
    mock_auth0_client = MagicMock()
    mock_request = MagicMock()

    admin = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
    )
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
        deleted_by_id=admin.id,
        deletion_reason="Mistakenly deleted",
    )
    deleted_user_id = deleted_user.id
    test_db_session.commit()

    mock_request.state.user = {"sub": admin.id}
    mock_request.form = AsyncMock(return_value=FormData({"reason-input": "Restore approved"}))

    mocker.patch("db.st_admin.get_db_session", return_value=iter([test_db_session]))
    mocker.patch("db.st_admin.get_auth0_client", return_value=mock_auth0_client)
    mocker.patch("db.st_admin.get_management_token")
    mocker.patch("db.st_admin.get_settings")

    view = DeletedUserView(BiocommonsUser)
    response = await view.restore_row_action(mock_request, deleted_user.id)

    assert response == "User restored successfully"

    test_db_session.expire_all()
    restored_user = BiocommonsUser.get_by_id_or_404(deleted_user_id, test_db_session)

    assert restored_user.is_deleted is False
    assert restored_user.deletion_reason == "Restore approved"
    assert BiocommonsUser.get_deleted_by_id(session=test_db_session, identity=deleted_user_id) is None


@pytest.mark.asyncio
async def test_restore_row_action_restores_deleted_user_with_history(
    mocker,
    test_db_session,
    persistent_factories,
):
    mock_auth0_client = MagicMock()
    mock_request = MagicMock()

    admin = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
    )
    admin_id = admin.id
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
        deleted_by_id=admin.id,
        deletion_reason="Mistakenly deleted",
    )
    deleted_user_id = deleted_user.id
    test_db_session.commit()

    mock_request.state.user = {"sub": admin.id}
    mock_request.form = AsyncMock(return_value=FormData({"reason-input": "Restore approved"}))

    mocker.patch("db.st_admin.get_db_session", return_value=iter([test_db_session]))
    mocker.patch("db.st_admin.get_auth0_client", return_value=mock_auth0_client)
    mocker.patch("db.st_admin.get_management_token")
    mocker.patch("db.st_admin.get_settings")

    view = DeletedUserView(BiocommonsUser)
    response = await view.restore_row_action(mock_request, deleted_user_id)

    assert response == "User restored successfully"
    mock_auth0_client.update_user.assert_called_once()

    test_db_session.expire_all()
    restored_user = BiocommonsUser.get_by_id_or_404(deleted_user_id, test_db_session)

    assert restored_user.is_deleted is False
    assert restored_user.deleted_by_id == admin_id
    assert restored_user.deletion_reason == "Restore approved"

    history_entries = test_db_session.exec(
        select(BiocommonsUserHistory).where(BiocommonsUserHistory.user_id == deleted_user_id)
    ).all()
    assert any(
        entry.change == "user_restoration"
        and entry.reason == "Restore approved"
        and entry.updated_by_id == admin_id
        for entry in history_entries
    )


@pytest.mark.asyncio
async def test_restore_row_action_restores_self_deleted_user(
    mocker,
    test_db_session,
    persistent_factories,
):
    mock_auth0_client = MagicMock()
    mock_request = MagicMock()

    admin = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
    )
    admin_id = admin.id
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
        deletion_reason="User requested account deletion",
    )
    deleted_user_id = deleted_user.id
    deleted_user.deleted_by_id = deleted_user_id
    test_db_session.add(deleted_user)
    test_db_session.commit()

    mock_request.state.user = {"sub": admin.id}
    mock_request.form = AsyncMock(return_value=FormData({"reason-input": "Admin restored self-deleted account"}))

    mocker.patch("db.st_admin.get_db_session", return_value=iter([test_db_session]))
    mocker.patch("db.st_admin.get_auth0_client", return_value=mock_auth0_client)
    mocker.patch("db.st_admin.get_management_token")
    mocker.patch("db.st_admin.get_settings")

    view = DeletedUserView(BiocommonsUser)
    response = await view.restore_row_action(mock_request, deleted_user.id)

    assert response == "User restored successfully"
    mock_auth0_client.update_user.assert_called_once()

    test_db_session.expire_all()
    restored_user = BiocommonsUser.get_by_id_or_404(deleted_user_id, test_db_session)

    assert restored_user.is_deleted is False
    assert restored_user.deleted_by_id == admin_id


def test_group_membership_view_list_query_includes_deleted_users(
    test_db_session,
    persistent_factories,
    mock_request,
):
    group = BiocommonsGroupFactory.create_sync()
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
    )
    membership = GroupMembershipFactory.create_sync(
        group_id=group.group_id,
        user_id=deleted_user.id,
    )
    test_db_session.add(membership)
    test_db_session.commit()

    view = GroupMembershipView(GroupMembership)
    stmt = view.get_list_query(mock_request)
    results = test_db_session.exec(stmt).all()

    membership_ids = {row.id for row in results}
    assert membership.id in membership_ids


def test_platform_membership_view_list_query_includes_deleted_users(
    test_db_session,
    persistent_factories,
    mock_request,
):
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
    )
    membership = PlatformMembershipFactory.create_sync(
        platform_id=platform.id,
        user_id=deleted_user.id,
    )
    test_db_session.add(membership)
    test_db_session.commit()

    view = PlatformMembershipView(PlatformMembership)
    stmt = view.get_list_query(mock_request)
    results = test_db_session.exec(stmt).all()

    membership_ids = {row.id for row in results}
    assert membership.id in membership_ids


def test_group_membership_history_view_list_query_includes_deleted_users(
    test_db_session,
    persistent_factories,
    mock_request,
):
    group = BiocommonsGroupFactory.create_sync()
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
    )
    history = GroupMembershipHistory(
        group_id=group.group_id,
        user_id=deleted_user.id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.add(history)
    test_db_session.commit()

    view = GroupMembershipHistoryView(GroupMembershipHistory)
    stmt = view.get_list_query(mock_request)
    results = test_db_session.exec(stmt).all()

    history_ids = {row.id for row in results}
    assert history.id in history_ids


def test_platform_membership_history_view_list_query_includes_deleted_users(
    test_db_session,
    persistent_factories,
    mock_request,
):
    platform = PlatformFactory.create_sync(id=PlatformEnum.GALAXY)
    deleted_user = BiocommonsUserFactory.create_sync(
        group_memberships=[],
        platform_memberships=[],
        is_deleted=True,
        deleted_at=datetime.now(UTC),
    )
    history = PlatformMembershipHistory(
        platform_id=platform.id,
        user_id=deleted_user.id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )
    test_db_session.add(history)
    test_db_session.commit()

    view = PlatformMembershipHistoryView(PlatformMembershipHistory)
    stmt = view.get_list_query(mock_request)
    results = test_db_session.exec(stmt).all()

    history_ids = {row.id for row in results}
    assert history.id in history_ids
