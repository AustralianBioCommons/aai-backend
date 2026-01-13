import base64
import logging
from typing import Any, Optional

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI
from sqlalchemy import Select
from sqlmodel import select
from starlette.datastructures import URL, FormData
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route
from starlette_admin import BaseAdmin, EnumField, HasMany, HasOne, row_action
from starlette_admin.auth import AdminUser, AuthProvider, login_not_required
from starlette_admin.contrib.sqlmodel import Admin, ModelView

from auth.management import get_management_token
from auth.validator import verify_jwt
from auth0.client import get_auth0_client
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    EmailChangeOtp,
    EmailNotification,
    GroupMembership,
    GroupMembershipHistory,
    Platform,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.setup import get_db_session, get_engine
from db.types import PlatformEnum

logger = logging.getLogger('uvicorn.error')


class DefaultView(ModelView):
    def can_create(self, request: Request) -> bool:
        return False

    def can_delete(self, request: Request) -> bool:
        return False

    def can_edit(self, request: Request) -> bool:
        return False


class UserView(DefaultView):
    fields = ["email", "email_verified", "username", "created_at", "id"]

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.email


class DeletedUserView(UserView):
    fields = ["email", "username", "deleted_at", HasOne("deleted_by", identity="user"), "deletion_reason"]

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.email

    def get_details_query(self, request: Request) -> Select:
        return select(self.model).execution_options(include_deleted=True).where(BiocommonsUser.is_deleted.is_(True))

    def get_list_query(self, request: Request) -> Select:
        return select(self.model).execution_options(include_deleted=True).where(BiocommonsUser.is_deleted.is_(True))

    @row_action(
        name="restore_user",
        text="Restore User",
        confirmation="Are you sure you want to restore this user?",
        icon_class="fa fa-trash-restore",
        submit_btn_text="Restore",
        submit_btn_class="btn btn-success",
        action_btn_class="btn btn-info",
        form="""
        <form>
            <div class="mt-3">
                <input type="text" class="form-control" name="reason-input" placeholder="Reason for restoration">
            </div>
        </form>
        """
    )
    async def restore_row_action(self, request: Request, pk: Any) -> Any:
        logger.info("Setting up Auth0 client")
        settings = get_settings()
        management_token = get_management_token(settings=settings)
        auth0_client = get_auth0_client(settings=settings, management_token=management_token)
        db_session_gen = get_db_session()
        db_session = next(db_session_gen)
        try:
            admin_id = request.state.user["sub"]
            admin = BiocommonsUser.get_by_id(admin_id, db_session)
            logger.info(f"Restoring user {pk}")
            user = BiocommonsUser.get_deleted_by_id(session=db_session, identity=pk)
            data: FormData = await request.form()
            reason = data.get("reason-input")
            user.admin_restore(admin, reason, db_session, auth0_client=auth0_client)
            return "User restored successfully"
        finally:
            db_session_gen.close()


class PlatformView(DefaultView):
    fields = [
        EnumField(name="id", choices=[(e.value, e.value) for e in PlatformEnum]),
        HasOne("platform_role", identity="role"),
        HasMany("admin_roles", identity="role"),
        "role_id",
        "name"
    ]

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.name


class RoleView(DefaultView):
    fields = ["id", "name", "description"]

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.name


class PlatformMembershipView(DefaultView):
    fields = [
        HasOne("platform", identity="platform"),
        HasOne("user", identity="user"),
        "approval_status",
        "id",
    ]

    async def repr(self, obj: Any, request: Request) -> str:
        return f"{obj.platform.name} ↔ {obj.user.email}"


class GroupView(DefaultView):
    fields = [
        "group_id",
        "name",
        "short_name",
        HasMany("admin_roles", identity="role"),
    ]
    row_actions = []
    pk_attr = "group_id"

    def _encode_pk(self, raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    def _decode_pk(self, token: str) -> str:
        pad = "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode((token + pad).encode()).decode()

    async def get_pk_value(self, request: Request, obj: Any) -> str:
        # obj.group_id may contain '/'
        return self._encode_pk(obj.group_id)

    async def find_by_pk(self, request: Request, pk: str) -> Any:
        raw_id = self._decode_pk(pk)
        stmt = select(self.model).where(self.model.group_id == raw_id)
        result = await request.state.session.run_sync(lambda s: s.exec(stmt).one_or_none())
        if result is None:
            raise self.not_found()
        return result

    async def get_serialized_pk_value(self, request: Request, obj: Any) -> str:
        return await self.get_pk_value(request, obj)

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.name


class GroupMembershipView(DefaultView):
    fields = [
        HasOne("group", identity="group"),
        HasOne("user", identity="user"),
        "approval_status",
        "id",
    ]


class PlatformMembershipHistoryView(DefaultView):
    fields = [
        "platform_id",
        HasOne("user", identity="user"),
        "approval_status",
        "updated_at",
        HasOne("updated_by", identity="user"),
        "id",
    ]


class GroupMembershipHistoryView(DefaultView):
    fields = [
        "group_id",
        HasOne("user", identity="user"),
        "approval_status",
        "updated_at",
        HasOne("updated_by", identity="user"),
        "id",
    ]


class EmailChangeOtpView(DefaultView):
    fields = ["target_email", "created_at", "expires_at", "is_active", "total_attempts"]
    fields_default_sort = [("created_at", True)]
    searchable_fields = ["target_email", "is_active"]


class EmailNotificationView(DefaultView):
    fields = [
        "to_address",
        "from_address",
        "subject",
        "status",
        "attempts",
        "send_after",
        "sent_at",
        "last_attempt_at",
        "created_at",
    ]
    fields_default_sort = [("created_at", True)]
    searchable_fields = ["to_address", "from_address", "status"]

    async def repr(self, obj: Any, request: Request) -> str:
        return obj.subject


def setup_starlette_admin(app: FastAPI):
    settings = get_settings()
    if not settings.enable_admin_dashboard:
        logger.info("Admin dashboard not enabled, skipping admin setup")
        return
    engine = get_engine()
    admin = Admin(
        engine,
        title="AAI Backend Admin",
        base_url="/db-admin",
        auth_provider=Auth0AuthProvider(),
        middlewares=[Middleware(SessionMiddleware, secret_key=settings.jwt_secret_key)]
    )
    admin.add_view(UserView(BiocommonsUser, identity="user", icon="fa fa-user"))
    admin.add_view(DeletedUserView(BiocommonsUser, identity="deleted_user", icon="fa fa-user-slash", name="Deleted Users", label="Deleted Users"))
    admin.add_view(PlatformView(Platform, identity="platform", icon="fa fa-server"))
    admin.add_view(PlatformMembershipView(PlatformMembership, identity="platform_membership", icon="fa fa-user-plus"))
    admin.add_view(GroupView(BiocommonsGroup, identity="group", icon="fa fa-users"))
    admin.add_view(GroupMembershipView(GroupMembership, identity="group_membership", icon="fa fa-user-plus"))
    admin.add_view(RoleView(Auth0Role, identity="role", icon="fa fa-user-tie"))
    admin.add_view(PlatformMembershipHistoryView(PlatformMembershipHistory, identity="platform_membership_history", icon="fa fa-clock-rotate-left"))
    admin.add_view(GroupMembershipHistoryView(GroupMembershipHistory, identity="group_membership_history", icon="fa fa-clock-rotate-left"))
    admin.add_view(EmailChangeOtpView(EmailChangeOtp, identity="email_change_otp", icon="fa fa-envelope"))
    admin.add_view(EmailNotificationView(EmailNotification, identity="email_notification", icon="fa fa-envelope-open-text"))
    admin.mount_to(app)


def setup_oauth():
    settings = get_settings()
    oauth = OAuth()
    oauth.register(
        name="auth0",
        client_id=settings.auth0_management_id,
        client_secret=settings.auth0_management_secret,
        server_metadata_url=f"{settings.auth0_custom_domain}/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid profile email",
        },
    )
    return oauth


class Auth0AuthProvider(AuthProvider):
    oauth: OAuth

    def __init__(self):
        super().__init__()
        self.oauth = setup_oauth()

    @login_not_required
    async def handle_auth_callback(self, request: Request):
        settings = get_settings()
        auth0 = self.oauth.create_client("auth0")
        token = await auth0.authorize_access_token(request)
        access_token = token.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Could not get access token.")
        payload = verify_jwt(access_token, settings)
        if not payload:
            raise HTTPException(status_code=401, detail="Could not verify JWT.")
        if not payload.has_admin_role(settings):
            raise HTTPException(
                status_code=401, detail="You do not have permission to access this endpoint."
            )
        request.session.update({"user": token["userinfo"]})
        return RedirectResponse("/db-admin/")

    async def is_authenticated(self, request: Request) -> bool:
        if request.session.get("user", None) is not None:
            request.state.user = request.session.get("user")
            return True
        return False

    async def render_login(self, request: Request, admin: BaseAdmin):
        """Override the default login behavior to implement custom logic."""
        auth0 = self.oauth.create_client("auth0")
        redirect_uri = request.url_for(
            admin.route_name + ":authorize_auth0"
        )
        return await auth0.authorize_redirect(request, str(redirect_uri))

    async def render_logout(self, request: Request, admin: BaseAdmin) -> Response:
        """Override the default logout to implement custom logic"""
        settings = get_settings()
        request.session.clear()
        return RedirectResponse(
            url=URL(f"{settings.auth0_custom_domain}/v2/logout").include_query_params(
                returnTo=request.url_for(admin.route_name + ":index"),
                client_id=settings.auth0_management_id,
            )
        )

    def setup_admin(self, admin: "BaseAdmin"):
        super().setup_admin(admin)
        """add custom authentication callback route"""
        admin.routes.append(
            Route(
                "/auth/auth0",
                self.handle_auth_callback,
                methods=["GET"],
                name="authorize_auth0",
            )
        )

    def get_admin_user(self, request: Request) -> Optional[AdminUser]:
        user = request.state.user
        if not user:
            return None
        return AdminUser(
            username=user["name"],
            photo_url=user["picture"],
        )
