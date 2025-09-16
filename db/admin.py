from typing import Self, Union

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from sqladmin.filters import AllUniqueStringValuesFilter
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from auth.validator import verify_jwt
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    GroupMembershipHistory,
    PlatformMembership,
    PlatformMembershipHistory,
)
from db.setup import get_engine


def setup_oauth():
    """
    Set up an OAuth client for Auth0.
    """
    settings = get_settings()
    oauth = OAuth()
    oauth.register(
        name="auth0",
        client_id=settings.auth0_management_id,
        client_secret=settings.auth0_management_secret,
        api_base_url=f"https://{settings.auth0_domain}",
        access_token_url=f"https://{settings.auth0_domain}/oauth/token",
        authorize_url=f"https://{settings.auth0_domain}/authorize",
        server_metadata_url=f"https://{settings.auth0_domain}/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid profile email",
            "audience": settings.auth0_audience,
        },
    )
    return oauth.create_client("auth0")


class AdminAuth(AuthenticationBackend):
    """
    Authentication backend for the Admin app.
    Checks that the user has an admin role before allowing access.
    """

    def __init__(self, secret_key: str, auth0_client: OAuth):
        super().__init__(secret_key=secret_key)
        self.auth0_client = auth0_client

    async def login(self, request: Request) -> bool:
        return True

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> Union[bool, RedirectResponse]:
        settings = get_settings()
        roles = request.session.get("biocommons_roles")
        if not roles:
            print("Redirecting to Auth0 for login.")
            redirect_uri = request.url_for("login_auth0")
            return await self.auth0_client.authorize_redirect(request, redirect_uri)
        for role in roles:
            if role in settings.admin_roles:
                return True
        return False


class BiocommonsUserAdmin(ModelView, model=BiocommonsUser):
    can_edit = False
    can_create = False
    can_delete = True
    column_list = ["id", "username", "email", "email_verified", "created_at"]
    column_default_sort = ("created_at", True)


class GroupAdmin(ModelView, model=BiocommonsGroup):
    can_edit = False
    can_create = False
    can_delete = False


class Auth0RoleAdmin(ModelView, model=Auth0Role):
    can_edit = False
    can_create = False
    can_delete = False
    column_list = ["id", "name", "description"]


class GroupMembershipAdmin(ModelView, model=GroupMembership):
    can_edit = False
    can_create = False
    can_delete = False
    column_list = [
        "name",
        "group_id",
        "user_email",
        "user_id",
        "approval_status",
        "updated_at",
        "updated_by_email",
    ]
    column_filters = [
        AllUniqueStringValuesFilter(GroupMembership.group_id),
        AllUniqueStringValuesFilter(GroupMembership.approval_status),
    ]


class GroupMembershipHistoryAdmin(ModelView, model=GroupMembershipHistory):
    can_edit = False
    can_create = False
    can_delete = False
    column_list = [
        "name",
        "group_id",
        "user_email",
        "user_id",
        "approval_status",
        "updated_at",
        "updated_by_email",
    ]
    column_default_sort = ("updated_at", True)


class PlatformMembershipAdmin(ModelView, model=PlatformMembership):
    can_edit = False
    can_create = False
    can_delete = True
    column_list = [
        "id",
        "platform_id",
        "user_id",
        "approval_status",
        "updated_at",
        "updated_by"
    ]
    column_default_sort = ("updated_at", True)


class PlatformMembershipHistoryAdmin(ModelView, model=PlatformMembershipHistory):
    can_edit = False
    can_create = False
    can_delete = True
    column_list = [
        "id",
        "platform_id",
        "user_id",
        "approval_status",
        "updated_at",
        "updated_by"
    ]
    column_default_sort = ("updated_at", True)


class DatabaseAdmin:
    """
    Sets up the Admin app for the database.
    """

    views = (
        BiocommonsUserAdmin,
        GroupAdmin,
        Auth0RoleAdmin,
        GroupMembershipAdmin,
        GroupMembershipHistoryAdmin,
        PlatformMembershipAdmin,
        PlatformMembershipHistoryAdmin,
    )

    def __init__(self, app: FastAPI, secret_key: str):
        self.app = app
        self.auth0_client = setup_oauth()
        self.admin = Admin(
            app,
            engine=get_engine(),
            base_url="/db_admin",
            authentication_backend=AdminAuth(
                secret_key=secret_key, auth0_client=self.auth0_client
            ),
            title="AAI Backend Admin",
        )
        self.admin.app.router.add_route("/auth/auth0", self.login_auth0)

    @classmethod
    def setup(cls, app: FastAPI, secret_key: str) -> Self:
        db_admin = cls(app, secret_key=secret_key)
        for view in db_admin.views:
            db_admin.admin.add_view(view)
        return db_admin

    async def login_auth0(self, request: Request) -> Response:
        settings = get_settings()
        token = await self.auth0_client.authorize_access_token(request)
        access_token = token.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Could not get access token.")
        payload = verify_jwt(access_token, settings)
        if not payload:
            raise HTTPException(status_code=401, detail="Could not verify JWT.")
        if not payload.has_admin_role(settings):
            raise HTTPException(
                status_code=401, detail="User does not have admin role."
            )
        request.session["biocommons_roles"] = payload.biocommons_roles
        return RedirectResponse(request.url_for("admin:index"), status_code=302)
