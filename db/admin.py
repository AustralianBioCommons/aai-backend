from typing import Self, Union

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from auth.validator import verify_jwt
from config import get_settings
from db.models import ApprovalHistory, Auth0Role, BiocommonsGroup, GroupMembership
from db.setup import engine


def setup_oauth():
    settings = get_settings()
    oauth = OAuth()
    oauth.register(
        name="auth0",
        client_id=settings.auth0_management_id,
        client_secret=settings.auth0_management_secret,
        api_base_url=f"https://{settings.auth0_domain}",
        access_token_url=f"https://{settings.auth0_domain}/oauth/token",
        authorize_url=f"https://{settings.auth0_domain}/authorize",
        server_metadata_url=f'https://{settings.auth0_domain}/.well-known/openid-configuration',
        client_kwargs={
            "scope": "openid profile email",
            "audience": settings.auth0_audience
        }
    )
    return oauth.create_client("auth0")


class AdminAuth(AuthenticationBackend):

    def __init__(self, session_middleware: Middleware, auth0_client: OAuth):
        self.middlewares = [session_middleware]
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
            redirect_uri = request.url_for('login_auth0')
            return await self.auth0_client.authorize_redirect(request, redirect_uri)
        for role in roles:
            if role in settings.admin_roles:
                return True
        return False


class GroupAdmin(ModelView, model=BiocommonsGroup):
    can_edit = False
    can_create = False


class Auth0RoleAdmin(ModelView, model=Auth0Role):
    can_edit = False
    can_create = False
    column_list = ["id", "name", "description"]


class GroupMembershipAdmin(ModelView, model=GroupMembership):
    can_edit = False
    can_create = False
    column_list = ["name", "group_id", "user_email", "user_id", "approval_status", "updated_at", "updated_by_email"]


class ApprovalHistoryAdmin(ModelView, model=ApprovalHistory):
    can_edit = False
    can_create = False
    column_list = ["name", "group_id", "user_email", "user_id", "approval_status", "updated_at", "updated_by_email"]


class DatabaseAdmin:

    def __init__(self, app: FastAPI, session_middleware: Middleware):
        self.app = app
        self.auth0_client = setup_oauth()
        self.admin = Admin(
            app,
            engine=engine,
            base_url="/db_admin",
            authentication_backend=AdminAuth(session_middleware=session_middleware, auth0_client=self.auth0_client),
            title="AAI Backend Admin"
        )
        self.admin.app.router.add_route("/auth/auth0", self.login_auth0)

    @classmethod
    def setup(cls, app: FastAPI, session_middleware: Middleware) -> Self:
        db_admin = cls(app, session_middleware)
        db_admin.admin.add_view(GroupAdmin)
        db_admin.admin.add_view(Auth0RoleAdmin)
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
            raise HTTPException(status_code=401, detail="User does not have admin role.")
        request.session['biocommons_roles'] = payload.biocommons_roles
        return RedirectResponse(request.url_for("admin:index"), status_code=302)
