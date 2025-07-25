from typing import Self, Union

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from config import get_settings
from db.models import Auth0Role, BiocommonsGroup
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
        }
    )
    return oauth.create_client("auth0")


class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        return True

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> Union[bool, RedirectResponse]:
        user = request.session.get("user")
        if not user:
            redirect_uri = request.url_for('login_auth0')
            return await auth0_client.authorize_redirect(request, redirect_uri)

        return True


class DatabaseAdmin:

    def __init__(self, app: FastAPI, secret_key: str):
        self.app = app
        self.admin = Admin(
            app,
            engine=engine,
            base_url="/db_admin",
            authentication_backend=AdminAuth(secret_key=secret_key),
            title="AAI Backend Admin"
        )

    @classmethod
    def setup(cls, app: FastAPI, secret_key: str) -> Self:
        db_admin = cls(app, secret_key)
        db_admin.admin.add_view(GroupAdmin)
        db_admin.admin.add_view(Auth0RoleAdmin)
        db_admin.admin.app.router.add_route("/auth/auth0", login_auth0)
        return db_admin


class GroupAdmin(ModelView, model=BiocommonsGroup):
    can_edit = False
    can_create = False


class Auth0RoleAdmin(ModelView, model=Auth0Role):
    can_edit = False
    can_create = False
    column_list = ["id", "name", "description"]


async def login_auth0(request: Request) -> Response:
    token = await auth0_client.authorize_access_token(request)
    user = token.get('userinfo')
    if user:
        request.session['user'] = user
    return RedirectResponse(request.url_for("admin:index"))

auth0_client = setup_oauth()
