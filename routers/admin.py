from fastapi import APIRouter, Depends

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import user_is_admin
from auth0.client import Auth0Client
from auth0.schemas import Auth0UserResponse

router = APIRouter(prefix="/admin", tags=["admin"],
                   dependencies=[Depends(user_is_admin)])


def get_auth0_client(settings: Settings = Depends(get_settings)):
    return Auth0Client(settings.auth0_domain)


@router.get("/users",
            response_model=list[Auth0UserResponse])
def get_users(settings: Settings = Depends(get_settings),
                    client: Auth0Client = Depends(get_auth0_client)):
    token = get_management_token(settings=settings)
    resp = client.get_users(token)
    return resp
