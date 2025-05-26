from fastapi import APIRouter, Depends, Path

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import user_is_admin
from auth0.client import Auth0Client
from auth0.schemas import Auth0UserResponse

router = APIRouter(prefix="/admin", tags=["admin"],
                   dependencies=[Depends(user_is_admin)])


def get_auth0_client(settings: Settings = Depends(get_settings),
                     management_token: str = Depends(get_management_token)):
    return Auth0Client(settings.auth0_domain, management_token=management_token)


# TODO: May need to paginate this response to make sure we get all
#   of them
@router.get("/users",
            response_model=list[Auth0UserResponse])
def get_users(client: Auth0Client = Depends(get_auth0_client)):
    resp = client.get_users()
    return resp


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get("/users/approved")
def get_approved_users(client: Auth0Client = Depends(get_auth0_client)):
    resp = client.get_approved_users()
    return resp


@router.get("/users/pending")
def get_pending_users(client: Auth0Client = Depends(get_auth0_client)):
    resp = client.get_pending_users()
    return resp

@router.get("/users/{user_id}",
            response_model=Auth0UserResponse)
def get_user(user_id: str = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$"),
            client: Auth0Client = Depends(get_auth0_client)):
    return client.get_user(user_id)
