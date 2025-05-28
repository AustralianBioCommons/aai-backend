import asyncio
import logging

from fastapi import APIRouter, Depends, Path

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client
from auth0.schemas import Auth0UserResponse
from routers.user import update_user_metadata
from schemas.user import User

logger = logging.getLogger('uvicorn.error')

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


@router.get("/users/{user_id}/services/approve/{service_id}")
def approve_service(user_id: str = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$"),
                    service_id: str = Path(..., pattern=r"^[a-zA-Z0-9_]+$"),
                    client: Auth0Client = Depends(get_auth0_client),
                    approving_user: User = Depends(get_current_user)):
    user = client.get_user(user_id=user_id)
    # Need to fetch full user info currently to get email address, not in access token
    approving_user_data = client.get_user(user_id=approving_user.access_token.sub)
    logger.debug(f"Approving service {service_id} for user {user_id} by {approving_user_data.email}")
    user.app_metadata.approve_service(service_id, approved_by=str(approving_user_data.email))
    logger.info("Sending updated metadata to Auth0 API")
    # update_user_metadata is async, so run via asyncio
    update = update_user_metadata(user_id=user_id, token=client.management_token, metadata=user.app_metadata.model_dump(mode="json"))
    resp = asyncio.run(update)
    logger.info("Metadata updated successfully")
    return resp
