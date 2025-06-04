import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, ValidationError

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client
from routers.user import update_user_metadata
from schemas.biocommons import BiocommonsAuth0User
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')


UserIdParam = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$")
ServiceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")
ResourceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")


class PaginationParams(BaseModel):
    """
    Query parameters for paginated endpoints. Page starts at 1.
    """
    page: int = Query(1, ge=1)
    per_page: int = Query(100, ge=1, le=100)

    @property
    def start_index(self):
        return (self.page - 1) * self.per_page


def get_pagination_params(page: int = 1, per_page: int = 100):
    try:
        return PaginationParams(page=page, per_page=per_page)
    except ValidationError:
        raise HTTPException(
            status_code=422,
            detail="Invalid page params: page should be >= 1, per_page should be >= 1 and <= 100"
        )


router = APIRouter(prefix="/admin", tags=["admin"],
                   dependencies=[Depends(user_is_admin)])


def get_auth0_client(settings: Settings = Depends(get_settings),
                     management_token: str = Depends(get_management_token)):
    return Auth0Client(settings.auth0_domain, management_token=management_token)


@router.get("/users",
            response_model=list[BiocommonsAuth0User],)
def get_users(client: Annotated[Auth0Client, Depends(get_auth0_client)],
              pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    resp = client.get_users(page=pagination.page, per_page=pagination.per_page)
    return resp


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get("/users/approved")
def get_approved_users(client: Annotated[Auth0Client, Depends(get_auth0_client)],
                       pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    resp = client.get_approved_users(page=pagination.page, per_page=pagination.per_page)
    return resp


@router.get("/users/pending")
def get_pending_users(client: Annotated[Auth0Client, Depends(get_auth0_client)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    resp = client.get_pending_users(page=pagination.page, per_page=pagination.per_page)
    return resp


@router.get("/users/revoked")
def get_revoked_users(client: Annotated[Auth0Client, Depends(get_auth0_client)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    resp = client.get_revoked_users(page=pagination.page, per_page=pagination.per_page)
    return resp


@router.get("/users/{user_id}",
            response_model=BiocommonsAuth0User)
def get_user(user_id: Annotated[str, UserIdParam],
             client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    return client.get_user(user_id)


@router.post("/users/{user_id}/services/{service_id}/approve")
def approve_service(user_id: Annotated[str, UserIdParam],
                    service_id: Annotated[str, ServiceIdParam],
                    client: Annotated[Auth0Client, Depends(get_auth0_client)],
                    approving_user: Annotated[SessionUser, Depends(get_current_user)]):
    user = client.get_user(user_id=user_id)
    # Need to fetch full user info currently to get email address, not in access token
    approving_user_data = client.get_user(user_id=approving_user.access_token.sub)
    logger.debug(f"Approving service {service_id} for user {user_id} by {approving_user_data.email}")
    user.app_metadata.approve_service(service_id, updated_by=str(approving_user_data.email))
    logger.info("Sending updated metadata to Auth0 API")
    # update_user_metadata is async, so run via asyncio
    update = update_user_metadata(
        user_id=user_id,
        token=client.management_token,
        metadata=user.app_metadata.model_dump(mode="json")
    )
    resp = asyncio.run(update)
    logger.info("Metadata updated successfully")
    return resp


@router.post("/users/{user_id}/services/{service_id}/revoke")
def revoke_service(user_id: Annotated[str, UserIdParam],
                   service_id: Annotated[str, ServiceIdParam],
                   client: Annotated[Auth0Client, Depends(get_auth0_client)],
                   revoking_user: Annotated[SessionUser, Depends(get_current_user)]):
    """
    Revoke a service and all associated resources for a user.
    """
    user = client.get_user(user_id=user_id)
    revoking_user_data = client.get_user(user_id=revoking_user.access_token.sub)
    user.app_metadata.revoke_service(service_id=service_id, updated_by=str(revoking_user_data.email))
    service = user.app_metadata.get_service_by_id(service_id)
    for resource in service.resources:
        resource.revoke()
    update = update_user_metadata(
        user_id=user_id,
        token=client.management_token,
        metadata=user.app_metadata.model_dump(mode="json")
    )
    resp = asyncio.run(update)
    return resp


@router.post("/users/{user_id}/services/{service_id}/resources/{resource_id}/approve")
def approve_resource(user_id: Annotated[str, UserIdParam],
                     service_id: Annotated[str, ServiceIdParam],
                     resource_id: Annotated[str, ResourceIdParam],
                     client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    user = client.get_user(user_id=user_id)
    user.app_metadata.approve_resource(service_id=service_id, resource_id=resource_id)
    update = update_user_metadata(
        user_id=user_id,
        token=client.management_token,
        metadata=user.app_metadata.model_dump(mode="json")
    )
    resp = asyncio.run(update)
    return resp
