import asyncio
import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError
from sqlmodel import Session, select

from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from db.models import (
    BiocommonsGroup,
    BiocommonsUser,
    GroupEnum,
    GroupMembership,
    PlatformEnum,
    PlatformMembership,
)
from db.setup import get_db_session
from routers.user import update_user_metadata
from schemas.biocommons import Auth0UserData
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')


UserIdParam = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$")
ServiceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")
ResourceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")


PLATFORM_MAPPING = {
    "galaxy": {"enum": PlatformEnum.GALAXY, "name": "Galaxy Australia"},
    "bpa_data_portal": {"enum": PlatformEnum.BPA_DATA_PORTAL, "name": "Bioplatforms Australia Data Portal"},
}

GROUP_MAPPING = {
    "tsi": {"enum": GroupEnum.TSI, "name": "TSI"},
    "bpa_galaxy": {"enum": GroupEnum.BPA_GALAXY, "name": "Bioplatforms Australia Data Portal & Galaxy Australia"},
}

class BiocommonsUserResponse(BaseModel):
    """
    Response schema for BiocommonsUser from the database
    """
    id: str = Field(description="Auth0 user ID")
    email: str = Field(description="User email address")
    username: str = Field(description="User username")
    created_at: datetime = Field(description="User creation timestamp")


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


@router.get("/filters")
def get_filter_options():
    """
    Get available filter options for users endpoint.

    Returns a list of all available filter options with their short IDs and display names.
    Uses the same IDs as defined in PLATFORM_MAPPING and GROUP_MAPPING.
    """
    options = []

    for platform_id, platform_data in PLATFORM_MAPPING.items():
        options.append({
            "id": platform_id,
            "name": platform_data["name"]
        })

    for group_id, group_data in GROUP_MAPPING.items():
        options.append({
            "id": group_id,
            "name": group_data["name"]
        })

    return options


@router.get("/users",
            response_model=list[BiocommonsUserResponse])
def get_users(db_session: Annotated[Session, Depends(get_db_session)],
              pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
              filter_by: str = Query(None, description="Filter users by group ('tsi', 'bpa_galaxy') or platform ('galaxy', 'bpa_data_portal')")):
    """
    Get all users from the database with pagination and optional filtering.

    Args:
        filter_by: Optional filter parameter. Can be:
            - Group bundle names: 'tsi', 'bpa_galaxy'
            - Platform names: 'galaxy', 'bpa_data_portal'
    """
    base_query = select(BiocommonsUser)

    if filter_by:
        if filter_by in GROUP_MAPPING:
            full_group_id = GROUP_MAPPING[filter_by]["enum"].value

            group_statement = select(BiocommonsGroup).where(BiocommonsGroup.group_id == full_group_id)
            group = db_session.exec(group_statement).first()
            if not group:
                raise HTTPException(status_code=404, detail=f"Group '{filter_by}' not found")

            base_query = base_query.join(GroupMembership, BiocommonsUser.id == GroupMembership.user_id).where(GroupMembership.group_id == full_group_id)

        elif filter_by in PLATFORM_MAPPING:
            platform_enum_value = PLATFORM_MAPPING[filter_by]["enum"]
            base_query = base_query.join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id).where(PlatformMembership.platform_id == platform_enum_value)

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid filter_by value '{filter_by}'"
            )

    user_query = base_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


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
            response_model=Auth0UserData)
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
                     client: Annotated[Auth0Client, Depends(get_auth0_client)],
                     approving_user: Annotated[SessionUser, Depends(get_current_user)]):
    user = client.get_user(user_id=user_id)
    approving_user_data = client.get_user(user_id=approving_user.access_token.sub)

    user.app_metadata.approve_resource(
        service_id=service_id,
        resource_id=resource_id,
        updated_by=approving_user_data.email
    )

    update = update_user_metadata(
        user_id=user_id,
        token=client.management_token,
        metadata=user.app_metadata.model_dump(mode="json")
    )
    resp = asyncio.run(update)
    return resp
