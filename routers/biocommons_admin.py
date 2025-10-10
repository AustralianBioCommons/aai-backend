import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.user_permissions import user_is_biocommons_admin
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import (
    BiocommonsGroupCreate,
    BiocommonsGroupResponse,
    GroupId,
    RoleId,
)
from db.models import Auth0Role
from db.setup import get_db_session
from db.types import PlatformEnum

logger = logging.getLogger("uvicorn.error")

# All routes should require biocommons admin permissions
router = APIRouter(prefix="/biocommons-admin", tags=["admin"],
                   dependencies=Depends(user_is_biocommons_admin))


@router.post("/groups/create",
             response_model=BiocommonsGroupResponse)
def create_group(
        group_info: BiocommonsGroupCreate,
        db_session: Annotated[Session, Depends(get_db_session)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    """
    Create a new group in the DB. Note that the Auth0 role for this group
    must already exist.
    """
    # Check group exists in Auth0
    try:
        # Note: our "group ids" are actually the Auth0 role names
        auth0_client.get_role_by_name(name=group_info.group_id)
    except ValueError:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Group {group_info.name} doesn't exist in Auth0"
        )
    group = group_info.save(session=db_session, auth0_client=auth0_client)
    return BiocommonsGroupResponse(
        group_id=group.group_id,
        name=group.name,
        admin_roles=[r.name for r in group.admin_roles]
    )


class PlatformCreateData(BaseModel):
    id: PlatformEnum
    name: str
    admin_roles: list[str]

    def save(self, db_session: Session, auth0_client: Auth0Client):
        for role in self.admin_roles:
            Auth0Role.get_by_name(role, db_session)


@router.post("/platforms/create")
def create_platform(platform_id: str, db_session: Annotated[Session, Depends(get_db_session)]):
    pass


class CreateRoleData(BaseModel):
    name: RoleId | GroupId
    description: str


@router.post("/roles/create",
             response_model=Auth0Role)
def create_role(
        role_data: CreateRoleData,
        db_session: Annotated[Session, Depends(get_db_session)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)]
    ):
    """
    Create a new role in Auth0 (if needed) and add it to the DB. If
    the role already exists in Auth0, we just add it to the DB.
    Note that our "RoleId/GroupId" is actually the
    Auth0 role name - Auth0 has its own internal IDs
    """
    logger.info(f"Creating role {role_data.name} in Auth0 if needed")
    resp = auth0_client.get_or_create_role(**role_data.model_dump())
    logger.info("Saving to database")
    role = Auth0Role(**resp.model_dump())
    db_session.add(role)
    db_session.commit()
    return role
