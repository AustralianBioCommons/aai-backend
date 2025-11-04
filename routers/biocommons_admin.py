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
from db.models import Auth0Role, Platform
from db.setup import get_db_session
from db.types import PlatformEnum

logger = logging.getLogger("uvicorn.error")

# All routes should require biocommons admin permissions
router = APIRouter(prefix="/biocommons-admin", tags=["admin"],
                   dependencies=[Depends(user_is_biocommons_admin)],
                   include_in_schema=False)


@router.post("/groups/create",
             response_model=BiocommonsGroupResponse)
def create_group(
        group_info: BiocommonsGroupCreate,
        db_session: Annotated[Session, Depends(get_db_session)],):
    """
    Create a new group in the DB. Note that the Auth0 role for this group
    must already exist and be in the DB.
    """
    # Check group exists in the DB
    existing_role = Auth0Role.get_by_name(group_info.group_id, db_session)
    if existing_role is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Role for {group_info.name} doesn't exist in the DB"
        )
    group = group_info.save_group(session=db_session)
    return BiocommonsGroupResponse(
        group_id=group.group_id,
        name=group.name,
        admin_roles=[r.name for r in group.admin_roles]
    )


class PlatformCreateData(BaseModel):
    id: PlatformEnum
    name: str
    admin_roles: list[str]

    def save_platform(self, db_session: Session, commit: bool = False):
        """
        Save the platform to the DB.
        Any roles in admin_roles must already exist in the DB.
        """
        db_roles: list[Auth0Role] = []
        for role in self.admin_roles:
            db_role = Auth0Role.get_by_name(role, db_session)
            if db_role is None:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"Role {role} doesn't exist in DB - create roles first"
                )
            db_roles.append(db_role)
        platform = Platform(
            id=self.id,
            role_name=f"biocommons/platform/{self.id}",
            name=self.name,
            admin_roles=db_roles,
        )
        db_session.add(platform)
        if commit:
            db_session.commit()
        return platform


class PlatformResponse(BaseModel):
    id: PlatformEnum
    name: str
    admin_roles: list[str]


@router.post("/platforms/create",
             response_model=PlatformResponse,)
def create_platform(platform_data: PlatformCreateData, db_session: Annotated[Session, Depends(get_db_session)]):
    existing = Platform.get_by_id(platform_data.id, db_session)
    if existing is not None:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Platform {platform_data.id} already exists"
        )
    platform = platform_data.save_platform(db_session, commit=True)
    return PlatformResponse(
        id=platform.id,
        name=platform.name,
        admin_roles=[role.name for role in platform.admin_roles],
    )


class SetRolesData(BaseModel):
    role_names: list[str]


@router.post("/platforms/{platform_id}/set-admin-roles")
def set_platform_admin_roles(platform_id: PlatformEnum, data: SetRolesData, db_session: Annotated[Session, Depends(get_db_session)]):
    platform = Platform.get_by_id(platform_id, db_session)
    db_roles = []
    for role_name in data.role_names:
        role = Auth0Role.get_by_name(role_name, db_session)
        if role is None:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"Role {role_name} doesn't exist in DB - create roles first"
            )
        db_roles.append(role)
    platform.admin_roles = db_roles
    db_session.add(platform)
    db_session.commit()
    return {"message": f"Admin roles for platform {platform_id} set successfully."}


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
