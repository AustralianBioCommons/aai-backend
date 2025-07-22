import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import BiocommonsGroupCreate, BiocommonsGroupResponse, RoleId
from db.models import Auth0Role
from db.setup import get_db_session

logger = logging.getLogger('uvicorn.error')

router = APIRouter(prefix="/biocommons", tags=["biocommons"],
                   dependencies=[Depends(get_current_user)])


@router.post("/groups/create",
             response_model=BiocommonsGroupResponse,
             dependencies=[Depends(user_is_admin)])
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
        auth0_client.get_role_by_name(group_info.name)
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


class CreateRoleData(BaseModel):
    name: RoleId
    description: str


@router.post("/roles/create",
             dependencies=[Depends(user_is_admin)],)
def create_role(
        role_data: CreateRoleData,
        db_session: Annotated[Session, Depends(get_db_session)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)]
    ):
    """
    Create a new role in Auth0 and add it to the DB.
    Note that our "RoleId" is actually the
    Auth0 role name - Auth0 has its own internal IDs
    """
    logger.info(f"Creating role {role_data.name} in Auth0")
    resp = auth0_client.create_role(**role_data.model_dump())
    logger.info("Saving to database")
    role = Auth0Role(**resp.model_dump())
    db_session.add(role)
    db_session.commit()
    return role
