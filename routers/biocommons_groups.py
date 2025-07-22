import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import BiocommonsGroupCreate, BiocommonsGroupResponse
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
