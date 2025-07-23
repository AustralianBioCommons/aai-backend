import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.ses import EmailService
from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import (
    BiocommonsGroupCreate,
    BiocommonsGroupResponse,
    GroupId,
    RoleId,
)
from config import Settings, get_settings
from db.models import ApprovalStatusEnum, Auth0Role, GroupMembership
from db.setup import get_db_session
from schemas.user import SessionUser

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


class GroupAccessRequestData(BaseModel):
    group_id: GroupId


@router.post("/groups/request")
def request_group_access(
        request_data: GroupAccessRequestData,
        user: Annotated[SessionUser, Depends(get_current_user)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
        db_session: Annotated[Session, Depends(get_db_session)],
        settings: Annotated[Settings, Depends(get_settings)],
        background_tasks: BackgroundTasks
    ):
    """
    Request access to a group. Assumes the user does not already have a
    GroupMembership record for this group.
    """
    group_id = request_data.group_id
    existing_membership = GroupMembership.get_by_user_id(
        user_id=user.access_token.sub,
        group_id=group_id,
        session=db_session,
    )
    if existing_membership is not None:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail=f"User {user.access_token.sub} already has a membership for {group_id}"
        )
    membership = GroupMembership(
        group_id=group_id,
        user_id=user.access_token.sub,
        user_email=user.access_token.email,
        approval_status=ApprovalStatusEnum.PENDING,
        updated_by_id="",
        updated_by_email=""
    )
    membership.save(session=db_session, commit=True)
    if settings.send_email:
        logger.info("Sending emails to group admins for approval")
        admin_emails = membership.group.get_admins(auth0_client=auth0_client)
        for email in admin_emails:
            background_tasks.add_task(send_group_approval_email, email, membership)
    return {"message": f"Group membership for {group_id} requested successfully."}


def send_group_approval_email(approver_email: str, request: GroupMembership):
    email_service = EmailService()
    approver_email = "aai-dev@biocommons.org.au"
    subject = f"New request to join {request.group.name}"

    body_html = f"""
        <p>A new user has requested access to the {request.group.name} group.</p>
        <p><strong>User:</strong> {request.user_email}</p>
        <p>Please <a href='https://aaiportal.test.biocommons.org.au/requests'>log into the BioCommons account dashboard</a> to review and approve access.</p>
    """

    email_service.send(approver_email, subject, body_html)


class CreateRoleData(BaseModel):
    name: RoleId | GroupId
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
    Note that our "RoleId/GroupId" is actually the
    Auth0 role name - Auth0 has its own internal IDs
    """
    logger.info(f"Creating role {role_data.name} in Auth0")
    resp = auth0_client.create_role(**role_data.model_dump())
    logger.info("Saving to database")
    role = Auth0Role(**resp.model_dump())
    db_session.add(role)
    db_session.commit()
    return role
