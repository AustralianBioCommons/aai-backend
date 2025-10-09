import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.ses import EmailService, get_email_service
from auth.user_permissions import get_session_user, user_is_general_admin
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import (
    BiocommonsGroupCreate,
    BiocommonsGroupResponse,
    GroupId,
    RoleId,
)
from config import Settings, get_settings
from db.models import (
    ApprovalStatusEnum,
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
)
from db.setup import get_db_session
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')

router = APIRouter(prefix="/biocommons", tags=["biocommons"],
                   dependencies=[Depends(get_session_user)])


@router.post("/groups/create",
             response_model=BiocommonsGroupResponse,
             dependencies=[Depends(user_is_general_admin)])
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


class GroupAccessRequestData(BaseModel):
    group_id: GroupId


@router.post("/groups/request")
def request_group_access(
        request_data: GroupAccessRequestData,
        user: Annotated[SessionUser, Depends(get_session_user)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
        db_session: Annotated[Session, Depends(get_db_session)],
        settings: Annotated[Settings, Depends(get_settings)],
        email_service: Annotated[EmailService, Depends(get_email_service)],
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
    group = db_session.get_one(BiocommonsGroup, group_id)
    user_record = BiocommonsUser.get_or_create(
        auth0_id=user.access_token.sub,
        db_session=db_session,
        auth0_client=auth0_client
    )
    membership = GroupMembership(
        group=group,
        user=user_record,
        approval_status=ApprovalStatusEnum.PENDING,
        updated_by=None
    )
    membership.save(session=db_session, commit=True)
    if settings.send_email:
        logger.info("Sending emails to group admins for approval")
        admin_emails = membership.group.get_admins(auth0_client=auth0_client)
        for email in admin_emails:
            background_tasks.add_task(send_group_approval_email,
                                      approver_email=email, request=membership, email_service=email_service, settings=settings)
    return {"message": f"Group membership for {group_id} requested successfully."}


class GroupAccessApprovalData(BaseModel):
    user_id: str
    group_id: str


@router.post("/groups/approve")
def approve_group_access(
    data: GroupAccessApprovalData,
    approving_user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
):
    group = db_session.get_one(BiocommonsGroup, data.group_id)
    is_admin = group.user_is_admin(approving_user)
    if not is_admin:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail=f"You do not have permission to approve group memberships for {group.name}"
        )
    membership = GroupMembership.get_by_user_id(user_id=data.user_id, group_id=data.group_id, session=db_session)
    approving_user_record = BiocommonsUser.get_or_create(
        auth0_id=approving_user.access_token.sub,
        db_session=db_session,
        auth0_client=auth0_client
    )
    if membership is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="No membership request found for this user"
        )
    membership.approval_status = ApprovalStatusEnum.APPROVED
    membership.updated_by = approving_user_record
    membership.grant_auth0_role(auth0_client=auth0_client)
    membership.save(session=db_session, commit=True)
    return {"message": f"Group membership for {group.name} approved successfully."}


def send_group_approval_email(approver_email: str, request: GroupMembership, email_service: EmailService, settings: Settings):
    subject = f"New request to join {request.group.name}"

    body_html = f"""
        <p>A new user has requested access to the {request.group.name} group.</p>
        <p><strong>User:</strong> {request.user.email}</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the BioCommons account dashboard</a> to review and approve access.</p>
    """

    email_service.send(approver_email, subject, body_html)


class CreateRoleData(BaseModel):
    name: RoleId | GroupId
    description: str


@router.post("/roles/create",
             dependencies=[Depends(user_is_general_admin)], )
def create_role(
        role_data: CreateRoleData,
        db_session: Annotated[Session, Depends(get_db_session)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)]
    ):
    """
    Create a new role in Auth0 (if needed) and add it to the DB.
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
