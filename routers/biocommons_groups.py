import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.ses import EmailService, get_email_service
from auth.user_permissions import get_session_user
from auth0.client import Auth0Client, get_auth0_client
from biocommons.groups import (
    GroupId,
)
from config import Settings, get_settings
from db.models import (
    ApprovalStatusEnum,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
)
from db.setup import get_db_session
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')

router = APIRouter(prefix="/biocommons", tags=["biocommons"],
                   dependencies=[Depends(get_session_user)])


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
    existing_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user.access_token.sub,
        group_id=group_id,
        session=db_session,
    )
    if existing_membership is not None:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail=f"User {user.access_token.sub} already has a membership for {group_id}"
        )
    group = BiocommonsGroup.get_by_id(group_id, db_session)
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
    background_tasks: BackgroundTasks,
    settings: Annotated[Settings, Depends(get_settings)],
    email_service: Annotated[EmailService, Depends(get_email_service)],
):
    group = BiocommonsGroup.get_by_id(data.group_id, db_session)
    is_admin = group.user_is_admin(approving_user)
    if not is_admin:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail=f"You do not have permission to approve group memberships for {group.name}"
        )
    membership = GroupMembership.get_by_user_id_and_group_id(user_id=data.user_id, group_id=data.group_id, session=db_session)
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
    if membership.user is None:
        db_session.refresh(membership, attribute_names=["user"])
    if settings.send_email and membership.user and membership.user.email:
        background_tasks.add_task(
            send_group_membership_approved_email,
            membership.user.email,
            group.name,
            group.short_name,
            settings,
            email_service,
        )
    return {"message": f"Group membership for {group.name} approved successfully."}


def send_group_approval_email(approver_email: str, request: GroupMembership, email_service: EmailService, settings: Settings):
    subject = f"New request to join {request.group.name}"

    body_html = f"""
        <p>A new user has requested access to the {request.group.name} group.</p>
        <p><strong>User:</strong> {request.user.email}</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the BioCommons account dashboard</a> to review and approve access.</p>
    """

    email_service.send(approver_email, subject, body_html)


def send_group_membership_approved_email(
    recipient_email: str,
    group_name: str,
    group_short_name: str,
    settings: Settings,
    email_service: EmailService,
):
    """
    Notify a user that their group/bundle access was approved.
    """
    if not recipient_email:
        logger.warning("Skipping group approval email due to missing recipient email")
        return

    short_name = group_short_name or group_name
    portal_url = settings.aai_portal_url.rstrip("/")
    subject = f"Access approved for {short_name}"
    body_html = f"""
        <p>Hello,</p>
        <p>Your request to join <strong>{group_name}</strong> ({short_name} bundle) has been approved.</p>
        <p>You now have access to all services included with this bundle. Sign in to the <a href="{portal_url}">AAI Portal</a> to review the bundle details and launch its platforms.</p>
        <p>If you have any questions, please reply to this email.</p>
    """
    email_service.send(recipient_email, subject, body_html)
