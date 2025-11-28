import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from auth.user_permissions import get_session_user
from auth0.client import Auth0Client, get_auth0_client
from biocommons.emails import compose_group_membership_approved_email
from config import Settings, get_settings
from db.models import (
    ApprovalStatusEnum,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
)
from db.setup import get_db_session
from schemas.user import SessionUser
from services.email_queue import enqueue_email

logger = logging.getLogger('uvicorn.error')

router = APIRouter(prefix="/biocommons", tags=["biocommons"],
                   dependencies=[Depends(get_session_user)])


class GroupAccessApprovalData(BaseModel):
    user_id: str
    group_id: str


@router.post("/groups/approve")
def approve_group_access(
    data: GroupAccessApprovalData,
    approving_user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
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
    if membership.approval_status not in {ApprovalStatusEnum.PENDING, ApprovalStatusEnum.REVOKED}:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Only pending or revoked group memberships can be approved.",
        )
    membership.approval_status = ApprovalStatusEnum.APPROVED
    membership.updated_by = approving_user_record
    membership.rejection_reason = None
    membership.revocation_reason = None
    membership.grant_auth0_role(auth0_client=auth0_client)
    membership.save(session=db_session, commit=False)
    if membership.user is None:
        db_session.refresh(membership, attribute_names=["user"])
    if membership.user and membership.user.email:
        subject, body_html = compose_group_membership_approved_email(
            group_name=group.name,
            group_short_name=group.short_name,
            settings=settings,
        )
        enqueue_email(
            db_session,
            to_address=membership.user.email,
            subject=subject,
            body_html=body_html,
        )
    db_session.commit()
    return {"message": f"Group membership for {group.name} approved successfully."}
