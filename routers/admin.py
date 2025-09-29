import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import alias, false, func, or_
from sqlmodel import Session, select

from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
    PlatformEnum,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import ApprovalStatusEnum, GroupEnum
from schemas.biocommons import Auth0UserDataWithMemberships
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')


UserIdParam = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$")
ServiceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")
ResourceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")


PLATFORM_MAPPING = {
    "galaxy": {"enum": PlatformEnum.GALAXY, "name": "Galaxy Australia"},
    "bpa_data_portal": {"enum": PlatformEnum.BPA_DATA_PORTAL, "name": "Bioplatforms Australia Data Portal"},
    "sbp": {"enum": PlatformEnum.SBP, "name": "Structural Biology Platform"},
}

GROUP_MAPPING = {
    "tsi": {"enum": GroupEnum.TSI, "name": "Threatened Species Initiative Bundle"},
    "bpa_galaxy": {"enum": GroupEnum.BPA_GALAXY, "name": "Bioplatforms Australia Data Portal & Galaxy Australia Bundle"},
}


class BiocommonsUserResponse(BaseModel):
    """
    Response schema for BiocommonsUser from the database
    """
    id: str = Field(description="Auth0 user ID")
    email: str = Field(description="User email address")
    username: str = Field(description="User username")
    email_verified: bool = Field(description="User email verification status")
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


class RevokeServiceRequest(BaseModel):
    reason: Annotated[str | None, Field(default=None, max_length=1024)] = None

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


def _get_platform_or_404(*, platform_id: str, db_session: Session) -> Platform:
    try:
        platform_enum = PlatformEnum(platform_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Platform '{platform_id}' is not recognised",
        ) from exc

    platform = db_session.get(Platform, platform_enum)
    if platform is None:
        raise HTTPException(
            status_code=404,
            detail=f"Platform '{platform_id}' is not configured",
        )
    return platform


def _get_group_or_404(*, group_identifier: str, db_session: Session) -> BiocommonsGroup:
    if group_identifier in GROUP_MAPPING:
        group_id = GROUP_MAPPING[group_identifier]["enum"].value
    else:
        group_id = group_identifier

    group = db_session.get(BiocommonsGroup, group_id)
    if group is None:
        raise HTTPException(
            status_code=404,
            detail=f"Group '{group_identifier}' is not configured",
        )
    return group


def _get_admin_db_user(*, user_id: str, db_session: Session) -> BiocommonsUser:
    db_user = db_session.get(BiocommonsUser, user_id)
    if db_user is None:
        raise HTTPException(
            status_code=404,
            detail=f"Admin user '{user_id}' is not registered in the portal database.",
        )
    return db_user


def _get_platform_membership_or_404(
    *, user_id: str, platform_id: PlatformEnum, db_session: Session
) -> PlatformMembership:
    membership = db_session.exec(
        select(PlatformMembership).where(
            PlatformMembership.user_id == user_id,
            PlatformMembership.platform_id == platform_id,
        )
    ).one_or_none()
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail=f"Platform membership '{platform_id.value}' not found for user '{user_id}'",
        )
    return membership


def _get_group_membership_or_404(
    *, user_id: str, group_id: str, db_session: Session
) -> GroupMembership:
    membership = GroupMembership.get_by_user_id(
        user_id=user_id,
        group_id=group_id,
        session=db_session,
    )
    if membership is None:
        raise HTTPException(
            status_code=404,
            detail=f"Group membership '{group_id}' not found for user '{user_id}'",
        )
    return membership


def _membership_response() -> dict[str, object]:
    return {"status": "ok", "updated": True}


def _assert_platform_admin_permissions(
    *, admin_user: SessionUser, platform: Platform
) -> None:
    allowed_roles = {role.name for role in platform.admin_roles}
    if not allowed_roles:
        logger.warning(
            "Platform %s has no admin roles configured", platform.id.value
        )

    user_roles = set(admin_user.access_token.biocommons_roles or [])
    if user_roles.isdisjoint(allowed_roles):
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to manage this platform.",
        )


def _assert_group_admin_permissions(
    *, admin_user: SessionUser, group: BiocommonsGroup
) -> None:
    if not group.admin_roles:
        logger.warning("Group %s has no admin roles configured", group.group_id)

    if not group.user_is_admin(admin_user):
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to manage this group.",
        )


def _approve_platform_membership(
    *,
    user_id: str,
    platform: PlatformEnum,
    admin_record: BiocommonsUser,
    db_session: Session,
) -> None:
    membership = _get_platform_membership_or_404(
        user_id=user_id,
        platform_id=platform,
        db_session=db_session,
    )
    membership.approval_status = ApprovalStatusEnum.APPROVED
    membership.revocation_reason = None
    membership.updated_at = datetime.now(timezone.utc)
    membership.updated_by = admin_record
    db_session.add(membership)
    membership.save_history(db_session)
    db_session.commit()
    db_session.refresh(membership)
    logger.info("Approved platform %s for user %s", platform.value, user_id)


def _revoke_platform_membership(
    *,
    user_id: str,
    platform: PlatformEnum,
    reason: str | None,
    admin_record: BiocommonsUser,
    db_session: Session,
) -> None:
    membership = _get_platform_membership_or_404(
        user_id=user_id,
        platform_id=platform,
        db_session=db_session,
    )
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = reason
    membership.updated_at = datetime.now(timezone.utc)
    membership.updated_by = admin_record
    db_session.add(membership)
    membership.save_history(db_session)
    db_session.commit()
    db_session.refresh(membership)
    logger.info("Revoked platform %s for user %s", platform.value, user_id)


def _approve_group_membership(
    *,
    user_id: str,
    group: BiocommonsGroup,
    admin_record: BiocommonsUser,
    client: Auth0Client,
    db_session: Session,
) -> None:
    membership = _get_group_membership_or_404(
        user_id=user_id,
        group_id=group.group_id,
        db_session=db_session,
    )
    membership.approval_status = ApprovalStatusEnum.APPROVED
    membership.revocation_reason = None
    membership.updated_at = datetime.now(timezone.utc)
    membership.updated_by = admin_record
    membership.grant_auth0_role(auth0_client=client)
    membership.save(session=db_session, commit=True)
    db_session.refresh(membership)
    logger.info("Approved group %s for user %s", group.group_id, user_id)


def _revoke_group_membership(
    *,
    user_id: str,
    group: BiocommonsGroup,
    reason: str | None,
    admin_record: BiocommonsUser,
    db_session: Session,
) -> None:
    membership = _get_group_membership_or_404(
        user_id=user_id,
        group_id=group.group_id,
        db_session=db_session,
    )
    membership.approval_status = ApprovalStatusEnum.REVOKED
    membership.revocation_reason = reason
    membership.updated_at = datetime.now(timezone.utc)
    membership.updated_by = admin_record
    membership.save(session=db_session, commit=True)
    db_session.refresh(membership)
    logger.info("Revoked group %s for user %s", group.group_id, user_id)


def _parse_platform_or_404(
    platform_id: str,
    db_session: Session,
) -> Platform:
    return _get_platform_or_404(platform_id=platform_id, db_session=db_session)


def _parse_group_or_404(
    group_id: str,
    db_session: Session,
) -> BiocommonsGroup:
    return _get_group_or_404(group_identifier=group_id, db_session=db_session)


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
def get_users(admin_user: Annotated[SessionUser, Depends(get_current_user)],
              db_session: Annotated[Session, Depends(get_db_session)],
              pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
              filter_by: str = Query(None, description="Filter users by group ('tsi', 'bpa_galaxy') or platform ('galaxy', 'bpa_data_portal')"),
              search: str = Query(None, description="Search users by username or email")):
    """
    Get all users from the database with pagination and optional filtering.

    Args:
        filter_by: Optional filter parameter. Can be:
            - Group bundle names: 'tsi', 'bpa_galaxy'
            - Platform names: 'galaxy', 'bpa_data_portal'
        search: Optional search parameter for username or email
    """
    admin_roles = admin_user.access_token.biocommons_roles
    # Base query with platform access filtering built-in
    allowed_platforms_subquery = (
        select(Platform.id)
        .join(Platform.admin_roles)
        .where(Auth0Role.name.in_(admin_roles))
    ).alias("allowed_platforms")
    # Need an alias or SQLAlchemy complains about duplicate column names
    pm = alias(PlatformMembership, name="pm")
    base_query = (
        select(BiocommonsUser)
        .join(pm, BiocommonsUser.id == pm.c.user_id)
        .where(pm.c.platform_id.in_(allowed_platforms_subquery))
        .distinct()
    )

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

    if search:
        s = search.strip().lower()

        if "@" in s:
            base_query = base_query.where(
                or_(
                    func.lower(BiocommonsUser.email) == s,
                    func.lower(BiocommonsUser.email).ilike(f"%{s}%")
                )
            )
        else:
            base_query = base_query.where(
                or_(
                    func.lower(BiocommonsUser.username).ilike(f"%{s}%"),
                    func.lower(BiocommonsUser.email).ilike(f"%{s}%")
                )
            )

    user_query = base_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get(
    "/users/approved",
    response_model=list[BiocommonsUserResponse])
def get_approved_users(db_session: Annotated[Session, Depends(get_db_session)],
                       pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_approved_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.APPROVED)
        .distinct()
    )
    user_query = platform_approved_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/pending",
            response_model=list[BiocommonsUserResponse])
def get_pending_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_pending_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.PENDING)
        .distinct()
    )
    user_query = platform_pending_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/revoked")
def get_revoked_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_revoked_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.REVOKED)
        .distinct()
    )
    user_query = platform_revoked_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/unverified", response_model=list[BiocommonsUserResponse])
def get_unverified_users(
    db_session: Annotated[Session, Depends(get_db_session)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
):
    """
    Return users whose email is not verified, using Auth0 search for efficiency.
    """
    query = (
        select(BiocommonsUser)
        .where(BiocommonsUser.email_verified == false())
        .offset(pagination.start_index)
        .limit(pagination.per_page)
    )
    users = db_session.exec(query).all()
    return users


@router.get("/users/{user_id}",
            response_model=BiocommonsUserResponse)
def get_user(user_id: Annotated[str, UserIdParam],
             db_session: Annotated[Session, Depends(get_db_session)]):
    user = db_session.get_one(BiocommonsUser, user_id)
    return user


@router.get("/users/{user_id}/details",
            response_model=Auth0UserDataWithMemberships)
def get_user_details(user_id: Annotated[str, UserIdParam],
                     client: Annotated[Auth0Client, Depends(get_auth0_client)],
                     db_session: Annotated[Session, Depends(get_db_session)]):
    """
    Get user data from Auth0, along with group and platform membership information
    from our user DB.
    """
    user = client.get_user(user_id)
    from db.models import BiocommonsUser
    db_user = db_session.get_one(BiocommonsUser, user_id)
    details = Auth0UserDataWithMemberships.from_auth0_data(
        auth0_data=user,
        db_data=db_user,
    )
    return details


@router.post("/users/{user_id}/verification-email/resend")
def resend_verification_email(user_id: Annotated[str, UserIdParam],
                              client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    client.resend_verification_email(user_id)
    return {"message": "Verification email resent."}


@router.post("/users/{user_id}/platforms/{platform_id}/approve")
def approve_platform_membership(user_id: Annotated[str, UserIdParam],
                                platform_id: Annotated[str, ServiceIdParam],
                                client: Annotated[Auth0Client, Depends(get_auth0_client)],
                                approving_user: Annotated[SessionUser, Depends(get_current_user)],
                                db_session: Annotated[Session, Depends(get_db_session)]):
    platform_record = _parse_platform_or_404(platform_id, db_session=db_session)
    _assert_platform_admin_permissions(
        admin_user=approving_user,
        platform=platform_record,
    )
    admin_record = _get_admin_db_user(
        user_id=approving_user.access_token.sub,
        db_session=db_session,
    )
    _approve_platform_membership(
        user_id=user_id,
        platform=platform_record.id,
        admin_record=admin_record,
        db_session=db_session,
    )
    return _membership_response()


@router.post("/users/{user_id}/platforms/{platform_id}/revoke")
def revoke_platform_membership(user_id: Annotated[str, UserIdParam],
                               platform_id: Annotated[str, ServiceIdParam],
                               payload: RevokeServiceRequest,
                               client: Annotated[Auth0Client, Depends(get_auth0_client)],
                               revoking_user: Annotated[SessionUser, Depends(get_current_user)],
                               db_session: Annotated[Session, Depends(get_db_session)]):
    platform_record = _parse_platform_or_404(platform_id, db_session=db_session)
    _assert_platform_admin_permissions(
        admin_user=revoking_user,
        platform=platform_record,
    )
    admin_record = _get_admin_db_user(
        user_id=revoking_user.access_token.sub,
        db_session=db_session,
    )
    _revoke_platform_membership(
        user_id=user_id,
        platform=platform_record.id,
        reason=payload.reason,
        admin_record=admin_record,
        db_session=db_session,
    )
    return _membership_response()


@router.post("/users/{user_id}/groups/{group_id}/approve")
def approve_group_membership(user_id: Annotated[str, UserIdParam],
                             group_id: Annotated[str, ServiceIdParam],
                             client: Annotated[Auth0Client, Depends(get_auth0_client)],
                             approving_user: Annotated[SessionUser, Depends(get_current_user)],
                             db_session: Annotated[Session, Depends(get_db_session)]):
    group_record = _parse_group_or_404(group_id, db_session=db_session)
    _assert_group_admin_permissions(
        admin_user=approving_user,
        group=group_record,
    )
    admin_record = _get_admin_db_user(
        user_id=approving_user.access_token.sub,
        db_session=db_session,
    )
    _approve_group_membership(
        user_id=user_id,
        group=group_record,
        admin_record=admin_record,
        client=client,
        db_session=db_session,
    )
    return _membership_response()


@router.post("/users/{user_id}/groups/{group_id}/revoke")
def revoke_group_membership(user_id: Annotated[str, UserIdParam],
                            group_id: Annotated[str, ServiceIdParam],
                            payload: RevokeServiceRequest,
                            client: Annotated[Auth0Client, Depends(get_auth0_client)],
                            revoking_user: Annotated[SessionUser, Depends(get_current_user)],
                            db_session: Annotated[Session, Depends(get_db_session)]):
    group_record = _parse_group_or_404(group_id, db_session=db_session)
    _assert_group_admin_permissions(
        admin_user=revoking_user,
        group=group_record,
    )
    admin_record = _get_admin_db_user(
        user_id=revoking_user.access_token.sub,
        db_session=db_session,
    )
    _revoke_group_membership(
        user_id=user_id,
        group=group_record,
        reason=payload.reason,
        admin_record=admin_record,
        db_session=db_session,
    )
    return _membership_response()
