import logging
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import func, or_
from sqlmodel import Session, select
from sqlmodel.sql._expression_select_cls import SelectOfScalar

from auth.ses import EmailService, get_email_service
from auth.user_permissions import (
    get_db_user,
    get_session_user,
    has_platform_admin_permission,
    require_admin_permission_for_group,
    require_admin_permission_for_platform,
    require_admin_permission_for_user,
    user_is_general_admin,
)
from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
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
from db.types import (
    ApprovalStatusEnum,
    GroupEnum,
    GroupMembershipData,
    PlatformMembershipData,
)
from routers.biocommons_groups import send_group_membership_approved_email
from schemas.biocommons import Auth0UserDataWithMemberships, ServiceIdParam, UserIdParam
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')

PLATFORM_MAPPING = {
    "galaxy": {"enum": PlatformEnum.GALAXY, "name": "Galaxy Australia"},
    "bpa_data_portal": {"enum": PlatformEnum.BPA_DATA_PORTAL, "name": "Bioplatforms Australia Data Portal"},
    "sbp": {"enum": PlatformEnum.SBP, "name": "Structural Biology Platform"},
}

GROUP_MAPPING = {
    "tsi": {"enum": GroupEnum.TSI, "name": "Threatened Species Initiative"},
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
    platform_memberships: list[PlatformMembershipData] = Field(
        default_factory=list,
        description="List of platform memberships with approval status and metadata"
    )
    group_memberships: list[GroupMembershipData] = Field(
        default_factory=list,
        description="List of group memberships with approval status and metadata"
    )

    @classmethod
    def from_db_user(cls, user: BiocommonsUser) -> "BiocommonsUserResponse":
        """Convert a BiocommonsUser DB model to a response model with membership data."""
        return cls(
            id=user.id,
            email=user.email,
            username=user.username,
            email_verified=user.email_verified,
            created_at=user.created_at,
            platform_memberships=[m.get_data() for m in user.platform_memberships],
            group_memberships=[m.get_data() for m in user.group_memberships],
        )


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
                   dependencies=[Depends(user_is_general_admin)])


class RevokeServiceRequest(BaseModel):
    reason: Annotated[str | None, Field(default=None, max_length=1024)] = None

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None



def _membership_response() -> dict[str, object]:
    return {"status": "ok", "updated": True}


def _approve_platform_membership(
    *,
    user_id: str,
    platform: PlatformEnum,
    admin_record: BiocommonsUser,
    db_session: Session,
) -> None:
    membership = PlatformMembership.get_by_user_id_and_platform_id_or_404(
        user_id=user_id,
        platform_id=platform,
        session=db_session,
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
    client: Auth0Client,
) -> None:
    membership = PlatformMembership.get_by_user_id_and_platform_id_or_404(
        user_id=user_id,
        platform_id=platform,
        session=db_session,
    )
    role_revoked = membership.revoke(
        auth0_client=client,
        reason=reason,
        updated_by=admin_record,
        session=db_session,
    )
    db_session.refresh(membership)
    logger.info(
        "Revoked platform %s for user %s%s",
        platform.value,
        user_id,
        "" if role_revoked else " (no Auth0 role assigned)",
    )


def _approve_group_membership(
    *,
    user_id: str,
    group: BiocommonsGroup,
    admin_record: BiocommonsUser,
    client: Auth0Client,
    db_session: Session,
) -> tuple[GroupMembership, bool]:
    membership = GroupMembership.get_by_user_id_and_group_id_or_404(
        user_id=user_id,
        group_id=group.group_id,
        session=db_session,
    )
    status_changed = membership.approval_status != ApprovalStatusEnum.APPROVED
    membership.approval_status = ApprovalStatusEnum.APPROVED
    membership.revocation_reason = None
    membership.updated_at = datetime.now(timezone.utc)
    membership.updated_by = admin_record
    membership.grant_auth0_role(auth0_client=client)
    membership.save(session=db_session, commit=True)
    db_session.refresh(membership)
    if membership.user is None:
        db_session.refresh(membership, attribute_names=["user"])
    logger.info("Approved group %s for user %s", group.group_id, user_id)
    return membership, status_changed


def _revoke_group_membership(
    *,
    user_id: str,
    group: BiocommonsGroup,
    reason: str | None,
    admin_record: BiocommonsUser,
    db_session: Session,
    client: Auth0Client,
) -> None:
    membership = GroupMembership.get_by_user_id_and_group_id_or_404(
        user_id=user_id,
        group_id=group.group_id,
        session=db_session,
    )
    role_revoked = membership.revoke(
        auth0_client=client,
        reason=reason,
        updated_by=admin_record,
        session=db_session,
    )
    db_session.refresh(membership)
    logger.info(
        "Revoked group %s for user %s%s",
        group.group_id,
        user_id,
        "" if role_revoked else " (no Auth0 role assigned)",
    )


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


class UserQueryParams(BaseModel):
    """
    Defines query parameters for the /users endpoint, and
    constructs SQLAlchemy queries to filter users based on them.

    Each field listed here must have a {field}_query method defined.
    """
    platform: PlatformEnum | None = Field(None, description="Filter by platform")
    platform_approval_status: ApprovalStatusEnum | None = Field(None, description="Filter by platform approval status")
    group: GroupEnum | None = Field(None, description="Filter by group")
    group_approval_status: ApprovalStatusEnum | None = Field(None, description="Filter by group approval status")
    email_verified: bool | None = Field(None, description="Filter by email verification status")
    filter_by: str | None = Field(
        None,
        description="Filter users by group ('tsi',) or platform ('galaxy', 'bpa_data_portal')"
    )
    search: str | None = Field(None, description="Search users by username or email")

    def _fields(self):
        return (name for name in self.__pydantic_fields__.keys()
                if not name.startswith("_"))

    def model_post_init(self, context: Any) -> None:
        """
        Check that query methods are defined for each field.
        """
        for field_name in self._fields():
            if not hasattr(self, f"{field_name}_query"):
                raise NotImplementedError(f"Missing query method for field '{field_name}'")

    def get_base_query(self):
        """
        Default user query that conditions can be added to
        """
        return (
            select(BiocommonsUser)
        )

    def get_admin_permissions_query(self, admin_roles: list[str]):
        """
        Get the query for only returning users the admin has permission to view/manage,
        based on group/platform roles
        """
        allowed_platforms_subquery = (
            select(Platform.id)
            .join(Platform.admin_roles)
            .where(Auth0Role.name.in_(admin_roles))
        )
        platform_access_condition = BiocommonsUser.id.in_(
            select(PlatformMembership.user_id).where(
                PlatformMembership.platform_id.in_(allowed_platforms_subquery)
            )
        )
        allowed_groups_subquery = (
            select(BiocommonsGroup.group_id)
            .join(BiocommonsGroup.admin_roles)
            .where(Auth0Role.name.in_(admin_roles))
        )
        group_access_condition = BiocommonsUser.id.in_(
            select(GroupMembership.user_id).where(
                GroupMembership.group_id.in_(allowed_groups_subquery)
            )
        )
        return or_(platform_access_condition, group_access_condition)

    def get_complete_query(self, admin_roles: list[str], pagination: PaginationParams = None) -> SelectOfScalar[BiocommonsUser]:
        """
        Return a full user query, with permissions from admin roles applied
        """
        return (
            self.get_base_query()
            .where(
                self.get_admin_permissions_query(admin_roles),
                *self.get_query_conditions())
            .distinct()
            .offset(pagination.start_index)
            .limit(pagination.per_page)
        )

    def get_query_conditions(self):
        """
        Returns a list of SQLAlchemy queries for the filters that have been set.
        The queries can be passed to where().
        Checks that the value of each field is not None, and if not calls the query method
        """
        queries = []

        for field_name in self._fields():
            field_value = getattr(self, field_name)
            if field_value is not None:
                method_name = f"{field_name}_query"
                query_method = getattr(self, method_name)
                condition = query_method()
                # conditions may be None for interacting queries like platform
                #   and platform_approval_status
                if condition is not None:
                    queries.append(condition)

        return queries

    def check_missing_ids(self, db_session: Session):
        """
        Check for any missing IDs in the database that should be present based on the queries,
        e.g. missing group IDs for a group query.
        """
        group_filter = self.filter_by is not None and self.filter_by in GROUP_MAPPING
        if self.group or group_filter:
            group_id = self.group or GROUP_MAPPING[self.filter_by]["enum"].value
            group_statement = select(BiocommonsGroup).where(BiocommonsGroup.group_id == group_id)
            group = db_session.exec(group_statement).one_or_none()
            if group is None:
                raise HTTPException(status_code=404, detail=f"Group '{self.group or self.filter_by}' not found")

        platform_filter = self.filter_by is not None and self.filter_by in PLATFORM_MAPPING
        if self.platform or platform_filter:
            platform_id = self.platform or PLATFORM_MAPPING[self.filter_by]["enum"]
            platform_statement = select(Platform).where(Platform.id == platform_id)
            platform = db_session.exec(platform_statement).one_or_none()
            if platform is None:
                raise HTTPException(status_code=404, detail=f"Platform '{platform_id}' not found")

    def platform_query(self):
        """
        Filter by platform. Note that this interacts with the platform_approval_status query,
        so we need special logic for combining them.
        :return:
        """
        conditions = [PlatformMembership.platform_id == self.platform]
        if self.platform_approval_status is not None:
            conditions.append(PlatformMembership.approval_status == self.platform_approval_status)
        platform_query = select(PlatformMembership.user_id).where(*conditions)
        return BiocommonsUser.id.in_(platform_query)

    def platform_approval_status_query(self):
        # If platform is set, let platform_query handle the combined query
        if self.platform is not None:
            return None
        platform_status_query = select(PlatformMembership.user_id).where(
            PlatformMembership.approval_status == self.platform_approval_status
        )
        return BiocommonsUser.id.in_(platform_status_query)

    def group_query(self):
        group_query = select(GroupMembership.user_id).where(
            GroupMembership.group_id == self.group
        )
        return BiocommonsUser.id.in_(group_query)

    def group_approval_status_query(self):
        group_status_query = select(GroupMembership.user_id).where(
            GroupMembership.approval_status == self.group_approval_status
        )
        return BiocommonsUser.id.in_(group_status_query)

    def email_verified_query(self):
        return BiocommonsUser.email_verified.is_(self.email_verified)

    def search_query(self):
        s = self.search.strip().lower()
        # Assume we're searching for an email address if @ present
        if "@" in s:
            return or_(
                func.lower(BiocommonsUser.email) == s,
                func.lower(BiocommonsUser.email).ilike(f"%{s}%")
            )
        else:
            return or_(
                func.lower(BiocommonsUser.username).ilike(f"%{s}%"),
                func.lower(BiocommonsUser.email).ilike(f"%{s}%")
            )

    def filter_by_query(self):
        if self.filter_by in GROUP_MAPPING:
            full_group_id = GROUP_MAPPING[self.filter_by]["enum"].value
            group_subquery = select(GroupMembership.user_id).where(
                GroupMembership.group_id == full_group_id
            )
            return BiocommonsUser.id.in_(group_subquery)
        elif self.filter_by in PLATFORM_MAPPING:
            platform_enum_value = PLATFORM_MAPPING[self.filter_by]["enum"]
            platform_subquery = select(PlatformMembership.user_id).where(
                PlatformMembership.platform_id == platform_enum_value
            )
            return BiocommonsUser.id.in_(platform_subquery)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid filter_by value '{self.filter_by}'"
            )


def get_filtered_user_query(
        admin_user: Annotated[SessionUser, Depends(get_session_user)],
        user_query: Annotated[UserQueryParams, Depends()],
        pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
):
    """
    Get an SQLAlchemy query for users based on the provided filter parameters,
    filtered to only return users the admin has permission to view/manage.
    """
    admin_roles = admin_user.access_token.biocommons_roles
    return user_query.get_complete_query(admin_roles, pagination)


@router.get("/users",
            response_model=list[BiocommonsUserResponse])
def get_users(db_session: Annotated[Session, Depends(get_db_session)],
              query_params: Annotated[UserQueryParams, Depends()],
              user_query: Annotated[SelectOfScalar[BiocommonsUser], Depends(get_filtered_user_query)]):
    """
    Get all users from the database with pagination and optional filtering.

    The admin_user must have roles that allow access to either the platform or group to
    see the users.
    """
    # Check for missing IDs in the database (e.g. group ID not found) and raise 404
    query_params.check_missing_ids(db_session)
    users = db_session.exec(user_query).all()
    return [BiocommonsUserResponse.from_db_user(user) for user in users]


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get(
    "/users/approved",
    response_model=list[BiocommonsUserResponse])
def get_approved_users(db_session: Annotated[Session, Depends(get_db_session)],
                       admin_user: Annotated[SessionUser, Depends(get_session_user)],
                       pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    user_query = get_filtered_user_query(
        admin_user=admin_user,
        user_query=UserQueryParams(platform_approval_status=ApprovalStatusEnum.APPROVED),
        pagination=pagination,
    )
    users = db_session.exec(user_query).all()
    return [BiocommonsUserResponse.from_db_user(user) for user in users]


@router.get("/users/pending",
            response_model=list[BiocommonsUserResponse])
def get_pending_users(db_session: Annotated[Session, Depends(get_db_session)],
                      admin_user: Annotated[SessionUser, Depends(get_session_user)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    user_query = get_filtered_user_query(
        admin_user=admin_user,
        user_query=UserQueryParams(platform_approval_status=ApprovalStatusEnum.PENDING),
        pagination=pagination,
    )
    users = db_session.exec(user_query).all()
    return [BiocommonsUserResponse.from_db_user(user) for user in users]


@router.get("/users/revoked",
            response_model=list[BiocommonsUserResponse])
def get_revoked_users(db_session: Annotated[Session, Depends(get_db_session)],
                      admin_user: Annotated[SessionUser, Depends(get_session_user)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    user_query = get_filtered_user_query(
        admin_user=admin_user,
        user_query=UserQueryParams(platform_approval_status=ApprovalStatusEnum.REVOKED),
        pagination=pagination,
    )
    users = db_session.exec(user_query).all()
    return [BiocommonsUserResponse.from_db_user(user) for user in users]


@router.get("/users/unverified", response_model=list[BiocommonsUserResponse])
def get_unverified_users(
    db_session: Annotated[Session, Depends(get_db_session)],
    admin_user: Annotated[SessionUser, Depends(get_session_user)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
):
    """
    Return users whose email is not verified
    """
    user_query = get_filtered_user_query(
        admin_user=admin_user,
        user_query=UserQueryParams(email_verified=False),
        pagination=pagination,
    )
    users = db_session.exec(user_query).all()
    return [BiocommonsUserResponse.from_db_user(user) for user in users]


@router.get("/users/{user_id}",
            response_model=BiocommonsUserResponse,
            dependencies=[Depends(require_admin_permission_for_user)])
def get_user(user_id: Annotated[str, UserIdParam],
             db_session: Annotated[Session, Depends(get_db_session)]):
    user = db_session.get_one(BiocommonsUser, user_id)
    return BiocommonsUserResponse.from_db_user(user)


@router.get("/users/{user_id}/details",
            response_model=Auth0UserDataWithMemberships,
            dependencies=[Depends(require_admin_permission_for_user)])
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


@router.post(
    "/users/{user_id}/verification-email/resend",
    dependencies=[Depends(require_admin_permission_for_user)],)
def resend_verification_email(user_id: Annotated[str, UserIdParam],
                              client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    client.resend_verification_email(user_id)
    return {"message": "Verification email resent."}


@router.post("/users/{user_id}/platforms/{platform_id}/approve",
             dependencies=[Depends(require_admin_permission_for_platform)])
def approve_platform_membership(user_id: Annotated[str, UserIdParam],
                                platform_id: Annotated[str, ServiceIdParam],
                                admin_record: Annotated[BiocommonsUser, Depends(get_db_user)],
                                db_session: Annotated[Session, Depends(get_db_session)]):
    platform_record = Platform.get_by_id_or_404(platform_id, db_session)
    _approve_platform_membership(
        user_id=user_id,
        platform=platform_record.id,
        admin_record=admin_record,
        db_session=db_session,
    )
    return _membership_response()


@router.post("/users/{user_id}/platforms/{platform_id}/revoke",
             dependencies=[Depends(require_admin_permission_for_platform)])
def revoke_platform_membership(user_id: Annotated[str, UserIdParam],
                               platform_id: Annotated[str, ServiceIdParam],
                               payload: RevokeServiceRequest,
                               client: Annotated[Auth0Client, Depends(get_auth0_client)],
                               admin_record: Annotated[BiocommonsUser, Depends(get_db_user)],
                               db_session: Annotated[Session, Depends(get_db_session)]):
    platform_record = Platform.get_by_id_or_404(platform_id, db_session)
    _revoke_platform_membership(
        user_id=user_id,
        platform=platform_record.id,
        reason=payload.reason,
        admin_record=admin_record,
        db_session=db_session,
        client=client,
    )
    return _membership_response()


# Need :path for group_id as may contain slashes
@router.post("/users/{user_id}/groups/{group_id:path}/approve",
             dependencies=[Depends(require_admin_permission_for_group)])
def approve_group_membership(user_id: Annotated[str, UserIdParam],
                             group_id: Annotated[str, ServiceIdParam],
                             client: Annotated[Auth0Client, Depends(get_auth0_client)],
                             admin_record: Annotated[BiocommonsUser, Depends(get_db_user)],
                             db_session: Annotated[Session, Depends(get_db_session)],
                             background_tasks: BackgroundTasks,
                             settings: Annotated[Settings, Depends(get_settings)],
                             email_service: Annotated[EmailService, Depends(get_email_service)]):
    group_record = BiocommonsGroup.get_by_id_or_404(group_id, db_session)
    membership, status_changed = _approve_group_membership(
        user_id=user_id,
        group=group_record,
        admin_record=admin_record,
        client=client,
        db_session=db_session,
    )
    if status_changed and settings.send_email and membership.user and membership.user.email:
        background_tasks.add_task(
            send_group_membership_approved_email,
            membership.user.email,
            group_record.name,
            group_record.short_name,
            settings,
            email_service,
        )
    return _membership_response()


@router.post("/users/{user_id}/groups/{group_id:path}/revoke",
             dependencies=[Depends(require_admin_permission_for_group)])
def revoke_group_membership(user_id: Annotated[str, UserIdParam],
                            group_id: Annotated[str, ServiceIdParam],
                            payload: RevokeServiceRequest,
                            client: Annotated[Auth0Client, Depends(get_auth0_client)],
                            admin_record: Annotated[BiocommonsUser, Depends(get_db_user)],
                            db_session: Annotated[Session, Depends(get_db_session)]):
    group_record = BiocommonsGroup.get_by_id_or_404(group_id, session=db_session)
    _revoke_group_membership(
        user_id=user_id,
        group=group_record,
        reason=payload.reason,
        admin_record=admin_record,
        db_session=db_session,
        client=client,
    )
    return _membership_response()


@router.get("/platforms/{platform_id}/is-admin")
def is_platform_admin(platform_id: Annotated[str, ServiceIdParam],
                      current_user: Annotated[SessionUser, Depends(get_session_user)],
                      db_session: Annotated[Session, Depends(get_db_session)]):
    return has_platform_admin_permission(platform_id=platform_id, current_user=current_user, db_session=db_session)
