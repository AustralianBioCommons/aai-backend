import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, or_
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
        description="Filter users by group ('tsi', 'bpa_galaxy') or platform ('galaxy', 'bpa_data_portal')"
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
        Default user query that conditions can be added to - join against platform and group membership
        """
        return (
            select(BiocommonsUser)
        )

    def get_complete_query(self, pagination: PaginationParams = None):
        """
        Return a full user query - can be used when no custom filters are required.
        """
        return (
            self.get_base_query()
            .where(*self.get_query_conditions())
            .distinct()
            .offset(pagination.start_index)
            .limit(pagination.per_page)
        )

    def get_query_conditions(self):
        """
        Returns a list of SQLAlchemy queries that can be passed to where().
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
                    queries.append(query_method())

        return queries

    def check_missing_ids(self, db_session: Session):
        """
        Check for any missing IDs in the database that should be present based on the queries,
        e.g. missing group IDs for a group query.
        """
        if self.group or self.filter_by in GROUP_MAPPING:
            group_id = self.group or GROUP_MAPPING[self.filter_by]["enum"].value
            group_statement = select(BiocommonsGroup).where(BiocommonsGroup.group_id == group_id)
            group = db_session.exec(group_statement).one_or_none()
            if group is None:
                raise HTTPException(status_code=404, detail=f"Group '{self.group or self.filter_by}' not found")

        if self.platform or self.filter_by in PLATFORM_MAPPING:
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
        platform_query = (
            select(PlatformMembership.user_id)
            .where(*conditions)
            .alias("platform_membership_q")
        )
        return BiocommonsUser.id.in_(platform_query)

    def platform_approval_status_query(self):
        # If platform is set, let platform_query handle the combined query
        if self.platform is not None:
            return None
        platform_status_query = (
            select(PlatformMembership.user_id)
            .where(PlatformMembership.approval_status == self.platform_approval_status)
            .alias("platform_approval_status_q")
        )
        return BiocommonsUser.id.in_(platform_status_query)

    def group_query(self):
        group_query = (
            select(GroupMembership.user_id)
            .where(GroupMembership.group_id == self.group)
            .alias("group_membership_q")
        )
        return BiocommonsUser.id.in_(group_query)

    def group_approval_status_query(self):
        group_status_query = (
            select(GroupMembership.user_id)
            .where(GroupMembership.approval_status == self.group_approval_status)
            .alias("group_approval_status_q")
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


@router.get("/users",
            response_model=list[BiocommonsUserResponse])
def get_users(admin_user: Annotated[SessionUser, Depends(get_current_user)],
              db_session: Annotated[Session, Depends(get_db_session)],
              user_query: Annotated[UserQueryParams, Query()],
              pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
              ):
    """
    Get all users from the database with pagination and optional filtering.
    """
    admin_roles = admin_user.access_token.biocommons_roles
    # Default query for users: join against platform and group membership
    #   in case needed for filtering
    base_query = select(BiocommonsUser)

    # Check for missing IDs in the database (e.g. group ID not found) and raise 404
    user_query.check_missing_ids(db_session)
    # Always check allowed platforms
    allowed_platforms_subquery = (
        select(Platform.id)
        .join(Platform.admin_roles)
        .where(Auth0Role.name.in_(admin_roles))
    ).alias("allowed_platforms_q")

    platform_access_condition = BiocommonsUser.id.in_(
        select(PlatformMembership.user_id).where(
            PlatformMembership.platform_id.in_(allowed_platforms_subquery)
        )
    )
    # Add other queries based on query params
    query_conditions = [
        platform_access_condition,
        *user_query.get_query_conditions()
    ]

    final_query = (
        base_query.where(*query_conditions)
        .distinct()
        .offset(pagination.start_index)
        .limit(pagination.per_page)
    )
    users = db_session.exec(final_query).all()
    return users


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get(
    "/users/approved",
    response_model=list[BiocommonsUserResponse])
def get_approved_users(db_session: Annotated[Session, Depends(get_db_session)],
                       pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    approved_query = UserQueryParams(platform_approval_status=ApprovalStatusEnum.APPROVED).get_complete_query(pagination)
    return db_session.exec(approved_query).all()


@router.get("/users/pending",
            response_model=list[BiocommonsUserResponse])
def get_pending_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    pending_query = UserQueryParams(platform_approval_status=ApprovalStatusEnum.PENDING).get_complete_query(pagination)
    return db_session.exec(pending_query).all()


@router.get("/users/revoked",
            response_model=list[BiocommonsUserResponse])
def get_revoked_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    revoked_query = UserQueryParams(platform_approval_status=ApprovalStatusEnum.REVOKED).get_complete_query(pagination)
    return db_session.exec(revoked_query).all()


@router.get("/users/unverified", response_model=list[BiocommonsUserResponse])
def get_unverified_users(
    db_session: Annotated[Session, Depends(get_db_session)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
):
    """
    Return users whose email is not verified
    """
    query = UserQueryParams(email_verified=False).get_complete_query(pagination)
    return db_session.exec(query).all()


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
