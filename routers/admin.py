import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import alias, and_, false, func, or_
from sqlalchemy.sql.selectable import NamedFromClause
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
    _pm: NamedFromClause
    _bg: NamedFromClause

    # Register a query for each field here
    _QUERY_METHODS = {
        'platform': 'platform_query',
        'platform_approval_status': 'platform_approval_status_query',
        'group': 'group_query',
        'group_approval_status': 'group_approval_status_query',
        'email_verified': 'email_verified_query',
        'filter_by': 'filter_by_query',
        'search': 'search_query',
    }

    def model_post_init(self, context: Any) -> None:
        """
        Check that query methods are defined for each field.
        """
        self._pm = alias(PlatformMembership, name="pm")
        self._bg = alias(BiocommonsGroup, name="bg")
        model_fields = [
            name for name in self.__pydantic_fields__.keys()
            if not name.startswith('_')
        ]
        for field_name in model_fields:
            if field_name not in self._QUERY_METHODS or not hasattr(self, self._QUERY_METHODS[field_name]):
                raise NotImplementedError(f"Missing query method for field '{field_name}'")

    def get_db_queries(self):
        """
        Returns a list of SQLAlchemy queries that can be passed to where().
        Checks that the value of each field is not None, and if not calls the query method
        """
        queries = []

        for field_name, method_name in self._QUERY_METHODS.items():
            field_value = getattr(self, field_name)
            if field_value is not None:
                query_method = getattr(self, method_name)
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
        platform_query = (
            select(PlatformMembership.id)
            .where(PlatformMembership.platform_id == self.platform)
            .alias("platform_membership_q")
        )
        return self._pm.c.platform_id.in_(platform_query)

    def platform_approval_status_query(self):
        platform_status_query = (
            select(PlatformMembership.id)
            .where(PlatformMembership.approval_status == self.platform_approval_status)
            .alias("platform_approval_status_q")
        )
        return self._pm.c.platform_id.in_(platform_status_query)

    def group_query(self):
        group_query = (
            select(GroupMembership.id)
            .where(GroupMembership.group_id == self.group)
            .alias("group_membership_q")
        )
        return self._bg.c.group_id.in_(group_query)

    def group_approval_status_query(self):
        group_status_query = (
            select(GroupMembership.id)
            .where(GroupMembership.approval_status == self.group_approval_status)
            .alias("group_approval_status_q")
        )
        return self._bg.c.group_id.in_(group_status_query)

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
            return and_(BiocommonsUser.id == GroupMembership.user_id, GroupMembership.group_id == full_group_id)
        elif self.filter_by in PLATFORM_MAPPING:
            platform_enum_value = PLATFORM_MAPPING[self.filter_by]["enum"]
            return and_(
                BiocommonsUser.id == PlatformMembership.user_id,
                PlatformMembership.platform_id == platform_enum_value
            )
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
    # Need an alias or SQLAlchemy complains about duplicate column names
    pm_table = alias(PlatformMembership, name="pm_table")
    g_table = alias(GroupMembership, name="g_table")
    # Default query for users: join against platform and group membership
    #   in case needed for filtering
    base_query = (
        select(BiocommonsUser)
        .outerjoin(pm_table, BiocommonsUser.id == pm_table.c.user_id)
        .outerjoin(g_table, BiocommonsUser.id == g_table.c.user_id)
    )

    # Check for missing IDs in the database (e.g. group ID not found) and raise 404
    user_query.check_missing_ids(db_session)
    # Always check allowed platforms
    allowed_platforms_subquery = (
        select(Platform.id)
        .join(Platform.admin_roles)
        .where(Auth0Role.name.in_(admin_roles))
    ).alias("allowed_platforms_q")
    # Add other queries based on query params
    query_conditions = [
        pm_table.c.platform_id.in_(allowed_platforms_subquery),
        *user_query.get_db_queries()
    ]

    user_query = (
        base_query.where(*query_conditions)
        .distinct()
        .offset(pagination.start_index)
        .limit(pagination.per_page)
    )
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
