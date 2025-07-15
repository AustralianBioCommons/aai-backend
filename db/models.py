import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import AwareDatetime
from sqlalchemy import UniqueConstraint
from sqlmodel import DateTime, Field, Relationship, SQLModel
from sqlmodel import Enum as DbEnum


class ApprovalStatusEnum(str, Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REVOKED = "revoked"


class GroupMembership(SQLModel, table=True):
    """
    Stores the current approval status for a user/group pairing.
    Note: only one row per user/group, the approval history
    is kept separately in the ApprovalHistory table
    """
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="user_group_pairing"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # TODO: May want to make group and/or user_id indexes?
    group_id: str = Field(foreign_key="biocommonsgroup.group_id")
    group: "BiocommonsGroup" = Relationship(back_populates="members")
    user_id: str
    user_email: str
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    updated_by_id: str
    updated_by_email: str


class ApprovalHistory(SQLModel, table=True):
    """
    Stores the full history of approval decisions for each user
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="biocommonsgroup.group_id")
    group: "BiocommonsGroup" = Relationship(back_populates="approval_history")
    user_id: str
    user_email: str
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    updated_by_id: str
    updated_by_email: str


class GroupRoleLink(SQLModel, table=True):
    group_id: str = Field(primary_key=True, foreign_key="biocommonsgroup.group_id")
    role_id: str = Field(primary_key=True, foreign_key="auth0role.auth0_id")


class Auth0Role(SQLModel, table=True):
    auth0_id: str = Field(primary_key=True, unique=True)
    name: str
    admin_groups: list["BiocommonsGroup"] = Relationship(back_populates="admin_roles", link_model=GroupRoleLink)


class BiocommonsGroup(SQLModel, table=True):
    # Name of the group / role name in Auth0, e.g. biocommons/group/tsi
    group_id: str = Field(primary_key=True, unique=True)
    # Human-readable name for the group
    name: str = Field(unique=True)
    # List of roles that are allowed to approve group membership
    admin_roles: list[Auth0Role] = Relationship(back_populates="admin_groups", link_model=GroupRoleLink)
    members: list[GroupMembership] = Relationship(back_populates="group")
    approval_history: list[ApprovalHistory] = Relationship(back_populates="group")
