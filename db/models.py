import uuid
from datetime import datetime, timezone
from typing import Self

from pydantic import AwareDatetime
from sqlalchemy import Column, String, UniqueConstraint
from sqlmodel import DateTime, Field, Relationship, Session, select
from sqlmodel import Enum as DbEnum

import schemas
from auth0.client import Auth0Client
from db.core import BaseModel
from db.types import (
    ApprovalStatusEnum,
    GroupMembershipData,
    PlatformEnum,
    PlatformMembershipData,
)
from schemas.user import SessionUser


class BiocommonsUser(BaseModel, table=True):
    __tablename__ = "biocommons_user"
    # Auth0 ID
    id: str = Field(primary_key=True)
    # Note: sqlmodel can't validate emails easily.
    #   Use a separate data model to validate this
    email: str = Field(unique=True)
    email_verified: bool = Field(default=False, nullable=False)
    username: str = Field(unique=True)
    created_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime
    )

    platform_memberships: list["PlatformMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"foreign_keys": "PlatformMembership.user_id"},
    )
    group_memberships: list["GroupMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"foreign_keys": "GroupMembership.user_id"},
    )

    @classmethod
    def create_from_auth0(cls, auth0_id: str, auth0_client: Auth0Client) -> Self:
        """
        Get user data from Auth0 API and create a new BiocommonsUser object.
        """
        user_data = auth0_client.get_user(user_id=auth0_id)
        return cls.from_auth0_data(user_data)

    @classmethod
    def from_auth0_data(cls, data: 'schemas.biocommons.Auth0UserData') -> Self:
        """
        Create a new BiocommonsUser object from Auth0 user data (no API call).
        """
        return cls(id=data.user_id, email=data.email, username=data.username, email_verified=data.email_verified)

    @classmethod
    def get_or_create(
        cls, auth0_id: str, db_session: Session, auth0_client: Auth0Client
    ) -> Self:
        """
        Get the user from the DB, or create it from Auth0 data if it doesn't exist.
        """
        user = db_session.get(cls, auth0_id)
        if user is None:
            user = cls.create_from_auth0(auth0_id=auth0_id, auth0_client=auth0_client)
            db_session.add(user)
            db_session.commit()
        return user

    def update_from_auth0(self, auth0_id: str, auth0_client: Auth0Client) -> Self:
        """
        Fetch user data from Auth0 and update this object with it.
        Currently only updates email_verified.
        """
        user_data = auth0_client.get_user(user_id=auth0_id)
        return self.update_from_auth0_data(user_data)

    def update_from_auth0_data(self, data: 'schemas.biocommons.Auth0UserData') -> Self:
        """
        Update this object with data from Auth0, without fetching.
        Currently only updates email_verified.
        """
        self.email_verified = data.email_verified
        return self

    def add_platform_membership(
        self, platform: PlatformEnum, db_session: Session, auto_approve: bool = False
    ) -> "PlatformMembership":
        membership = PlatformMembership(
            platform_id=platform,
            user=self,
            approval_status=ApprovalStatusEnum.APPROVED
            if auto_approve
            else ApprovalStatusEnum.PENDING,
            updated_by=None,
        )
        db_session.add(membership)
        db_session.flush()
        membership.save_history(db_session)
        return membership

    def add_group_membership(
        self, group_id: str, db_session: Session, auto_approve: bool = False
    ) -> "GroupMembership":
        membership = GroupMembership(
            group_id=group_id,
            user_id=self.id,
            approval_status=ApprovalStatusEnum.APPROVED if auto_approve else ApprovalStatusEnum.PENDING,
            updated_by_id=None,
        )
        db_session.add(membership)
        membership.save_history(db_session)
        return membership


class PlatformRoleLink(BaseModel, table=True):
    platform_id: PlatformEnum = Field(primary_key=True, foreign_key="platform.id", sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    role_id: str = Field(primary_key=True, foreign_key="auth0role.id")


class Platform(BaseModel, table=True):
    id: PlatformEnum = Field(primary_key=True, unique=True, sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    # Human-readable name for the platform
    name: str = Field(unique=True)
    admin_roles: list["Auth0Role"] = Relationship(
        back_populates="admin_platforms", link_model=PlatformRoleLink,
    )
    members: list["PlatformMembership"] = Relationship(back_populates="platform")


class PlatformMembership(BaseModel, table=True):
    __table_args__ = (
        UniqueConstraint("platform_id", "user_id", name="platform_user_id_platform_id"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    platform_id: PlatformEnum = Field(foreign_key="platform.id", sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    platform: Platform = Relationship(back_populates="members")
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(
        back_populates="platform_memberships",
        sa_relationship_kwargs={
            "foreign_keys": "PlatformMembership.user_id",
        },
    )
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime
    )
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "PlatformMembership.updated_by_id",
        }
    )
    revocation_reason: str | None = Field(
        default=None,
        sa_column=Column(String(1024), nullable=True)
    )

    def save_history(self, session: Session) -> "PlatformMembershipHistory":
        # Make sure this object is in the session before accessing relationships
        if self not in session:
            session.add(self)
        session.flush()  # Ensure relationships are loaded

        history = PlatformMembershipHistory(
            platform_id=self.platform_id,
            user=self.user,
            approval_status=self.approval_status,
            updated_at=self.updated_at,
            updated_by=self.updated_by,
            reason=self.revocation_reason,
        )
        session.add(history)
        return history

    def get_data(self) -> PlatformMembershipData:
        """
        Get a data model for this membership, suitable for returning to the frontend.
        """
        if self.updated_by is not None:
            updated_by = self.updated_by.email
        else:
            updated_by = '(automatic)'
        return PlatformMembershipData(
            id=self.id,
            platform_id=self.platform_id,
            user_id=self.user_id,
            approval_status=self.approval_status,
            updated_by=updated_by,
            revocation_reason=self.revocation_reason,
        )


class PlatformMembershipHistory(BaseModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    platform_id: PlatformEnum = Field(sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "PlatformMembershipHistory.user_id",
        }
    )
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime
    )
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "PlatformMembershipHistory.updated_by_id",
        }
    )
    reason: str | None = Field(
        default=None,
        sa_column=Column(String(1024), nullable=True)
    )


class GroupMembership(BaseModel, table=True):
    """
    Stores the current approval status for a user/group pairing.
    Note: only one row per user/group, the approval history
    is kept separately in the GroupMembershipHistory table
    """

    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="user_group_pairing"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="biocommonsgroup.group_id")
    group: "BiocommonsGroup" = Relationship(back_populates="members")
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(
        back_populates="group_memberships",
        sa_relationship_kwargs={
            "foreign_keys": "GroupMembership.user_id",
        },
    )
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime
    )
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "GroupMembership.updated_by_id",
        }
    )
    revocation_reason: str | None = Field(
        default=None,
        sa_column=Column(String(1024), nullable=True)
    )

    @classmethod
    def get_by_user_id(
        cls, user_id: str, group_id: str, session: Session
    ) -> Self | None:
        return session.exec(
            select(GroupMembership).where(
                GroupMembership.user_id == user_id, GroupMembership.group_id == group_id
            )
        ).one_or_none()

    def save(self, session: Session, commit: bool = True) -> Self:
        """
        Save the current object, and create a new GroupMembershipHistory row for it
        """
        session.add(self)
        # Don't commit history until the main object is committed
        self.save_history(session, commit=False)
        if commit:
            session.commit()
        return self

    def save_history(
        self, session: Session, commit: bool = True
    ) -> "GroupMembershipHistory":
        # Make sure this object is in the session before accessing relationships
        if self not in session:
            session.add(self)
        session.flush()

        history = GroupMembershipHistory(
            group_id=self.group_id,
            user_id=self.user_id,
            approval_status=self.approval_status,
            updated_at=self.updated_at,
            updated_by=self.updated_by,
            reason=self.revocation_reason,
        )
        session.add(history)
        if commit:
            session.commit()
        return history

    def grant_auth0_role(self, auth0_client: Auth0Client):
        if not self.approval_status == ApprovalStatusEnum.APPROVED:
            raise ValueError("User is not approved")
        role = auth0_client.get_role_by_name(self.group_id)
        auth0_client.add_roles_to_user(user_id=self.user_id, role_id=role.id)
        return True

    def get_data(self) -> GroupMembershipData:
        """
        Get a data model for this membership, suitable for returning to the frontend.
        """
        if self.updated_by is not None:
            updated_by = self.updated_by.email
        else:
            updated_by = '(automatic)'
        return GroupMembershipData(
            id=self.id,
            group_id=self.group_id,
            group_name=self.group.name,
            approval_status=self.approval_status,
            updated_by=updated_by,
            revocation_reason=self.revocation_reason,
        )


class GroupMembershipHistory(BaseModel, table=True):
    """
    Stores the full history of approval decisions for each user
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="biocommonsgroup.group_id")
    group: "BiocommonsGroup" = Relationship(back_populates="approval_history")
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "GroupMembershipHistory.user_id",
        }
    )
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime
    )
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "GroupMembershipHistory.updated_by_id",
        }
    )
    reason: str | None = Field(
        default=None,
        sa_column=Column(String(1024), nullable=True)
    )

    @classmethod
    def get_by_user_id(
        cls, user_id: str, group_id: str, session: Session
    ) -> list[Self] | None:
        return session.exec(
            select(GroupMembershipHistory)
            .where(
                GroupMembershipHistory.user_id == user_id,
                GroupMembershipHistory.group_id == group_id,
            )
            .order_by(GroupMembershipHistory.updated_at.desc())
        ).all()


class GroupRoleLink(BaseModel, table=True):
    group_id: str = Field(primary_key=True, foreign_key="biocommonsgroup.group_id")
    role_id: str = Field(primary_key=True, foreign_key="auth0role.id")


class Auth0Role(BaseModel, table=True):
    id: str = Field(primary_key=True, unique=True)
    name: str
    description: str = Field(default="")
    admin_groups: list["BiocommonsGroup"] = Relationship(
        back_populates="admin_roles", link_model=GroupRoleLink
    )
    admin_platforms: list["Platform"] = Relationship(
        back_populates="admin_roles", link_model=PlatformRoleLink
    )

    @classmethod
    def get_or_create_by_id(
        cls, auth0_id: str, session: Session, auth0_client: Auth0Client
    ) -> Self:
        # Try to get from the DB
        role = session.get(Auth0Role, auth0_id)
        if role is not None:
            return role
        # Try to get from the API and save to the DB
        role_data = auth0_client.get_role_by_id(role_id=auth0_id)
        role = cls(
            id=role_data.id, name=role_data.name, description=role_data.description
        )
        session.add(role)
        session.commit()
        return role

    @classmethod
    def get_or_create_by_name(
        cls, name: str, session: Session, auth0_client: Auth0Client = None
    ) -> Self:
        # Try to get from the DB
        role = session.exec(
            select(Auth0Role).where(Auth0Role.name == name)
        ).one_or_none()
        if role is not None:
            return role
        # Try to get from the API and save to the DB
        role_data = auth0_client.get_role_by_name(name=name)
        role = cls(**role_data.model_dump())
        session.add(role)
        session.commit()
        return role


class BiocommonsGroup(BaseModel, table=True):
    # Name of the group / role name in Auth0, e.g. biocommons/group/tsi
    group_id: str = Field(primary_key=True, unique=True)
    # Human-readable name for the group
    name: str = Field(unique=True)
    # List of roles that are allowed to approve group membership
    admin_roles: list[Auth0Role] = Relationship(
        back_populates="admin_groups", link_model=GroupRoleLink
    )
    members: list[GroupMembership] = Relationship(back_populates="group")
    approval_history: list[GroupMembershipHistory] = Relationship(
        back_populates="group"
    )

    def get_admins(self, auth0_client: Auth0Client) -> set[str]:
        """
        Get all admin emails for this group from the Auth0 API, returning a set of emails.
        """
        admins = set()
        for role in self.admin_roles:
            role_admins = auth0_client.get_all_role_users(role_id=role.id)
            for admin in role_admins:
                admins.add(admin.email)
        return admins

    def user_is_admin(self, user: SessionUser) -> bool:
        user_roles = user.access_token.biocommons_roles
        admin_role_names = [role.name for role in self.admin_roles]
        for role in user_roles:
            if role in admin_role_names:
                return True
        return False


# Update all model references
BiocommonsUser.model_rebuild()
Platform.model_rebuild()
PlatformMembership.model_rebuild()
PlatformMembershipHistory.model_rebuild()
GroupMembership.model_rebuild()
GroupMembershipHistory.model_rebuild()
