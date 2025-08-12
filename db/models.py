import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Self

from pydantic import AwareDatetime
from sqlalchemy import UniqueConstraint
from sqlmodel import DateTime, Field, Relationship, Session, select
from sqlmodel import Enum as DbEnum

from auth0.client import Auth0Client
from db.core import BaseModel
from schemas.biocommons import Auth0UserData
from schemas.user import SessionUser


class ApprovalStatusEnum(str, Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REVOKED = "revoked"


class PlatformEnum(str, Enum):
    GALAXY = "galaxy"
    BPA_DATA_PORTAL = "bpa_data_portal"


class BiocommonsUser(BaseModel, table=True):
    __tablename__ = "biocommons_user"
    # Auth0 ID
    id: str = Field(primary_key=True)
    # Note: sqlmodel can't validate emails easily.
    #   Use a separate data model to validate this
    email: str = Field(unique=True)
    username: str = Field(unique=True)
    created_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)

    platform_memberships: list["PlatformMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"foreign_keys": "PlatformMembership.user_id"}
    )
    group_memberships: list["GroupMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"foreign_keys": "GroupMembership.user_id"}
    )

    @classmethod
    def create_from_auth0(cls, auth0_id: str, auth0_client: Auth0Client) -> Self:
        user_data = auth0_client.get_user(user_id=auth0_id)
        return cls.from_auth0_data(user_data)

    @classmethod
    def from_auth0_data(cls, data: Auth0UserData) -> Self:
        return cls(
            id=data.user_id,
            email=data.email,
            username=data.username
        )

    @classmethod
    def get_or_create(cls, auth0_id: str, db_session: Session, auth0_client: Auth0Client) -> Self:
        """
        Get the user from the DB, or create it from Auth0 data if it doesn't exist.
        """
        user = db_session.get(cls, auth0_id)
        if user is None:
            user = cls.create_from_auth0(auth0_id=auth0_id, auth0_client=auth0_client)
            db_session.add(user)
            db_session.commit()
        return user


class PlatformMembership(BaseModel, table=True):
    __table_args__ = (
        UniqueConstraint("platform_id", "user_id", name="platform_user_id_platform_id"),
    )
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    platform_id: PlatformEnum = Field(sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(back_populates="platform_memberships",
                                          sa_relationship_kwargs={"foreign_keys": "PlatformMembership.user_id",})
    approval_status: ApprovalStatusEnum = Field(sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum"))
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "PlatformMembership.updated_by_id",})




class PlatformMembershipHistory(BaseModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    platform_id: PlatformEnum = Field(sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "PlatformMembershipHistory.user_id",})
    approval_status: ApprovalStatusEnum = Field(sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum"))
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "PlatformMembershipHistory.updated_by_id",})


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
    user: "BiocommonsUser" = Relationship(back_populates="group_memberships",
                                          sa_relationship_kwargs={"foreign_keys": "GroupMembership.user_id",})
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "GroupMembership.updated_by_id",})

    @classmethod
    def get_by_user_id(cls, user_id: str, group_id: str, session: Session) -> Self | None:
        return session.exec(
            select(GroupMembership)
            .where(GroupMembership.user_id == user_id,
                   GroupMembership.group_id == group_id)
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

    def save_history(self, session: Session, commit: bool = True) -> 'GroupMembershipHistory':
        history = GroupMembershipHistory(
            group=self.group,
            user=self.user,
            approval_status=self.approval_status,
            updated_at=self.updated_at,
            updated_by=self.updated_by,
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


class GroupMembershipHistory(BaseModel, table=True):
    """
    Stores the full history of approval decisions for each user
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    group_id: str = Field(foreign_key="biocommonsgroup.group_id")
    group: "BiocommonsGroup" = Relationship(back_populates="approval_history")
    user_id: str = Field(foreign_key="biocommons_user.id")
    user: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "GroupMembershipHistory.user_id",})
    approval_status: ApprovalStatusEnum = Field(
        sa_type=DbEnum(ApprovalStatusEnum, name="ApprovalStatusEnum")
    )
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    # Nullable: some memberships are automatically approved
    updated_by_id: str | None = Field(foreign_key="biocommons_user.id", nullable=True)
    updated_by: "BiocommonsUser" = Relationship(sa_relationship_kwargs={"foreign_keys": "GroupMembershipHistory.updated_by_id",})

    @classmethod
    def get_by_user_id(cls, user_id: str, group_id: str, session: Session) -> list[Self] | None:
        return session.exec(
            select(GroupMembershipHistory)
            .where(GroupMembershipHistory.user_id == user_id,
                   GroupMembershipHistory.group_id == group_id)
            .order_by(GroupMembershipHistory.updated_at.desc())
        ).all()


class GroupRoleLink(BaseModel, table=True):
    group_id: str = Field(primary_key=True, foreign_key="biocommonsgroup.group_id")
    role_id: str = Field(primary_key=True, foreign_key="auth0role.id")


class Auth0Role(BaseModel, table=True):
    id: str = Field(primary_key=True, unique=True)
    name: str
    description: str = Field(default="")
    admin_groups: list["BiocommonsGroup"] = Relationship(back_populates="admin_roles", link_model=GroupRoleLink)

    @classmethod
    def get_or_create_by_id(cls, auth0_id: str, session: Session, auth0_client: Auth0Client) -> Self:
        # Try to get from the DB
        role = session.get(Auth0Role, auth0_id)
        if role is not None:
            return role
        # Try to get from the API and save to the DB
        role_data = auth0_client.get_role_by_id(role_id=auth0_id)
        role = cls(
            id=role_data.id,
            name=role_data.name,
            description=role_data.description
        )
        session.add(role)
        session.commit()
        return role

    @classmethod
    def get_or_create_by_name(cls, name: str, session: Session, auth0_client: Auth0Client = None) -> Self:
        # Try to get from the DB
        role = session.exec(select(Auth0Role).where(Auth0Role.name == name)).one_or_none()
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
    admin_roles: list[Auth0Role] = Relationship(back_populates="admin_groups", link_model=GroupRoleLink)
    members: list[GroupMembership] = Relationship(back_populates="group")
    approval_history: list[GroupMembershipHistory] = Relationship(back_populates="group")

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
PlatformMembership.model_rebuild()
PlatformMembershipHistory.model_rebuild()
GroupMembership.model_rebuild()
GroupMembershipHistory.model_rebuild()
