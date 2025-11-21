import uuid
from datetime import datetime, timedelta, timezone
from logging import getLogger
from typing import Optional, Self

from pydantic import AwareDatetime
from sqlalchemy import Column, String, Text, UniqueConstraint
from sqlmodel import DateTime, Field, Relationship, Session, select
from sqlmodel import Enum as DbEnum
from starlette.exceptions import HTTPException

import schemas
from auth0.client import Auth0Client
from db.core import BaseModel, SoftDeleteModel
from db.types import (
    ApprovalStatusEnum,
    EmailStatusEnum,
    GroupMembershipData,
    PlatformEnum,
    PlatformMembershipData,
)
from schemas.auth0 import get_platform_id_from_role_name
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser

logger = getLogger(__name__)


class BiocommonsUser(SoftDeleteModel, table=True):
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
    def get_by_id(cls, user_id: str, session: Session) -> Self | None:
        return session.get(BiocommonsUser, user_id)

    @classmethod
    def has_platform_membership(cls, user_id: str, platform_id: PlatformEnum, session: Session) -> bool:
        """
        Check if a user has a membership for a specific platform.
        """
        result = session.exec(
            select(PlatformMembership.id).where(
                PlatformMembership.user_id == user_id,
                PlatformMembership.platform_id == platform_id,
                PlatformMembership.approval_status == ApprovalStatusEnum.APPROVED,
            )
        ).first()
        return result is not None

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

    def delete(self, session: Session, commit: bool = False) -> "BiocommonsUser":
        """
        Soft delete the user and cascade the soft delete to related memberships.
        """
        for membership in list(self.platform_memberships or []):
            if not membership.is_deleted:
                membership.delete(session, commit=False)
        for membership in list(self.group_memberships or []):
            if not membership.is_deleted:
                membership.delete(session, commit=False)

        super().delete(session, commit=commit)
        return self

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

    def add_role(self, role_name: str, auth0_client: Auth0Client, session: Session) -> None:
        """
        Add a role to the user in Auth0. The role must already exist in Auth0 and the DB.
        """
        role = Auth0Role.get_by_name(role_name, session)
        if role is None:
            raise ValueError(f"Role {role_name} not found in DB")
        auth0_client.add_roles_to_user(user_id=self.id, role_id=role.id)

    def add_platform_membership(
        self, platform: PlatformEnum, db_session: Session, auth0_client: Auth0Client, auto_approve: bool = False
    ) -> "PlatformMembership":
        """
        Create a platform membership for this user. If auto_approve is True,
        add the Auth0 role for the platform to the user's roles
        """
        db_platform = Platform.get_by_id(platform, db_session)
        if auto_approve:
            logger.info(f"Adding role {db_platform.platform_role.name} to user {self.id}")
            self.add_role(role_name=db_platform.platform_role.name, auth0_client=auth0_client, session=db_session)
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

    def is_any_platform_admin(self, access_token: AccessTokenPayload, db_session: Session) -> bool:
        """
        Check if the user is an admin on any platform.
        """
        if access_token.sub != self.id:
            raise ValueError("User ID does not match access token")
        all_admin_roles = Platform.get_all_admin_roles(db_session)
        for role in all_admin_roles:
            if role.name in access_token.biocommons_roles:
                return True
        return False

    def is_any_group_admin(self, access_token: AccessTokenPayload, db_session: Session) -> bool:
        """
        Check if the user is an admin on any group.
        """
        if access_token.sub != self.id:
            raise ValueError("User ID does not match access token")
        all_admin_roles = BiocommonsGroup.get_all_admin_roles(db_session)
        for role in all_admin_roles:
            if role.name in access_token.biocommons_roles:
                return True
        return False


class PlatformRoleLink(SoftDeleteModel, table=True):
    platform_id: PlatformEnum = Field(primary_key=True, foreign_key="platform.id", sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    role_id: str = Field(primary_key=True, foreign_key="auth0role.id")


class Platform(SoftDeleteModel, table=True):
    id: PlatformEnum = Field(primary_key=True, unique=True, sa_type=DbEnum(PlatformEnum, name="PlatformEnum"))
    # Role name in Auth0 for basic access to the platform
    role_id: str | None = Field(foreign_key="auth0role.id", ondelete="SET NULL", nullable=True)
    platform_role: "Auth0Role" = Relationship(back_populates="platform")
    # Human-readable name for the platform
    name: str = Field(unique=True)
    admin_roles: list["Auth0Role"] = Relationship(
        back_populates="admin_platforms", link_model=PlatformRoleLink,
    )
    members: list["PlatformMembership"] = Relationship(back_populates="platform")

    @classmethod
    def create_from_auth0_role(cls, role: "Auth0Role", session: Session, commit: bool = True) -> Self:
        platform_id = get_platform_id_from_role_name(role.name)
        default_admin_role = Auth0Role.get_by_name(f"biocommons/role/{platform_id}/admin", session=session)
        if default_admin_role is None:
            raise ValueError(f"Default admin role for platform {platform_id} not found in DB. ")
        platform = cls(
            id=platform_id,
            role_id=role.id,
            name=role.description,
            admin_roles=[default_admin_role],
        )
        session.add(platform)
        if commit:
            session.commit()
        session.flush()
        return platform

    def update_from_auth0_role(self, role: "Auth0Role", session: Session, commit: bool = True) -> Self:
        # May need to update the ID if a role has been deleted and recreated
        self.role_id = role.id
        self.name = role.description
        session.add(self)
        if commit:
            session.commit()
        session.flush()
        return self

    @classmethod
    def get_by_id(cls, platform_id: PlatformEnum, session: Session) -> Self | None:
        return session.get(cls, platform_id)

    @classmethod
    def get_by_id_or_404(cls, platform_id: PlatformEnum, session: Session) -> Self:
        platform = cls.get_by_id(platform_id, session)
        if platform is None:
            raise HTTPException(status_code=404, detail=f"Platform {platform_id} not found")
        return platform

    @classmethod
    def get_all_admin_roles(cls, session: Session) -> list["Auth0Role"]:
        return session.exec(
            select(Auth0Role)
            .join(PlatformRoleLink, Auth0Role.id == PlatformRoleLink.role_id)
            .distinct()
        ).all()

    @classmethod
    def get_for_admin_roles(cls, role_names: list[str], session: Session) -> list[Self]:
        """
        Given a list of role names, return a list of platforms
        where the roles grant admin rights.
        """
        return session.exec(
            select(Platform)
            .join(Platform.admin_roles)
            .where(Auth0Role.name.in_(role_names))
        ).all()

    @classmethod
    def get_approved_by_user_id(cls, user_id: str, session: Session) -> list[Self] | None:
        return session.exec(
            select(Platform)
            .join(PlatformMembership)
            .where(PlatformMembership.user_id == user_id)
            .where(PlatformMembership.approval_status == ApprovalStatusEnum.APPROVED)
        ).all()

    def user_is_admin(self, user: SessionUser) -> bool:
        """
        Check if the user is an admin on this platform (based on access token roles).
        """
        for role in user.access_token.biocommons_roles:
            if role in {ar.name for ar in self.admin_roles}:
                return True
        return False

    def delete(self, session: Session, commit: bool = False) -> "Platform":
        memberships = list(self.members or [])
        for membership in memberships:
            if not membership.is_deleted:
                membership.delete(session, commit=False)

        super().delete(session, commit=commit)
        return self


class PlatformMembership(SoftDeleteModel, table=True):
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

    @classmethod
    def get_by_user_id(
        cls, user_id: str, session: Session, approval_status: set[ApprovalStatusEnum] | ApprovalStatusEnum | None = None
    ) -> list[Self]:
        query = (
            select(PlatformMembership)
            .where(PlatformMembership.user_id == user_id)
        )
        if isinstance(approval_status, set):
            query = query.where(PlatformMembership.approval_status.in_(approval_status))
        elif isinstance(approval_status, ApprovalStatusEnum):
            query = query.where(PlatformMembership.approval_status == approval_status)
        return session.exec(query).all()

    @classmethod
    def get_by_user_id_and_platform_id(cls, user_id: str, platform_id: PlatformEnum, session: Session) -> Self | None:
        return session.exec(
            select(PlatformMembership).where(
                PlatformMembership.user_id == user_id,
                PlatformMembership.platform_id == platform_id,
            )
        ).one_or_none()

    @classmethod
    def get_by_user_id_and_platform_id_or_404(cls, user_id: str, platform_id: PlatformEnum, session: Session) -> Self:
        membership = cls.get_by_user_id_and_platform_id(user_id, platform_id, session)
        if membership is None:
            raise HTTPException(status_code=404, detail=f"Platform membership for user {user_id} on platform {platform_id} not found")
        return membership

    def delete(self, session: Session, commit: bool = False) -> "PlatformMembership":
        history_entries = session.exec(
            select(PlatformMembershipHistory)
            .where(
                PlatformMembershipHistory.user_id == self.user_id,
                PlatformMembershipHistory.platform_id == self.platform_id,
            )
        ).all()

        super().delete(session, commit=False)

        for history in history_entries:
            if not history.is_deleted:
                history.delete(session, commit=False)

        if commit:
            session.commit()
            session.expunge(self)
        return self

    def save_history(self, session: Session, commit: bool = False) -> "PlatformMembershipHistory":
        # Make sure this object is in the session before accessing relationships
        if self not in session:
            session.add(self)
        session.flush()  # Ensure relationships are loaded

        history = PlatformMembershipHistory(
            platform_id=self.platform_id,
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

    def revoke_auth0_role(self, auth0_client: Auth0Client) -> bool:
        """
        Remove the Auth0 role associated with this platform membership.
        """
        if self.approval_status != ApprovalStatusEnum.APPROVED:
            return False
        platform_value = self.platform_id.value if isinstance(self.platform_id, PlatformEnum) else self.platform_id
        role_name = f"biocommons/platform/{platform_value}"
        role = auth0_client.get_role_by_name(role_name)
        auth0_client.remove_roles_from_user(user_id=self.user_id, role_id=role.id)
        return True

    def grant_auth0_role(self, auth0_client: Auth0Client) -> bool:
        """
        Assign the Auth0 role backing this platform membership when access is granted.
        """
        if self.approval_status != ApprovalStatusEnum.APPROVED:
            raise ValueError("User is not approved")
        if self.platform is None or self.platform.platform_role is None:
            raise ValueError("Platform role is not configured")
        role = self.platform.platform_role
        auth0_client.add_roles_to_user(user_id=self.user_id, role_id=role.id)
        return True

    def revoke(
        self,
        *,
        auth0_client: Auth0Client,
        reason: str | None,
        updated_by: Optional["BiocommonsUser"],
        session: Session,
        commit: bool = True,
    ) -> bool:
        """
        Revoke the membership by removing the Auth0 role (if present) and
        persisting the revoked status in the database.

        :return: True when an Auth0 role removal call was performed.
        """
        role_revoked = self.revoke_auth0_role(auth0_client)
        self.approval_status = ApprovalStatusEnum.REVOKED
        self.revocation_reason = reason
        self.updated_at = datetime.now(timezone.utc)
        self.updated_by = updated_by
        session.add(self)
        self.save_history(session, commit=False)
        if commit:
            session.commit()
        return role_revoked

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
            platform_name=self.platform.name,
            user_id=self.user_id,
            approval_status=self.approval_status,
            updated_by=updated_by,
            revocation_reason=self.revocation_reason,
        )



class PlatformMembershipHistory(SoftDeleteModel, table=True):
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


class GroupMembership(SoftDeleteModel, table=True):
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
        cls, user_id: str, session: Session, approval_status: set[ApprovalStatusEnum] | ApprovalStatusEnum | None = None
    ) -> list[Self]:
        query = (
            select(GroupMembership)
            .where(
                GroupMembership.user_id == user_id,
            )
        )
        if isinstance(approval_status, set):
            query = query.where(GroupMembership.approval_status.in_(approval_status))
        elif isinstance(approval_status, ApprovalStatusEnum):
            query = query.where(GroupMembership.approval_status == approval_status)
        return session.exec(query).all()

    @classmethod
    def get_by_user_id_and_group_id(cls, user_id: str, group_id: str, session: Session) -> Self | None:
        return session.exec(
            select(GroupMembership).where(
                GroupMembership.user_id == user_id,
                GroupMembership.group_id == group_id,
            )
        ).one_or_none()

    def delete(self, session: Session, commit: bool = False) -> "GroupMembership":
        history_entries = session.exec(
            select(GroupMembershipHistory)
            .where(
                GroupMembershipHistory.user_id == self.user_id,
                GroupMembershipHistory.group_id == self.group_id,
            )
        ).all()

        super().delete(session, commit=False)

        for history in history_entries:
            if not history.is_deleted:
                history.delete(session, commit=False)

        if commit:
            session.commit()
            session.expunge(self)
        return self

    @classmethod
    def get_by_user_id_and_group_id_or_404(cls, user_id: str, group_id: str, session: Session) -> Self:
        membership = cls.get_by_user_id_and_group_id(user_id, group_id, session)
        if membership is None:
            raise HTTPException(status_code=404, detail=f"Group membership for user {user_id} on group {group_id} not found")
        return membership

    @classmethod
    def has_group_membership(cls, user_id: str, group_id: str, session: Session) -> bool:
        result = session.exec(
            select(GroupMembership.id).where(
                GroupMembership.user_id == user_id,
                GroupMembership.group_id == group_id,
                GroupMembership.approval_status == ApprovalStatusEnum.APPROVED,
            )
        ).first()
        return result is not None



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

    def revoke_auth0_role(self, auth0_client: Auth0Client):
        """
        Remove the Auth0 role backing this group membership when access is revoked.
        """
        if self.approval_status != ApprovalStatusEnum.APPROVED:
            return False
        role = auth0_client.get_role_by_name(self.group_id)
        auth0_client.remove_roles_from_user(user_id=self.user_id, role_id=role.id)
        return True

    def revoke(
        self,
        *,
        auth0_client: Auth0Client,
        reason: str | None,
        updated_by: Optional["BiocommonsUser"],
        session: Session,
        commit: bool = True,
    ) -> bool:
        """
        Revoke this membership by removing its Auth0 role (when applicable) and
        persisting the revoked status in the database.

        :return: True when an Auth0 role removal call was performed.
        """
        role_revoked = self.revoke_auth0_role(auth0_client)
        self.approval_status = ApprovalStatusEnum.REVOKED
        self.revocation_reason = reason
        self.updated_at = datetime.now(timezone.utc)
        self.updated_by = updated_by
        self.save(session=session, commit=commit)
        return role_revoked

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
            group_short_name=self.group.short_name,
            approval_status=self.approval_status,
            updated_by=updated_by,
            revocation_reason=self.revocation_reason,
        )



class GroupMembershipHistory(SoftDeleteModel, table=True):
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
    def get_by_user_id_and_group_id(
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

    @classmethod
    def get_by_user_id(cls, user_id: str, session: Session) -> list[Self] | None:
        return session.exec(
            select(GroupMembershipHistory)
            .where(
                GroupMembershipHistory.user_id == user_id,
            )
            .order_by(GroupMembershipHistory.updated_at.desc())
        ).all()


class GroupRoleLink(SoftDeleteModel, table=True):
    group_id: str = Field(primary_key=True, foreign_key="biocommonsgroup.group_id")
    role_id: str = Field(primary_key=True, foreign_key="auth0role.id")


class Auth0Role(SoftDeleteModel, table=True):
    id: str = Field(primary_key=True, unique=True)
    name: str
    description: str = Field(default="")
    platform: Platform | None = Relationship(back_populates="platform_role")
    admin_groups: list["BiocommonsGroup"] = Relationship(
        back_populates="admin_roles", link_model=GroupRoleLink
    )
    admin_platforms: list["Platform"] = Relationship(
        back_populates="admin_roles", link_model=PlatformRoleLink
    )

    @classmethod
    def get_by_id(cls, role_id: str, session: Session) -> Self | None:
        return session.get(Auth0Role, role_id)

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
        session.flush()
        return role

    @classmethod
    def get_or_create_by_name(
        cls, name: str, session: Session, auth0_client: Auth0Client = None
    ) -> Self:
        # Try to get from the DB
        role = cls.get_by_name(name=name, session=session)
        if role is not None:
            return role
        # Try to get from the API and save to the DB
        role_data = auth0_client.get_role_by_name(name=name)
        role = cls(**role_data.model_dump())
        session.add(role)
        session.commit()
        return role

    @classmethod
    def get_by_name(cls, name: str, session: Session) -> Self | None:
        return session.exec(
            select(Auth0Role).where(Auth0Role.name == name)
        ).one_or_none()


class BiocommonsGroup(SoftDeleteModel, table=True):
    # Name of the group / role name in Auth0, e.g. biocommons/group/tsi
    group_id: str = Field(primary_key=True, unique=True)
    # Human-readable name for the group
    name: str = Field(unique=True)
    # Short name / abbreviation for the group
    short_name: str = Field(unique=True)
    # List of roles that are allowed to approve group membership
    admin_roles: list[Auth0Role] = Relationship(
        back_populates="admin_groups", link_model=GroupRoleLink
    )
    members: list[GroupMembership] = Relationship(back_populates="group")
    approval_history: list[GroupMembershipHistory] = Relationship(
        back_populates="group"
    )

    @classmethod
    def get_by_id(cls, group_id: str, session: Session) -> Self | None:
        return session.get(BiocommonsGroup, group_id)

    @classmethod
    def get_by_id_or_404(cls, group_id: str, session: Session) -> Self:
        group = cls.get_by_id(group_id, session)
        if group is None:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found in database")
        return group

    def delete(self, session: Session, commit: bool = False) -> "BiocommonsGroup":
        memberships = list(self.members or [])
        for membership in memberships:
            if not membership.is_deleted:
                membership.delete(session, commit=False)

        super().delete(session, commit=commit)
        return self

    def get_admins(self, auth0_client: Auth0Client) -> set[str]:
        """
        Get all admin emails for this group from the Auth0 API, returning a set of emails.
        """
        admins = set()
        for role in self.admin_roles:
            role_admins = auth0_client.get_all_role_users(role_id=role.id)
            for admin in role_admins:
                email = admin.email
                if email is None:
                    full_admin = auth0_client.get_user(admin.user_id)
                    email = full_admin.email
                if email:
                    admins.add(email)
        return admins

    def user_is_admin(self, user: SessionUser) -> bool:
        user_roles = user.access_token.biocommons_roles
        admin_role_names = [role.name for role in self.admin_roles]
        for role in user_roles:
            if role in admin_role_names:
                return True
        return False

    @classmethod
    def get_all_admin_roles(cls, session: Session) -> list[Auth0Role]:
        return session.exec(
            select(Auth0Role)
            .join(GroupRoleLink, Auth0Role.id == GroupRoleLink.role_id)
            .distinct()
        ).all()

    @classmethod
    def get_for_admin_roles(cls, role_names: list[str], session: Session) -> list[Self]:
        """
        Given a list of role names, return a list of groups
        where the roles grant admin rights.
        """
        return session.exec(
            select(BiocommonsGroup)
            .join(BiocommonsGroup.admin_roles)
            .where(Auth0Role.name.in_(role_names))
        ).all()


class EmailNotification(BaseModel, table=True):
    """
    Stores pending outbound emails for asynchronous processing.
    """
    __tablename__ = "emailnotification"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    to_address: str = Field(index=True)
    subject: str = Field()
    body_html: str = Field(sa_column=Column(Text(), nullable=False))
    status: EmailStatusEnum = Field(
        default=EmailStatusEnum.PENDING,
        sa_type=DbEnum(EmailStatusEnum, name="EmailStatusEnum"),
        nullable=False,
        index=True,
    )
    attempts: int = Field(default=0, nullable=False)
    last_error: str | None = Field(default=None, sa_column=Column(String(1024), nullable=True))
    send_after: AwareDatetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    sent_at: AwareDatetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    created_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_type=DateTime(timezone=True),
    )
    updated_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_type=DateTime(timezone=True),
    )

    def mark_sending(self) -> None:
        self.status = EmailStatusEnum.SENDING
        self.attempts += 1
        self.updated_at = datetime.now(timezone.utc)

    def mark_sent(self) -> None:
        now = datetime.now(timezone.utc)
        self.status = EmailStatusEnum.SENT
        self.sent_at = now
        self.updated_at = now
        self.last_error = None

    def mark_failed(self, error: str, retry_delay_seconds: int | None = None) -> None:
        now = datetime.now(timezone.utc)
        self.status = EmailStatusEnum.FAILED
        self.last_error = error[:1024]
        self.updated_at = now
        if retry_delay_seconds:
            self.send_after = now + timedelta(seconds=retry_delay_seconds)


class EmailChangeOtp(BaseModel, table=True):
    __tablename__ = "email_change_otps"

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_id: str = Field(foreign_key="biocommons_user.id")
    target_email: str
    otp_hash: str
    created_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_type=DateTime(timezone=True),
    )
    expires_at: AwareDatetime = Field(sa_type=DateTime(timezone=True))
    is_active: bool = Field(default=True)
    total_attempts: int = Field(default=0)


# Update all model references
BiocommonsUser.model_rebuild()
Platform.model_rebuild()
PlatformMembership.model_rebuild()
PlatformMembershipHistory.model_rebuild()
GroupMembership.model_rebuild()
GroupMembershipHistory.model_rebuild()
EmailNotification.model_rebuild()
EmailChangeOtp.model_rebuild()
