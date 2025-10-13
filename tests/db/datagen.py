from polyfactory.factories.sqlalchemy_factory import SQLAlchemyFactory
from sqlmodel import Session

from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.types import ApprovalStatusEnum, PlatformEnum
from tests.datagen import random_auth0_id


class BiocommonsUserFactory(SQLAlchemyFactory[BiocommonsUser]):
    __set_relationships__ = False

    @classmethod
    def id(cls) -> str:
        return random_auth0_id()


class Auth0RoleFactory(SQLAlchemyFactory[Auth0Role]):
    __set_relationships__ = False


class BiocommonsGroupFactory(SQLAlchemyFactory[BiocommonsGroup]):
    __set_relationships__ = False


class GroupMembershipFactory(SQLAlchemyFactory[GroupMembership]):
    __set_relationships__ = False


class PlatformMembershipFactory(SQLAlchemyFactory[PlatformMembership]):
    __set_relationships__ = False


class PlatformFactory(SQLAlchemyFactory[Platform]):
    __set_relationships__ = False


def _create_user_with_platform_membership(db_session: Session, platform_id: PlatformEnum,
                                          approval_status=ApprovalStatusEnum.APPROVED,
                                          commit=True, **kwargs):
    user = BiocommonsUserFactory.build(**kwargs)
    membership = PlatformMembershipFactory.create_sync(
        platform_id=platform_id,
        user_id=user.id,
        approval_status=approval_status,
    )
    user.platform_memberships.append(membership)
    db_session.add(user)
    if commit:
        db_session.commit()
    return user


def _users_with_platform_membership(n: int, db_session: Session, platform_id: PlatformEnum,
                                    approval_status=ApprovalStatusEnum.APPROVED, **kwargs):
    users = []
    for i in range(n):
        user = _create_user_with_platform_membership(db_session, platform_id, approval_status, commit=False, **kwargs)
        users.append(user)
    db_session.commit()
    return users


def _create_user_with_group_membership(db_session: Session, group_id: str,
                                       approval_status=ApprovalStatusEnum.APPROVED,
                                       commit=True, **kwargs):
    user = BiocommonsUserFactory.build(**kwargs)
    membership = GroupMembershipFactory.create_sync(
        group_id=group_id,
        user_id=user.id,
        approval_status=approval_status,
    )
    user.group_memberships.append(membership)
    db_session.add(user)
    if commit:
        db_session.commit()
    return user


def _users_with_group_membership(n: int, db_session: Session, group_id: str,
                                  approval_status=ApprovalStatusEnum.APPROVED, **kwargs):
    users = []
    for i in range(n):
        user = _create_user_with_group_membership(db_session, group_id, approval_status, commit=False, **kwargs)
        users.append(user)
    db_session.commit()
    return users
