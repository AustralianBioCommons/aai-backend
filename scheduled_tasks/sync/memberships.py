from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from enum import StrEnum

from loguru import logger
from pydantic import BaseModel
from sqlmodel import Session

from auth0.client import Auth0Client, RoleData, RoleUserData
from db.models import (
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.types import ApprovalStatusEnum, PlatformEnum
from scheduled_tasks.sync.summaries import SyncSummary
from schemas.auth0 import get_platform_id_from_role_name


class MembershipSyncResult(StrEnum):
    CREATED = "created"
    RESTORED = "restored"
    STATUS_CHANGED = "status_changed"
    SKIPPED_UNCHANGED = "skipped_unchanged"
    SKIPPED_MISSING_USER = "skipped_missing_user"
    SKIPPED_DELETED_USER = "skipped_deleted_user"
    SKIPPED_MISSING_RESOURCE = "skipped_missing_resource"


class MembershipSyncStatus(BaseModel):
    created: bool = False
    restored: bool = False
    status_changed: bool = False

    def is_changed(self) -> bool:
        return self.created or self.restored or self.status_changed


class MembershipSyncSummary(SyncSummary):
    total: int = 0
    created: int = 0
    restored: int = 0
    status_changed: int = 0
    soft_deleted: int = 0
    skipped_unchanged: int = 0
    skipped_missing_user: int = 0
    skipped_deleted_user: int = 0
    skipped_missing_resource: int = 0

    def add_result(self, result: MembershipSyncResult) -> None:
        self.total += 1
        match result:
            case MembershipSyncResult.CREATED:
                self.created += 1
            case MembershipSyncResult.RESTORED:
                self.restored += 1
            case MembershipSyncResult.STATUS_CHANGED:
                self.status_changed += 1
            case MembershipSyncResult.SKIPPED_UNCHANGED:
                self.skipped_unchanged += 1
            case MembershipSyncResult.SKIPPED_MISSING_USER:
                self.skipped_missing_user += 1
            case MembershipSyncResult.SKIPPED_DELETED_USER:
                self.skipped_deleted_user += 1
            case MembershipSyncResult.SKIPPED_MISSING_RESOURCE:
                self.skipped_missing_resource += 1


def get_active_synced_user(
    session: Session,
    user_id: str,
) -> BiocommonsUser | None:
    user = BiocommonsUser.get_by_id(user_id, session, include_deleted=True)
    if user is None or user.is_deleted:
        return None
    return user


async def sync_platform_memberships_for_role(
    role: RoleData,
    auth0_client: Auth0Client,
    session: Session,
    *,
    batch_size: int = 500,
    commit: bool = True,
) -> MembershipSyncSummary:
    platform_id = _platform_id_from_role(role)
    platform = Platform.get_by_id(platform_id, session)
    if platform is None:
        logger.warning(
            "Platform {} for role {} not found in DB, skipping membership sync",
            platform_id,
            role.name,
        )
        summary = MembershipSyncSummary()
        summary.add_result(MembershipSyncResult.SKIPPED_MISSING_RESOURCE)
        return summary

    summary = MembershipSyncSummary()
    seen_user_ids: set[str] = set()
    pending_role_users: list[RoleUserData] = []

    for role_user_page in auth0_client.get_all_role_users_generator(role_id=role.id):
        for role_user in role_user_page:
            pending_role_users.append(role_user)
            if len(pending_role_users) == batch_size:
                summary.merge(
                    _sync_platform_role_user_batch(
                        session,
                        platform_id,
                        pending_role_users,
                        seen_user_ids,
                    )
                )
                if commit:
                    session.commit()
                pending_role_users = []

    if pending_role_users:
        summary.merge(
            _sync_platform_role_user_batch(
                session,
                platform_id,
                pending_role_users,
                seen_user_ids,
            )
        )
        if commit:
            session.commit()

    summary.soft_deleted += _soft_delete_missing_platform_memberships(
        session,
        platform_id,
        seen_user_ids,
    )
    if commit:
        session.commit()
    return summary


async def sync_group_memberships_for_role(
    role: RoleData,
    auth0_client: Auth0Client,
    session: Session,
    *,
    batch_size: int = 500,
    commit: bool = True,
) -> MembershipSyncSummary:
    group = BiocommonsGroup.get_by_id(role.name, session)
    if group is None:
        logger.warning(
            "Group {} for role {} not found in DB, skipping membership sync",
            role.name,
            role.name,
        )
        summary = MembershipSyncSummary()
        summary.add_result(MembershipSyncResult.SKIPPED_MISSING_RESOURCE)
        return summary

    summary = MembershipSyncSummary()
    seen_user_ids: set[str] = set()
    pending_role_users: list[RoleUserData] = []

    for role_user_page in auth0_client.get_all_role_users_generator(role_id=role.id):
        for role_user in role_user_page:
            pending_role_users.append(role_user)
            if len(pending_role_users) == batch_size:
                summary.merge(
                    _sync_group_role_user_batch(
                        session,
                        group.group_id,
                        pending_role_users,
                        seen_user_ids,
                    )
                )
                if commit:
                    session.commit()
                pending_role_users = []

    if pending_role_users:
        summary.merge(
            _sync_group_role_user_batch(
                session,
                group.group_id,
                pending_role_users,
                seen_user_ids,
            )
        )
        if commit:
            session.commit()

    summary.soft_deleted += _soft_delete_missing_group_memberships(
        session,
        group.group_id,
        seen_user_ids,
    )
    if commit:
        session.commit()
    return summary


def sync_one_platform_membership(
    session: Session,
    *,
    user_id: str,
    platform_id: PlatformEnum,
) -> MembershipSyncResult:
    user = BiocommonsUser.get_by_id(user_id, session, include_deleted=True)
    if user is None:
        logger.warning(
            "Skipping platform membership for {} on {} because user has not been synced",
            user_id,
            platform_id,
        )
        return MembershipSyncResult.SKIPPED_MISSING_USER
    if user.is_deleted:
        logger.info(
            "Skipping platform membership for {} on {} because user is deleted",
            user_id,
            platform_id,
        )
        return MembershipSyncResult.SKIPPED_DELETED_USER

    status = MembershipSyncStatus()
    membership = PlatformMembership.get_by_user_id_and_platform_id(
        user.id,
        platform_id,
        session,
        include_deleted=True,
    )
    if membership is None:
        status.created = True
        membership = PlatformMembership(
            platform_id=platform_id,
            user_id=user.id,
            approval_status=ApprovalStatusEnum.APPROVED,
            updated_by_id=None,
        )
        session.add(membership)
        session.flush()
    elif membership.is_deleted:
        status.restored = True
        membership.restore(session, commit=False)

    if membership.approval_status != ApprovalStatusEnum.APPROVED:
        status.status_changed = True
        membership.approval_status = ApprovalStatusEnum.APPROVED
        membership.updated_at = datetime.now(timezone.utc)

    session.add(membership)
    if status.is_changed():
        membership.save_history(session, commit=False)
        return _membership_action(status)
    return MembershipSyncResult.SKIPPED_UNCHANGED


def sync_one_group_membership(
    session: Session,
    *,
    user_id: str,
    group_id: str,
) -> MembershipSyncResult:
    user = BiocommonsUser.get_by_id(user_id, session, include_deleted=True)
    if user is None:
        logger.warning(
            "Skipping group membership for {} on {} because user has not been synced",
            user_id,
            group_id,
        )
        return MembershipSyncResult.SKIPPED_MISSING_USER
    if user.is_deleted:
        logger.info(
            "Skipping group membership for {} on {} because user is deleted",
            user_id,
            group_id,
        )
        return MembershipSyncResult.SKIPPED_DELETED_USER

    status = MembershipSyncStatus()
    membership = GroupMembership.get_by_user_id_and_group_id(
        user.id,
        group_id,
        session,
        include_deleted=True,
    )
    if membership is None:
        status.created = True
        membership = GroupMembership(
            group_id=group_id,
            user_id=user.id,
            approval_status=ApprovalStatusEnum.APPROVED,
            updated_by_id=None,
        )
        session.add(membership)
        session.flush()
    elif membership.is_deleted:
        status.restored = True
        membership.restore(session, commit=False)

    if membership.approval_status != ApprovalStatusEnum.APPROVED:
        status.status_changed = True
        membership.approval_status = ApprovalStatusEnum.APPROVED
        membership.updated_at = datetime.now(timezone.utc)

    session.add(membership)
    if status.is_changed():
        membership.save_history(session, commit=False)
        return _membership_action(status)
    return MembershipSyncResult.SKIPPED_UNCHANGED


def _sync_platform_role_user_batch(
    session: Session,
    platform_id: PlatformEnum,
    role_users: Iterable[RoleUserData],
    seen_user_ids: set[str],
) -> MembershipSyncSummary:
    summary = MembershipSyncSummary()
    for role_user in role_users:
        seen_user_ids.add(role_user.user_id)
        with session.begin_nested():
            summary.add_result(
                sync_one_platform_membership(
                    session,
                    user_id=role_user.user_id,
                    platform_id=platform_id,
                )
            )
    return summary


def _sync_group_role_user_batch(
    session: Session,
    group_id: str,
    role_users: Iterable[RoleUserData],
    seen_user_ids: set[str],
) -> MembershipSyncSummary:
    summary = MembershipSyncSummary()
    for role_user in role_users:
        seen_user_ids.add(role_user.user_id)
        with session.begin_nested():
            summary.add_result(
                sync_one_group_membership(
                    session,
                    user_id=role_user.user_id,
                    group_id=group_id,
                )
            )
    return summary


def _soft_delete_missing_platform_memberships(
    session: Session,
    platform_id: PlatformEnum,
    seen_user_ids: set[str],
) -> int:
    deleted = 0
    memberships = PlatformMembership.list_by_platform_id(
        platform_id,
        session,
        include_deleted=True,
    )
    for membership in memberships:
        if _should_soft_delete_membership(membership, seen_user_ids):
            logger.info(
                "Soft deleting platform membership {} -> {} absent from Auth0",
                membership.user_id,
                membership.platform_id,
            )
            membership.delete(session, commit=False)
            deleted += 1
    return deleted


def _soft_delete_missing_group_memberships(
    session: Session,
    group_id: str,
    seen_user_ids: set[str],
) -> int:
    deleted = 0
    memberships = GroupMembership.list_by_group_id(
        group_id,
        session,
        include_deleted=True,
    )
    for membership in memberships:
        if _should_soft_delete_membership(membership, seen_user_ids):
            logger.info(
                "Soft deleting group membership {} -> {} absent from Auth0",
                membership.user_id,
                membership.group_id,
            )
            membership.delete(session, commit=False)
            deleted += 1
    return deleted


def _should_soft_delete_membership(
    membership: PlatformMembership | GroupMembership,
    seen_user_ids: set[str],
) -> bool:
    return (
        not membership.is_deleted
        and membership.approval_status == ApprovalStatusEnum.APPROVED
        and membership.user_id not in seen_user_ids
    )


def _membership_action(status: MembershipSyncStatus) -> MembershipSyncResult:
    if status.created:
        return MembershipSyncResult.CREATED
    if status.restored:
        return MembershipSyncResult.RESTORED
    if status.status_changed:
        return MembershipSyncResult.STATUS_CHANGED
    return MembershipSyncResult.SKIPPED_UNCHANGED


def _platform_id_from_role(role: RoleData) -> PlatformEnum:
    platform_id = get_platform_id_from_role_name(role.name)
    if platform_id is None:
        raise ValueError(f"Role {role.name} is not a platform role")
    return PlatformEnum(platform_id)
