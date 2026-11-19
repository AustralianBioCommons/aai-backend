from unittest.mock import MagicMock

import pytest

from auth0.client import RoleData, RoleUserData
from db.models import BiocommonsGroup, BiocommonsUser, Platform, PlatformMembership
from db.types import ApprovalStatusEnum, PlatformEnum
from scheduled_tasks.sync.memberships import (
    MembershipSyncResult,
    get_active_synced_user,
    sync_group_memberships_for_role,
    sync_one_platform_membership,
    sync_platform_memberships_for_role,
)
from schemas.biocommons import BiocommonsUserAccountType


def test_get_active_synced_user_returns_only_active_users(test_db_session):
    active = _db_user(test_db_session, user_id="auth0|active")
    deleted = _db_user(test_db_session, user_id="auth0|deleted")
    deleted.delete(test_db_session, commit=False)
    test_db_session.flush()

    assert get_active_synced_user(test_db_session, active.id) == active
    assert get_active_synced_user(test_db_session, deleted.id) is None
    assert get_active_synced_user(test_db_session, "auth0|missing") is None


def test_sync_one_platform_membership_skips_missing_user(test_db_session):
    _platform(test_db_session, PlatformEnum.GALAXY)

    result = sync_one_platform_membership(
        test_db_session,
        user_id="auth0|missing",
        platform_id=PlatformEnum.GALAXY,
    )

    assert result == MembershipSyncResult.SKIPPED_MISSING_USER
    assert test_db_session.get(BiocommonsUser, "auth0|missing") is None


@pytest.mark.asyncio
async def test_sync_platform_memberships_for_role_creates_membership_for_existing_user(test_db_session):
    _platform(test_db_session, PlatformEnum.GALAXY)
    user = _db_user(test_db_session, user_id="auth0|member")
    role = RoleData(
        id="role-platform",
        name="biocommons/platform/galaxy",
        description="Galaxy",
    )
    auth0_client = _auth0_client_with_role_users([[user.id]])

    summary = await sync_platform_memberships_for_role(
        role,
        auth0_client,
        test_db_session,
        batch_size=1,
        commit=False,
    )

    membership = PlatformMembership.get_by_user_id_and_platform_id(
        user.id,
        PlatformEnum.GALAXY,
        test_db_session,
    )
    assert summary.created == 1
    assert membership is not None
    assert membership.approval_status == ApprovalStatusEnum.APPROVED


@pytest.mark.asyncio
async def test_sync_group_memberships_for_role_skips_missing_user(test_db_session):
    group = _group(test_db_session, "biocommons/group/tsi")
    role = RoleData(
        id="role-group",
        name=group.group_id,
        description="TSI",
    )
    auth0_client = _auth0_client_with_role_users([["auth0|missing"]])

    summary = await sync_group_memberships_for_role(
        role,
        auth0_client,
        test_db_session,
        batch_size=1,
        commit=False,
    )

    assert summary.skipped_missing_user == 1
    assert test_db_session.get(BiocommonsUser, "auth0|missing") is None


@pytest.mark.asyncio
async def test_sync_platform_memberships_for_role_soft_deletes_absent_approved_membership(test_db_session):
    _platform(test_db_session, PlatformEnum.GALAXY)
    present_user = _db_user(test_db_session, user_id="auth0|present")
    absent_user = _db_user(test_db_session, user_id="auth0|absent")
    absent_membership = PlatformMembership(
        platform_id=PlatformEnum.GALAXY,
        user_id=absent_user.id,
        approval_status=ApprovalStatusEnum.APPROVED,
        updated_by_id=None,
    )
    test_db_session.add(absent_membership)
    test_db_session.flush()

    role = RoleData(
        id="role-platform",
        name="biocommons/platform/galaxy",
        description="Galaxy",
    )
    auth0_client = _auth0_client_with_role_users([[present_user.id]])

    summary = await sync_platform_memberships_for_role(
        role,
        auth0_client,
        test_db_session,
        batch_size=1,
        commit=False,
    )

    assert summary.created == 1
    assert summary.soft_deleted == 1
    assert absent_membership.is_deleted is True


def _auth0_client_with_role_users(user_id_pages: list[list[str]]) -> MagicMock:
    auth0_client = MagicMock()
    auth0_client.get_all_role_users_generator.return_value = [
        [RoleUserData(user_id=user_id) for user_id in page]
        for page in user_id_pages
    ]
    return auth0_client


def _db_user(test_db_session, *, user_id: str) -> BiocommonsUser:
    user = BiocommonsUser(
        id=user_id,
        email=f"{user_id.replace('|', '-')}@example.com",
        username=user_id.replace("|", "_"),
        email_verified=True,
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    test_db_session.add(user)
    test_db_session.flush()
    return user


def _platform(test_db_session, platform_id: PlatformEnum) -> Platform:
    platform = Platform(
        id=platform_id,
        name=f"{platform_id.value} platform",
    )
    test_db_session.add(platform)
    test_db_session.flush()
    return platform


def _group(test_db_session, group_id: str) -> BiocommonsGroup:
    group = BiocommonsGroup(
        group_id=group_id,
        name="Test Group",
        short_name="TEST",
    )
    test_db_session.add(group)
    test_db_session.flush()
    return group
