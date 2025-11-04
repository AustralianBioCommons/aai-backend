import random

import pytest

from db.models import BiocommonsUser
from db.types import ApprovalStatusEnum, GroupEnum, PlatformEnum
from routers.admin import UserQueryParams
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    PlatformFactory,
    _users_with_platform_membership,
)


def test_user_query_no_params():
    """
    Check that UserQueryParams works with no params.

    Also checks that all the required query methods
    exist, since these are checked on init.
    :return:
    """
    query = UserQueryParams()
    assert query.get_query_conditions() == []


def test_user_query_params_missing_method(monkeypatch):
    """
    Test that UserQueryParams raises an error if a query method is missing.
    """
    monkeypatch.delattr(UserQueryParams, "email_verified_query")
    with pytest.raises(NotImplementedError, match="Missing query method for field 'email_verified'"):
        UserQueryParams(email_verified=True)


def test_user_query_multiple_filters(test_client, as_admin_user, test_db_session, persistent_factories):
    """
    Test that multiple conditions can be combined correctly
    """
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    for platform in PlatformEnum:
        PlatformFactory.create_sync(id=platform.value, admin_roles=[admin_role])
    users = BiocommonsUserFactory.create_batch_sync(size=100)
    for user in users:
        random_platform = random.choice(list(PlatformEnum))
        user.add_platform_membership(
            platform=random_platform.value,
            db_session=test_db_session,
            auto_approve=random.choice([True, False])
        )
    test_db_session.flush()
    test_db_session.commit()
    resp = test_client.get("/admin/users?email_verified=true&platform=galaxy&platform_approval_status=approved&page=1&per_page=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    for user_record in data:
        user = test_db_session.get(BiocommonsUser, user_record["id"])
        # Generated to only have one platform membership
        platform = user.platform_memberships[0]
        assert user.email_verified
        assert platform.platform_id == PlatformEnum.GALAXY.value
        assert platform.approval_status == "approved"


# Test combining platform and platform_approval_status filters
def test_get_users_combined_platform_filters(
        test_client,
        as_admin_user,
        test_db_session,
        persistent_factories,
):
    """
    Test that platform and platform_approval_status filters are combined correctly
    to find users with the SAME membership record matching both conditions.
    """
    # Setup admin role for all platforms
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    for platform in PlatformEnum:
        PlatformFactory.create_sync(id=platform.value, admin_roles=[admin_role])

    # Create users with Galaxy + Approved (should match)
    matching_users = _users_with_platform_membership(
        n=5, db_session=test_db_session, platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED
    )

    # Create users with Galaxy + Pending (should NOT match)
    _users_with_platform_membership(
        n=3, db_session=test_db_session, platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.PENDING)

    # Create users with BPA + Approved (should NOT match)
    _users_with_platform_membership(
        n=3, db_session=test_db_session,
        platform_id=PlatformEnum.BPA_DATA_PORTAL,
        approval_status=ApprovalStatusEnum.APPROVED
    )
    # Call endpoint with both filters
    resp = test_client.get(
        f"/admin/users?platform={PlatformEnum.GALAXY.value}&platform_approval_status={ApprovalStatusEnum.APPROVED.value}"
    )
    assert resp.status_code == 200

    data = resp.json()
    assert len(data) == 5, "Expected only users with Galaxy AND Approved"
    # Verify all returned users have Galaxy platform with Approved status
    matching_user_ids = {u.id for u in matching_users}
    returned_ids = {u["id"] for u in data}
    assert returned_ids == matching_user_ids


# Test combining group and group_approval_status filters
def test_get_users_combined_group_filters(
        test_client,
        as_admin_user,
        test_db_session,
        persistent_factories,
):
    """
    Test that group and group_approval_status filters are combined correctly.
    """
    # Setup admin role for all platforms
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    for platform in PlatformEnum:
        PlatformFactory.create_sync(id=platform.value, admin_roles=[admin_role])

    # Create the group
    group = BiocommonsGroupFactory.create_sync(
        group_id=GroupEnum.TSI.value,
        name="Threatened Species Initiative"
    )

    # Create users with TSI + Approved (should match)
    matching_users = _users_with_platform_membership(n=5, db_session=test_db_session, platform_id=PlatformEnum.GALAXY)
    for user in matching_users:
        user.add_group_membership(
            group_id=group.group_id,
            db_session=test_db_session,
            auto_approve=True
        )

    # Create users with TSI + Pending (should NOT match)
    tsi_pending_users = _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=PlatformEnum.GALAXY)
    for user in tsi_pending_users:
        user.add_group_membership(
            group_id=group.group_id,
            db_session=test_db_session,
            auto_approve=False
        )

    test_db_session.commit()

    # Call endpoint with both filters
    resp = test_client.get(
        f"/admin/users?group={GroupEnum.TSI.value}&group_approval_status={ApprovalStatusEnum.APPROVED.value}"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 5, "Expected only users with TSI group AND Approved status"
    matching_user_ids = {u.id for u in matching_users}
    returned_ids = {u["id"] for u in data}
    assert returned_ids == matching_user_ids
