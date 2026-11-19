import random
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import sqlite

from db.models import BiocommonsUser
from db.types import ApprovalStatusEnum, GroupEnum, PlatformEnum
from db.utils import refresh_unverified_users_task
from routers.admin import UserQueryParams
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    PlatformFactory,
    PlatformMembershipFactory,
    _create_user_with_platform_membership,
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


@pytest.mark.parametrize("sort_order", ["asc", "desc", pytest.param(None, id="default")])
@pytest.mark.parametrize(
    ("tab_params", "ascending", "descending"),
    [
        ({}, [1, 2, 3, 0, 4], [4, 0, 3, 1, 2]),
        ({"approval_status": "pending"}, [1, 2, 0], [0, 1, 2]),
        ({"approval_status": "revoked"}, [3], [3]),
        ({"email_verified": "false"}, [1, 2, 0], [0, 1, 2]),
    ],
    ids=["all", "pending", "revoked", "unverified"],
)
def test_signup_sorting_across_filtered_pages(
    test_client, as_admin_user, test_db_session, persistent_factories,
    mock_auth0_client, mock_background_tasks, sort_order, tab_params,
    ascending, descending,
):
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    platform = PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY, admin_roles=[admin_role]
    )
    users = [
        _create_user_with_platform_membership(
            db_session=test_db_session,
            platform_id=platform.id,
            id=f"auth0|signup{index}",
            username=f"signup-user-{index}",
            created_at=datetime(2024, 1, day, tzinfo=timezone.utc),
            approval_status=approval_status,
            email_verified=verified,
        )
        for index, (day, approval_status, verified) in enumerate([
            (3, ApprovalStatusEnum.PENDING, False),
            (1, ApprovalStatusEnum.PENDING, False),
            (1, ApprovalStatusEnum.PENDING, False),
            (2, ApprovalStatusEnum.REVOKED, True),
            (4, ApprovalStatusEnum.APPROVED, True),
        ])
    ]
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=platform.id,
        username="excluded-by-search", email="excluded@example.com",
    )
    BiocommonsUserFactory.create_sync(username="signup-without-admin-access")
    test_db_session.commit()
    params = {
        **tab_params, "per_page": 2,
        "search": "signup", "filter_by": "galaxy",
    }
    if sort_order is not None:
        params["sort_order"] = sort_order
    expected = ascending if sort_order == "asc" else descending
    page_info = test_client.get("/admin/users/pages", params=params)
    assert page_info.status_code == 200
    assert page_info.json()["total"] == len(expected)

    results = []
    for page in range(1, page_info.json()["pages"] + 1):
        response = test_client.get("/admin/users", params={**params, "page": page})
        assert response.status_code == 200
        results.extend(response.json())

    assert [user["id"] for user in results] == [users[index].id for index in expected]
    assert all(user["created_at"] for user in results)


def test_signup_sort_rejects_invalid_order(test_client, as_admin_user, mock_auth0_client):
    response = test_client.get("/admin/users", params={"sort_order": "invalid"})
    assert response.status_code == 422
    assert any(error["loc"] == ["query", "sort_order"] for error in response.json()["detail"])


def test_platform_filter_scopes_admin_permissions_to_platforms_only():
    query = UserQueryParams(filter_by="bpa_data_portal", email_verified=False)
    sql = str(
        query.get_complete_query(
            admin_roles=["biocommons/role/bpa_data_portal/admin"],
            pagination=SimpleNamespace(start_index=0, per_page=50),
        ).compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": False})
    )

    assert "platformrolelink" in sql
    assert "grouprolelink" not in sql
    assert sql.count("FROM platformmembership") == 1


def test_user_query_params_missing_method(monkeypatch):
    """
    Test that UserQueryParams raises an error if a query method is missing.
    """
    monkeypatch.delattr(UserQueryParams, "email_verified_query")
    with pytest.raises(NotImplementedError, match="Missing query method for field 'email_verified'"):
        UserQueryParams(email_verified=True)


def test_user_query_multiple_filters(test_client, mock_auth0_client, as_admin_user, test_db_session, mock_background_tasks, persistent_factories):
    """
    Test that multiple conditions can be combined correctly
    """
    admin_role = Auth0RoleFactory.create_sync(name="Admin")
    for platform in PlatformEnum:
        PlatformFactory.create_sync(id=platform.value, admin_roles=[admin_role])
    users = BiocommonsUserFactory.create_batch_sync(size=100)
    for user in users:
        random_platform = random.choice(list(PlatformEnum))
        PlatformMembershipFactory.create_sync(
            platform_id=random_platform.value,
            user=user,
            approval_status=random.choice([ApprovalStatusEnum.APPROVED, ApprovalStatusEnum.PENDING])
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


def test_get_users_email_verified_refreshes_status(test_client, as_admin_user, test_db_session, persistent_factories, mock_background_tasks):
    """
    Check that explicitly searching based on email_verified status triggers a refresh of unverified users.
    """
    resp = test_client.get(
        "/admin/users?email_verified=true"
    )
    assert resp.status_code == 200
    assert mock_background_tasks.called
    assert mock_background_tasks.call_args[0][0] == refresh_unverified_users_task
