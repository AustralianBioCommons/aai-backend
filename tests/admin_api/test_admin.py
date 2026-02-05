import asyncio
from urllib.parse import quote

import pytest
import respx
from fastapi import HTTPException
from freezegun import freeze_time
from sqlalchemy import func
from sqlmodel import select

from auth.management import get_management_token
from auth.user_permissions import get_session_user, user_is_general_admin
from auth0.client import Auth0Client, UpdateUserData
from db.models import (
    BiocommonsGroup,
    BiocommonsUser,
    EmailNotification,
    GroupMembershipHistory,
    PlatformMembershipHistory,
)
from db.types import ApprovalStatusEnum, EmailStatusEnum, GroupEnum, PlatformEnum
from main import app
from routers.admin import PaginationParams, UserQueryParams
from tests.biocommons.datagen import RoleDataFactory
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    EmailVerificationResponseFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    Auth0RoleFactory,
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformFactory,
    PlatformMembershipFactory,
    _create_user_with_platform_membership,
    _users_with_group_membership,
    _users_with_platform_membership,
)


@pytest.fixture
def frozen_time():
    """
    Freeze time so datetime.now() returns FROZEN_TIME.
    """
    with freeze_time("2025-01-01 12:00:00", tz_offset=0) as time:
        yield time()


@pytest.fixture
def mock_group_enum(mocker):
    class GroupEnum:
        TSI = "biocommons/group/tsi"
        OTHER = "biocommons/group/other"
    mocker.patch("routers.admin.GroupEnum", GroupEnum)


@pytest.fixture
def galaxy_platform(persistent_factories):
    """
    Set up a Galaxy platform with the admin role set to the Galaxy admin scope.
    """
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/galaxy/admin")
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/galaxy")
    return PlatformFactory.create_sync(
        id=PlatformEnum.GALAXY,
        name="Galaxy Australia",
        admin_roles=[admin_role],
        role_id=platform_role.id,
        platform_role=platform_role,
    )


@pytest.fixture
def tsi_group(persistent_factories):
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    return BiocommonsGroupFactory.create_sync(
        group_id=GroupEnum.TSI.value,
        name="Threatened Species Initiative",
        admin_roles=[admin_role],
    )


@pytest.fixture
def bpa_platform(persistent_factories):
    """
    Set up a BPA platform in the DB (no admin roles configured)
    """
    platform_role = Auth0RoleFactory.create_sync(name="biocommons/platform/bpa_data_portal")
    return PlatformFactory.create_sync(
        id=PlatformEnum.BPA_DATA_PORTAL,
        name="BPA Data Portal",
        admin_roles=[],
        role_id=platform_role.id,
        platform_role=platform_role,
    )


def test_pagination_params_start_index():
    """
    Test we can get the current start index given the page number and per_page.
    """
    params = PaginationParams(page=2, per_page=10)
    # start index for page 1 is 0, for page 2 is 0 + per_page = 10
    assert params.start_index == 10


def test_get_users_requires_admin_unauthorized(test_client, test_db_session):
    def get_nonadmin_user():
        payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
        return SessionUserFactory.build(access_token=payload)

    app.dependency_overrides[get_session_user] = get_nonadmin_user
    app.dependency_overrides[get_management_token] = lambda: "mock_token"
    resp = test_client.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json() == {"detail": "You must be an admin to access this endpoint."}
    app.dependency_overrides.clear()


def test_user_is_admin(mock_settings, test_db_session, persistent_factories):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    admin_user = SessionUserFactory.build(access_token=payload)
    db_user = BiocommonsUserFactory.create_sync(id=admin_user.access_token.sub)
    assert user_is_general_admin(current_user=admin_user, settings=mock_settings, db_session=test_db_session,
                                 db_user=db_user)


def test_user_is_admin_nonadmin_user(mock_settings, test_db_session, persistent_factories):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
    user = SessionUserFactory.build(access_token=payload)
    db_user = BiocommonsUserFactory.create_sync(id=user.access_token.sub)
    with pytest.raises(HTTPException, match="You must be an admin to access this endpoint."):
        user_is_general_admin(current_user=user, settings=mock_settings,
                              db_session=test_db_session, db_user=db_user)


def test_get_users(test_client, as_admin_user, galaxy_platform,
                   mock_auth0_client, test_db_session, persistent_factories):
    """
    Test getting a list of users. The list should only contain users with platform memberships
    that the admin user has access to.
    """
    valid_users = _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=galaxy_platform.id)
    other_platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL)
    invalid_users = _users_with_platform_membership(n=2, db_session=test_db_session, platform_id=other_platform.id)

    resp = test_client.get("/admin/users")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    user_ids = [u["id"] for u in data]
    assert all(u.id in user_ids for u in valid_users)
    assert all(u.id not in user_ids for u in invalid_users)


def test_get_users_platform_or_group_access(
    test_client,
    as_admin_user,
    mock_group_enum,
    galaxy_platform,
    tsi_group,
    test_db_session,
    persistent_factories
):
    """
    Test that admins can get users with platform *or* group memberships
    they have access to.
    """
    other_platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL)
    other_group = BiocommonsGroupFactory.create_sync(group_id="other")
    test_db_session.commit()
    galaxy_users = _users_with_platform_membership(n=5, db_session=test_db_session, platform_id=galaxy_platform.id)
    other_platform_users = _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=other_platform.id)
    tsi_users = _users_with_group_membership(n=5, db_session=test_db_session, group_id=tsi_group.group_id)
    other_group_users = _users_with_group_membership(n=3, db_session=test_db_session, group_id=other_group.group_id)

    resp = test_client.get("/admin/users")
    data = resp.json()
    assert len(data) == 10
    user_ids = [u["id"] for u in data]
    assert all(u.id in user_ids for u in galaxy_users)
    assert all(u.id in user_ids for u in tsi_users)
    assert all(u.id not in user_ids for u in other_platform_users)
    assert all(u.id not in user_ids for u in other_group_users)


def test_get_users_pagination_params(test_client, as_admin_user, galaxy_platform, mock_auth0_client, test_db_session):
    _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=galaxy_platform.id)

    resp = test_client.get("/admin/users?page=2&per_page=10")
    assert resp.status_code == 200
    # Page 2 with per_page=10 should be empty since we only have 3 users
    assert len(resp.json()) == 0


def test_get_users_invalid_params(test_client, as_admin_user, galaxy_platform, test_db_session, mock_auth0_client):
    _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=galaxy_platform.id)
    resp = test_client.get("/admin/users?page=0&per_page=500")
    assert resp.status_code == 422
    error_msg = resp.json()["detail"]
    assert "Invalid page params" in error_msg


def test_get_users_filter_by_platform(test_client, as_admin_user,
                                      galaxy_platform, bpa_platform, test_db_session,
                                      persistent_factories):
    galaxy_users = _users_with_platform_membership(n=2, db_session=test_db_session, platform_id=galaxy_platform.id)
    other_users = BiocommonsUserFactory.batch(2)
    for user in other_users:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?filter_by=galaxy")
    assert resp.status_code == 200
    galaxy_data = resp.json()
    assert len(galaxy_data) == 2
    galaxy_ids = [u["id"] for u in galaxy_data]
    assert all(u.id in galaxy_ids for u in galaxy_users)

    resp = test_client.get("/admin/users?filter_by=bpa_data_portal")
    assert resp.status_code == 200
    assert len(resp.json()) == 0



def test_get_users_filter_by_group(test_client, as_admin_user, galaxy_platform, test_db_session):
    tsi_group = BiocommonsGroup(
        group_id=GroupEnum.TSI,
        name="Threatened Species Initiative",
        short_name="TSI"
    )
    test_db_session.add(tsi_group)
    test_db_session.commit()
    # Create users who can be managed by the admin user
    tsi_users = _users_with_platform_membership(n=3, db_session=test_db_session, platform_id=galaxy_platform.id)
    other_users = _users_with_platform_membership(n=2, db_session=test_db_session, platform_id=galaxy_platform.id)

    for user in tsi_users:
        membership = GroupMembershipFactory.create_sync(
            user_id=user.id,
            group_id=GroupEnum.TSI,
            approval_status=ApprovalStatusEnum.APPROVED
        )
        user.group_memberships.append(membership)
        test_db_session.add(membership)
    test_db_session.commit()

    resp = test_client.get("/admin/users?filter_by=tsi")
    assert resp.status_code == 200
    tsi_data = resp.json()
    assert len(tsi_data) == 3
    tsi_ids = [u["id"] for u in tsi_data]
    assert all(u.id in tsi_ids for u in tsi_users)
    assert all(u.id not in tsi_ids for u in other_users)


def test_get_users_invalid_filter(test_client, as_admin_user, test_db_session):
    resp = test_client.get("/admin/users?filter_by=invalid_filter")
    assert resp.status_code == 400
    assert "Invalid filter_by value 'invalid_filter'" in resp.json()["detail"]


def test_get_users_search_by_email_exact(test_client, as_admin_user, galaxy_platform, test_db_session):
    user1 = _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="john.doe@example.com", username="johndoe"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="jane.smith@example.com", username="janesmith"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="bob.wilson@example.com", username="bobwilson"
    )

    resp = test_client.get("/admin/users?search=john.doe@example.com")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["email"] == "john.doe@example.com"
    assert results[0]["id"] == user1.id


def test_get_users_search_by_email_partial(test_client, as_admin_user, galaxy_platform, test_db_session):
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="john.doe@example.com", username="johndoe"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="jane.smith@example.com", username="janesmith"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="bob.wilson@different.com", username="bobwilson"
    )

    resp = test_client.get("/admin/users?search=example.com")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    emails = [user["email"] for user in results]
    assert "john.doe@example.com" in emails
    assert "jane.smith@example.com" in emails
    assert "bob.wilson@different.com" not in emails


def test_get_users_search_by_username(test_client, as_admin_user, galaxy_platform, test_db_session):
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="john.doe@example.com", username="johndoe"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="jane.smith@example.com", username="janesmith"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="bob.wilson@different.com", username="bobwilson"
    )

    resp = test_client.get("/admin/users?search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["username"] == "johndoe"


def test_get_users_search_by_username_partial(test_client, as_admin_user, galaxy_platform, test_db_session):
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="john.doe@example.com", username="johndoe"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="smith@example.com", username="johnsmith"
    )
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="bob.wilson@example.com", username="bobwilson"
    )

    resp = test_client.get("/admin/users?search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    usernames = [user["username"] for user in results]
    assert "johnsmith" in usernames
    assert "johndoe" in usernames
    assert "bobwilson" not in usernames


def test_get_users_search_case_insensitive(test_client, as_admin_user, galaxy_platform, test_db_session):
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="John.Doe@Example.Com", username="JohnDoe"
    )

    resp = test_client.get("/admin/users?search=JOHN")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["username"] == "JohnDoe"

    resp = test_client.get("/admin/users?search=john.doe@example.com")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["email"] == "John.Doe@Example.Com"


def test_get_users_search_empty_string(test_client, as_admin_user, galaxy_platform, test_db_session):
    users = BiocommonsUserFactory.batch(3)
    for user in users:
        membership = PlatformMembershipFactory.create_sync(user_id=user.id, platform_id=galaxy_platform.id)
        user.platform_memberships.append(membership)
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?search=")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 3

    resp = test_client.get("/admin/users?search=   ")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 3


def test_get_users_search_with_filter(test_client, as_admin_user, galaxy_platform, test_db_session):
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=galaxy_platform.id,
        email="john.doe@example.com", username="johndoe"
    )
    other_platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL)
    _create_user_with_platform_membership(
        db_session=test_db_session, platform_id=other_platform.id,
        email="jane@example.com", username="janesmith"
    )

    resp = test_client.get("/admin/users?filter_by=galaxy&search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["username"] == "johndoe"

    resp = test_client.get("/admin/users?filter_by=galaxy&search=jane")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 0


def test_get_filter_options(test_client, as_admin_user, test_db_session, persistent_factories):
    resp = test_client.get("/admin/filters")
    assert resp.status_code == 200

    options = resp.json()
    assert isinstance(options, list)
    assert len(options) == 4

    for option in options:
        assert "id" in option
        assert "name" in option
        assert isinstance(option["id"], str)
        assert isinstance(option["name"], str)

    option_ids = {opt["id"] for opt in options}
    expected_ids = {"galaxy", "bpa_data_portal", "sbp", "tsi"}
    assert option_ids == expected_ids

    option_dict = {opt["id"]: opt["name"] for opt in options}
    assert option_dict["galaxy"] == "Galaxy Australia"
    assert option_dict["bpa_data_portal"] == "Bioplatforms Australia Data Portal"
    assert option_dict["sbp"] == "Structural Biology Platform"
    assert option_dict["tsi"] == "Threatened Species Initiative"


def test_get_user(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    """
    Test getting a user by ID. The admin must have access to the user
    via group/platform membership.
    """
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    resp = test_client.get(f"/admin/users/{user.id}")
    assert resp.status_code == 200
    response_data = resp.json()

    assert response_data["id"] == user.id
    assert response_data["email"] == user.email
    assert response_data["username"] == user.username
    assert response_data["email_verified"] == user.email_verified

    assert "platform_memberships" in response_data
    assert "group_memberships" in response_data
    assert isinstance(response_data["platform_memberships"], list)
    assert isinstance(response_data["group_memberships"], list)


def test_get_user_forbidden_without_admin_role(test_client, test_db_session, as_admin_user, persistent_factories):
    # Create user with platform membership that admin can't access
    platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL)
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=platform.id)
    resp = test_client.get(f"/admin/users/{user.id}")
    assert resp.status_code == 403


def test_delete_user(test_client, test_db_session, as_admin_user, mock_auth0_client, galaxy_platform, persistent_factories, frozen_time):
    """
    Test deleting a user marks them as deleted (without actually deleting them from the database), and records
    deletion info
    """
    mock_auth0_client.update_user.return_value = True
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    user_id = user.id
    admin_user = as_admin_user
    resp = test_client.post(f"/admin/users/{user.id}/delete", json={"reason": "Testing user deletion"})
    assert resp.status_code == 200
    user_query = select(func.count()).select_from(BiocommonsUser).where(BiocommonsUser.id == user_id)
    # Should be hidden from normal queries
    assert test_db_session.exec(user_query).one() == 0
    # Should still be found when include_deleted=True is passed
    assert test_db_session.exec(user_query.execution_options(include_deleted=True)).one() == 1
    # Check user is updated with deletion info
    refreshed_user = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert refreshed_user.is_deleted
    assert refreshed_user.deleted_at == frozen_time
    assert refreshed_user.deleted_by == admin_user
    assert refreshed_user.deletion_reason == "Testing user deletion"


def test_delete_user_empty_reason(test_client, test_db_session, as_admin_user, mock_auth0_client, galaxy_platform, persistent_factories, frozen_time):
    mock_auth0_client.update_user.return_value = True
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    user_id = user.id
    admin_user = as_admin_user
    resp = test_client.post(f"/admin/users/{user.id}/delete", json={"reason": None})
    assert resp.status_code == 200
    # Check user is updated with deletion info
    refreshed_user = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert refreshed_user.deleted_at == frozen_time
    assert refreshed_user.deleted_by == admin_user
    assert refreshed_user.deletion_reason is None


def test_delete_user_calls_auth0_api(test_client, test_db_session, as_admin_user, mock_auth0_client, galaxy_platform, persistent_factories):
    """
    Test that deleting a user calls the Auth0 API to block the user and delete refresh tokens.
    """
    mock_auth0_client.update_user.return_value = True
    mock_auth0_client.delete_user_refresh_tokens.return_value = True
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    user_id = user.id
    resp = test_client.post(f"/admin/users/{user.id}/delete", json={"reason": "Testing user deletion"})
    assert resp.status_code == 200
    mock_auth0_client.update_user.assert_called_once()
    mock_auth0_client.update_user.assert_called_with(
        user_id=user_id,
        update_data=UpdateUserData(blocked=True)
    )
    mock_auth0_client.delete_user_refresh_tokens.assert_called_once_with(user_id=user_id)


@respx.mock
def test_delete_user_continue_when_refresh_token_delete_fails(test_client, test_db_session, as_admin_user, test_auth0_client, galaxy_platform, persistent_factories):
    """
    Test that deleting a user continues even if refresh token deletion fails.
    """
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    user_id = user.id
    user_data =  Auth0UserDataFactory.build(user_id=user_id, blocked=True)
    update_user_route = respx.patch(f"https://auth0.example.com/api/v2/users/{user_id}").respond(200, json=user_data.model_dump(mode="json"))
    delete_token_route = respx.delete(f"https://auth0.example.com/api/v2/users/{user_id}/refresh-tokens").respond(400)
    resp = test_client.post(f"/admin/users/{user.id}/delete", json={"reason": "Testing user deletion"})
    assert resp.status_code == 200
    assert update_user_route.called
    assert delete_token_route.called
    # Check user is still deleted from DB
    refreshed_user = BiocommonsUser.get_deleted_by_id(test_db_session, user_id)
    assert refreshed_user.is_deleted


def test_delete_user_forbidden_without_admin_role(test_client, test_db_session, as_admin_user, bpa_platform, mock_auth0_client, persistent_factories):
    mock_auth0_client.update_user.return_value = True
    # Create user with platform membership that admin can't access
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=bpa_platform.id)
    user_id = user.id
    resp = test_client.post(f"/admin/users/{user.id}/delete", json={"reason": "Testing user deletion"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "You do not have permission to manage this user."
    # Auth0 API should not have been called
    assert mock_auth0_client.update_user.call_count == 0
    # User should not have been deleted
    refreshed_user = BiocommonsUser.get_by_id(user_id, test_db_session)
    assert refreshed_user is not None
    assert refreshed_user.is_deleted is False


def test_get_user_counts(
    test_client,
    as_admin_user,
    galaxy_platform,
    bpa_platform,
    test_db_session,
    persistent_factories,
):
    approved_users = _users_with_platform_membership(
        2,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
    )
    pending_users = _users_with_platform_membership(
        3,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    revoked_users = _users_with_platform_membership(
        1,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.REVOKED,
    )
    _create_user_with_platform_membership(
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        email_verified=False,
    )
    # Users on a platform without admin access should not be counted
    _users_with_platform_membership(
        2, db_session=test_db_session, platform_id=bpa_platform.id
    )

    resp = test_client.get("/admin/users/counts")
    assert resp.status_code == 200
    assert resp.json() == {
        "all": len(approved_users) + len(pending_users) + len(revoked_users) + 1,
        "pending": len(pending_users),
        "revoked": len(revoked_users),
        "unverified": 1,
    }


def test_get_user_page_info(
    test_client,
    as_admin_user,
    galaxy_platform,
    bpa_platform,
    test_db_session,
    persistent_factories,
):
    # Create users on a platform the admin has access to (Galaxy)
    _users_with_platform_membership(
        2,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
    )
    _users_with_platform_membership(
        3,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.PENDING,
    )

    # Create users on a platform the admin does NOT have access to (BPA)
    _users_with_platform_membership(
        2, db_session=test_db_session, platform_id=bpa_platform.id
    )

    # Case 1: Total count (default pagination)
    # Should only count Galaxy users
    resp = test_client.get("/admin/users/pages")
    assert resp.status_code == 200
    assert resp.json() == {
        "total": 5,
        "pages": 1,
        "per_page": 100
    }

    # Case 2: Pagination (per_page=2)
    # 5 items / 2 per page = 3 pages
    resp = test_client.get("/admin/users/pages?per_page=2")
    assert resp.status_code == 200
    assert resp.json() == {
        "total": 5,
        "pages": 3,
        "per_page": 2
    }

    # Case 3: Filter by status
    # Should only count pending Galaxy users (3)
    resp = test_client.get(f"/admin/users/pages?approval_status={ApprovalStatusEnum.PENDING.value}")
    assert resp.status_code == 200
    assert resp.json() == {
        "total": 3,
        "pages": 1,
        "per_page": 100
    }


def test_user_query_params_get_count(
    test_db_session,
    admin_user,
    galaxy_platform,
    persistent_factories,
):
    """
    Ensure UserQueryParams.get_count respects approval_status across accessible platforms/groups.
    """
    _users_with_platform_membership(
        2,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.PENDING,
    )
    _users_with_platform_membership(
        1,
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
        approval_status=ApprovalStatusEnum.APPROVED,
    )

    query_params = UserQueryParams(
        approval_status=ApprovalStatusEnum.PENDING,
        platform_approval_status=None,
        group_approval_status=None,
    )
    count = query_params.get_count(
        db_session=test_db_session,
        admin_roles=admin_user.access_token.biocommons_roles,
    )
    assert count == 2


def test_get_approved_users(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    approved_users = _users_with_platform_membership(
        3,
        db_session=test_db_session,
        platform_id=PlatformEnum.GALAXY
    )
    resp = test_client.get("/admin/users/approved")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    approved_ids = set(u.id for u in approved_users)
    for returned_user in resp.json():
        assert returned_user["id"] in approved_ids


def test_get_pending_users(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    pending_users = _users_with_platform_membership(
        3,
        db_session=test_db_session,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.PENDING
    )
    # Include a user pending on a group to ensure group statuses are returned
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(
        group_id=GroupEnum.TSI.value,
        name="Threatened Species Initiative",
        admin_roles=[admin_role],
    )
    group_pending_user = BiocommonsUserFactory.create_sync()
    GroupMembershipFactory.create_sync(
        group=group,
        user=group_pending_user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()

    resp = test_client.get("/admin/users/pending")
    assert resp.status_code == 200
    assert len(resp.json()) == 4
    expected_ids = {u.id for u in pending_users} | {group_pending_user.id}
    for returned_user in resp.json():
        assert returned_user["id"] in expected_ids


def test_get_revoked_users(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    revoked_users = _users_with_platform_membership(
        3,
        db_session=test_db_session,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.REVOKED
    )
    # Include a user revoked on a group to ensure group statuses are returned
    admin_role = Auth0RoleFactory.create_sync(name="biocommons/role/tsi/admin")
    group = BiocommonsGroupFactory.create_sync(
        group_id=GroupEnum.TSI.value,
        name="Threatened Species Initiative",
        admin_roles=[admin_role],
    )
    group_revoked_user = BiocommonsUserFactory.create_sync()
    GroupMembershipFactory.create_sync(
        group=group,
        user=group_revoked_user,
        approval_status=ApprovalStatusEnum.REVOKED.value,
    )
    test_db_session.commit()

    resp = test_client.get("/admin/users/revoked")
    assert resp.status_code == 200
    assert len(resp.json()) == 4
    expected_ids = {u.id for u in revoked_users} | {group_revoked_user.id}
    for returned_user in resp.json():
        assert returned_user["id"] in expected_ids


# Patch asyncio.run to work in the AnyIO worker thread
def run_in_new_loop(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_approve_platform_membership_updates_db(
    test_client,
    test_db_session,
    as_admin_user,
    galaxy_platform,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(platform_memberships=[])
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    resp = test_client.post(f"/admin/users/{user.id}/platforms/galaxy/approve")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.APPROVED
    assert membership.revocation_reason is None
    assert membership.updated_by_id == admin_db_user.id

    history_entries = test_db_session.exec(
        select(PlatformMembershipHistory)
        .where(
            PlatformMembershipHistory.user_id == user.id,
            PlatformMembershipHistory.platform_id == PlatformEnum.GALAXY,
        )
        .order_by(PlatformMembershipHistory.updated_at)
    ).all()
    assert history_entries[-1].approval_status == ApprovalStatusEnum.APPROVED
    assert history_entries[-1].reason is None
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.add_roles_to_user.assert_called_once_with(
        user_id=user.id,
        role_id=galaxy_platform.platform_role.id,
    )


def test_approve_platform_membership_forbidden_without_platform_role(
    test_client,
    test_db_session,
    galaxy_platform,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(platform_memberships=[])
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/platforms/galaxy/approve",
            json={},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this platform."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.add_roles_to_user.assert_not_called()


def test_revoke_platform_membership_records_reason(
    test_client,
    test_db_session,
    as_admin_user,
    galaxy_platform,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(platform_memberships=[])
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    mock_role = RoleDataFactory.build(name="biocommons/platform/galaxy")
    mock_auth0_client.get_role_by_name.return_value = mock_role

    reason = "  No longer meets access requirements  "
    resp = test_client.post(
        f"/admin/users/{user.id}/platforms/galaxy/revoke",
        json={"reason": reason},
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REVOKED
    assert membership.revocation_reason == reason.strip()
    assert membership.updated_by_id == admin_db_user.id

    history_entries = test_db_session.exec(
        select(PlatformMembershipHistory)
        .where(
            PlatformMembershipHistory.user_id == user.id,
            PlatformMembershipHistory.platform_id == PlatformEnum.GALAXY,
        )
        .order_by(PlatformMembershipHistory.updated_at)
    ).all()
    assert history_entries[-1].approval_status == ApprovalStatusEnum.REVOKED
    assert history_entries[-1].reason == reason.strip()
    mock_auth0_client.get_role_by_name.assert_called_once_with("biocommons/platform/galaxy")
    mock_auth0_client.remove_roles_from_user.assert_called_once_with(
        user_id=user.id,
        role_id=mock_role.id,
    )


def test_revoke_platform_membership_forbidden_without_platform_role(
    test_client,
    test_db_session,
    galaxy_platform,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(platform_memberships=[])
    membership = PlatformMembershipFactory.create_sync(
        user=user,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status
    original_reason = membership.revocation_reason

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(
            biocommons_roles=["Admin"]
        )
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/platforms/galaxy/revoke",
            json={"reason": "Policy"},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this platform."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.remove_roles_from_user.assert_not_called()
    assert membership.revocation_reason == original_reason


def test_approve_group_membership_updates_db(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    mock_auth0_client,
    persistent_factories,
    mocker,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    mock_role = mocker.Mock(id="role1")
    mock_auth0_client.get_role_by_name.return_value = mock_role
    mock_auth0_client.add_roles_to_user.return_value = True

    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client.post(f"/admin/users/{user.id}/groups/{group_url}/approve")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.APPROVED
    assert membership.revocation_reason is None
    assert membership.updated_by_id == admin_db_user.id
    mock_auth0_client.add_roles_to_user.assert_called_once()
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == user.email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


def test_admin_group_approval_sends_email(
    test_client_with_email,
    test_db_session,
    as_admin_user,
    tsi_group,
    mock_auth0_client,
    persistent_factories,
    mocker,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()

    mock_role = mocker.Mock(id="role1")
    mock_auth0_client.get_role_by_name.return_value = mock_role
    mock_auth0_client.add_roles_to_user.return_value = True

    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client_with_email.post(f"/admin/users/{user.id}/groups/{group_url}/approve")

    assert resp.status_code == 200
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == user.email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


def test_admin_group_approval_no_email_when_already_approved(
    test_client_with_email,
    test_db_session,
    as_admin_user,
    tsi_group,
    mock_auth0_client,
    persistent_factories,
    mocker,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    test_db_session.commit()

    mock_role = mocker.Mock(id="role1")
    mock_auth0_client.get_role_by_name.return_value = mock_role
    mock_auth0_client.add_roles_to_user.return_value = True

    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client_with_email.post(f"/admin/users/{user.id}/groups/{group_url}/approve")

    assert resp.status_code == 400
    assert resp.json()["detail"] == "Only pending or revoked group memberships can be approved."


def test_approve_group_membership_rejected_fails(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.REJECTED.value,
        rejection_reason="Not eligible",
    )
    test_db_session.commit()

    group_url = quote(tsi_group.group_id, safe="")
    resp = test_client.post(f"/admin/users/{user.id}/groups/{group_url}/approve")

    assert resp.status_code == 400
    assert resp.json() == {
        "detail": "Only pending or revoked group memberships can be approved."
    }
    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REJECTED


def test_approve_group_membership_forbidden_without_group_role(
    test_client,
    test_db_session,
    tsi_group,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(
            biocommons_roles=[
                "Admin",
                "biocommons/role/galaxy/admin",
            ]
        )
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/groups/{tsi_group.group_id}/approve",
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this group."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status


def test_reject_group_membership_records_reason(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    reason = "Not eligible for this bundle"
    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client.post(
        f"/admin/users/{user.id}/groups/{group_url}/reject",
        json={"reason": reason},
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REJECTED
    assert membership.rejection_reason == reason
    assert membership.updated_by_id == admin_db_user.id

    history = GroupMembershipHistory.get_by_user_id_and_group_id(
        user_id=user.id,
        group_id=tsi_group.group_id,
        session=test_db_session,
    )
    assert history[-1].reason == reason


def test_reject_group_membership_forbidden_without_group_role(
    test_client,
    test_db_session,
    tsi_group,
    persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status
    original_reason = membership.rejection_reason

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(
            biocommons_roles=[
                "Admin",
                "biocommons/role/galaxy/admin",
            ]
        )
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    group_url = quote(tsi_group.group_id, safe='')
    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/groups/{group_url}/reject",
            json={"reason": "Not allowed"},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this group."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status
    assert membership.rejection_reason == original_reason


def test_unreject_group_membership(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.REJECTED.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client.post(
        f"/admin/users/{user.id}/groups/{group_url}/unreject",
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}
    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.PENDING
    assert membership.rejection_reason is None
    assert membership.updated_by_id == admin_db_user.id


def test_unreject_group_membership_status_not_rejected(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.PENDING.value,
    )
    test_db_session.commit()
    group_url = quote(tsi_group.group_id, safe='')
    resp = test_client.post(
        f"/admin/users/{user.id}/groups/{group_url}/unreject",
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "Only rejected group requests can be unrejected."}


def test_unreject_group_membership_forbidden_without_group_role(
        test_client,
        test_db_session,
        tsi_group,
        persistent_factories,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.REJECTED.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status
    original_reason = membership.rejection_reason

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(
            biocommons_roles=[
                "Admin",
                "biocommons/role/galaxy/admin",
            ]
        )
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    group_url = quote(tsi_group.group_id, safe='')
    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/groups/{group_url}/unreject",
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this group."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status
    assert membership.rejection_reason == original_reason


def test_revoke_group_membership_records_reason(
    test_client,
    test_db_session,
    as_admin_user,
    tsi_group,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    admin_db_user = as_admin_user
    test_db_session.commit()

    mock_role = RoleDataFactory.build(name=tsi_group.group_id)
    mock_auth0_client.get_role_by_name.return_value = mock_role

    reason = "Access no longer required"
    resp = test_client.post(
        f"/admin/users/{user.id}/groups/{tsi_group.group_id}/revoke",
        json={"reason": reason},
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "updated": True}

    test_db_session.refresh(membership)
    assert membership.approval_status == ApprovalStatusEnum.REVOKED
    assert membership.revocation_reason == reason
    assert membership.updated_by_id == admin_db_user.id
    mock_auth0_client.get_role_by_name.assert_called_once_with(tsi_group.group_id)
    mock_auth0_client.remove_roles_from_user.assert_called_once_with(
        user_id=user.id,
        role_id=mock_role.id,
    )


def test_revoke_group_membership_forbidden_without_group_role(
    test_client,
    test_db_session,
    tsi_group,
    persistent_factories,
    mock_auth0_client,
):
    user = BiocommonsUserFactory.create_sync(group_memberships=[])
    membership = GroupMembershipFactory.create_sync(
        group=tsi_group,
        user=user,
        approval_status=ApprovalStatusEnum.APPROVED.value,
    )
    test_db_session.commit()

    original_status = membership.approval_status
    original_reason = membership.revocation_reason

    unauthorized_admin = SessionUserFactory.build(
        access_token=AccessTokenPayloadFactory.build(
            biocommons_roles=[
                "Admin",
                "biocommons/role/galaxy/admin",
            ]
        )
    )
    app.dependency_overrides[get_session_user] = lambda: unauthorized_admin
    app.dependency_overrides[get_management_token] = lambda: "mock_token"

    try:
        resp = test_client.post(
            f"/admin/users/{user.id}/groups/{tsi_group.group_id}/revoke",
            json={"reason": "Policy"},
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 403
    assert resp.json() == {
        "detail": "You do not have permission to manage this group."
    }

    test_db_session.refresh(membership)
    assert membership.approval_status == original_status
    assert membership.revocation_reason == original_reason
    mock_auth0_client.get_role_by_name.assert_not_called()
    mock_auth0_client.remove_roles_from_user.assert_not_called()


def test_resend_verification_email(test_client, as_admin_user, test_db_session, galaxy_platform, mock_auth0_client):
    """
    Test resend verification email - requires admin permissions for the user
    """
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=galaxy_platform.id)
    response_data = EmailVerificationResponseFactory.build()
    mock_auth0_client.resend_verification_email.return_value = response_data
    resp = test_client.post(f"/admin/users/{user.id}/verification-email/resend")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Verification email resent."}


def test_resend_verification_email_unauthorized(test_client, as_admin_user, test_db_session, persistent_factories):
    """
    Test resend verification email fails when admin doesn't have permission
    """
    # User has membership to a platform that admin can't access
    platform = PlatformFactory.create_sync(id=PlatformEnum.BPA_DATA_PORTAL)
    user = _create_user_with_platform_membership(db_session=test_db_session, platform_id=platform.id)
    resp = test_client.post(f"/admin/users/{user.id}/verification-email/resend")
    assert resp.status_code == 403


def test_admin_update_user_email(
    test_client_with_email,
    as_admin_user,
    test_db_session,
    mock_auth0_client,
    galaxy_platform,
    persistent_factories,
):
    user = _create_user_with_platform_membership(
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
    )
    test_db_session.commit()

    old_email = user.email
    new_email = "updated.user@example.com"
    auth0_user = Auth0UserDataFactory.build(
        user_id=user.id,
        email=new_email,
        email_verified=False,
    )
    mock_auth0_client.update_user.return_value = auth0_user

    resp = test_client_with_email.post(
        f"/admin/users/{user.id}/email/update",
        json={"email": new_email},
    )

    assert resp.status_code == 200
    assert resp.json() == {"message": "Email updated. Verification email sent."}

    test_db_session.refresh(user)
    assert user.email == new_email
    assert user.email_verified is False

    mock_auth0_client.update_user.assert_called_once()
    _, update_kwargs = mock_auth0_client.update_user.call_args
    update_data = update_kwargs["update_data"]
    assert isinstance(update_data, UpdateUserData)
    assert update_data.email == new_email
    assert update_data.email_verified is False

    mock_auth0_client.resend_verification_email.assert_called_once_with(user_id=user.id)
    queued_emails = test_db_session.exec(select(EmailNotification)).all()
    assert len(queued_emails) == 1
    assert queued_emails[0].to_address == old_email
    assert queued_emails[0].status == EmailStatusEnum.PENDING


def test_admin_update_user_email_rejects_duplicate(
    test_client_with_email,
    as_admin_user,
    test_db_session,
    mock_auth0_client,
    galaxy_platform,
    persistent_factories,
):
    user = _create_user_with_platform_membership(
        db_session=test_db_session,
        platform_id=galaxy_platform.id,
    )
    _ = BiocommonsUserFactory.create_sync(email="existing@example.com")
    test_db_session.commit()

    resp = test_client_with_email.post(
        f"/admin/users/{user.id}/email/update",
        json={"email": "existing@example.com"},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["message"] == "Email is already in use by another user"
    assert len(data["field_errors"]) == 1
    assert data["field_errors"][0]["field"] == "email"
    assert data["field_errors"][0]["message"] == "Email is already in use by another user"


def test_get_user_details(test_client, test_db_session, as_admin_user, mock_auth0_client, persistent_factories, tsi_group, galaxy_platform):
    user = Auth0UserDataFactory.build()
    db_user = BiocommonsUserFactory.create_sync(id=user.user_id, group_memberships=[], platform_memberships=[])
    group_membership = GroupMembershipFactory.create_sync(group=tsi_group, user=db_user, approval_status="approved")
    platform_membership = PlatformMembershipFactory.create_sync(user=db_user, platform_id="galaxy")
    mock_auth0_client.get_user.return_value = user
    test_db_session.commit()
    resp = test_client.get(f"/admin/users/{user.user_id}/details")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == user.email
    groups = data["group_memberships"]
    group_membership_data = group_membership.get_data().model_dump(mode="json")
    assert groups[0] == group_membership_data
    platforms = data["platform_memberships"]
    platform_membership_data = platform_membership.get_data().model_dump(mode="json")
    assert platforms[0] == platform_membership_data


def test_get_unverified_users(test_client, test_db_session, as_admin_user, galaxy_platform, persistent_factories):
    _users_with_platform_membership(
        n=2,
        db_session=test_db_session,
        platform_id=PlatformEnum.GALAXY,
        email_verified=True,
    )
    _users_with_platform_membership(
        n=3,
        db_session=test_db_session,
        platform_id=PlatformEnum.GALAXY,
        email_verified=False,
    )
    resp = test_client.get("/admin/users/unverified")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    assert all(u["email_verified"] is False for u in data)


def test_auth0client_get_users_forwards_filter_to_httpx(mocker):
    client = Auth0Client(domain="tenant.example.auth0.com", management_token="tok")

    # Mock the underlying httpx client and its response
    fake_resp = mocker.Mock()
    fake_resp.json.return_value = []  # get_users() reads .json() only
    client._client = mocker.Mock()
    client._client.get.return_value = fake_resp

    # Call with a filter + pagination
    client.get_users(page=2, per_page=10, q="email_verified:false")

    # Assert the HTTP call had the filter and v3 search, with 0-based page
    client._client.get.assert_called_once()
    called_url = client._client.get.call_args[0][0]
    called_params = client._client.get.call_args.kwargs["params"]

    assert called_url.endswith("/api/v2/users")
    assert called_params["q"] == "email_verified:false"
    assert called_params["search_engine"] == "v3"
    assert called_params["page"] == 1
    assert called_params["per_page"] == 10
