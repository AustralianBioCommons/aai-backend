import asyncio
from datetime import datetime

import pytest
from fastapi import HTTPException
from freezegun import freeze_time

from auth.management import get_management_token
from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client
from db.types import ApprovalStatusEnum, PlatformEnum
from main import app
from routers.admin import PaginationParams
from tests.datagen import (
    AccessTokenPayloadFactory,
    Auth0UserDataFactory,
    EmailVerificationResponseFactory,
    SessionUserFactory,
)
from tests.db.datagen import (
    BiocommonsGroupFactory,
    BiocommonsUserFactory,
    GroupMembershipFactory,
    PlatformMembershipFactory,
)

FROZEN_TIME = datetime(2025, 1, 1, 12, 0, 0)


@pytest.fixture
def frozen_time():
    """
    Freeze time so datetime.now() returns FROZEN_TIME.
    """
    with freeze_time("2025-01-01 12:00:00"):
        yield


def test_pagination_params_start_index():
    """
    Test we can get the current start index given the page number and per_page.
    """
    params = PaginationParams(page=2, per_page=10)
    # start index for page 1 is 0, for page 2 is 0 + per_page = 10
    assert params.start_index == 10


def test_get_users_requires_admin_unauthorized(test_client):
    def get_nonadmin_user():
        payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
        return SessionUserFactory.build(access_token=payload)

    app.dependency_overrides[get_current_user] = get_nonadmin_user
    app.dependency_overrides[get_management_token] = lambda: "mock_token"
    resp = test_client.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json() == {"detail": "You must be an admin to access this endpoint."}
    app.dependency_overrides.clear()


def test_user_is_admin(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    admin_user = SessionUserFactory.build(access_token=payload)
    assert user_is_admin(current_user=admin_user, settings=mock_settings)


def test_user_is_admin_nonadmin_user(mock_settings):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
    user = SessionUserFactory.build(access_token=payload)
    with pytest.raises(HTTPException, match="You must be an admin to access this endpoint."):
        user_is_admin(current_user=user, settings=mock_settings)


def test_get_users(test_client, as_admin_user, mock_auth0_client, test_db_session):
    # Create some test users in the database
    db_users = BiocommonsUserFactory.batch(3)
    for user in db_users:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_get_users_pagination_params(test_client, as_admin_user, mock_auth0_client, test_db_session):
    # Create some test users in the database
    db_users = BiocommonsUserFactory.batch(3)
    for user in db_users:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?page=2&per_page=10")
    assert resp.status_code == 200
    # Page 2 with per_page=10 should be empty since we only have 3 users
    assert len(resp.json()) == 0


def test_get_users_invalid_params(test_client, as_admin_user, mock_auth0_client):
    users = Auth0UserDataFactory.batch(3)
    mock_auth0_client.get_users.return_value = users
    resp = test_client.get("/admin/users?page=0&per_page=500")
    assert resp.status_code == 422
    error_msg = resp.json()["detail"]
    assert "Invalid page params" in error_msg


def test_get_users_filter_by_platform(test_client, as_admin_user, test_db_session):
    from db.models import ApprovalStatusEnum, PlatformEnum, PlatformMembership
    from tests.db.datagen import BiocommonsUserFactory

    galaxy_users = BiocommonsUserFactory.batch(2)
    other_users = BiocommonsUserFactory.batch(2)

    for user in galaxy_users + other_users:
        test_db_session.add(user)
    test_db_session.commit()

    for user in galaxy_users:
        membership = PlatformMembership(
            user_id=user.id,
            platform_id=PlatformEnum.GALAXY,
            approval_status=ApprovalStatusEnum.APPROVED
        )
        test_db_session.add(membership)
    test_db_session.commit()

    resp = test_client.get("/admin/users?filter_by=galaxy")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    resp = test_client.get("/admin/users?filter_by=bpa_data_portal")
    assert resp.status_code == 200
    assert len(resp.json()) == 0


def test_get_users_filter_by_group(test_client, as_admin_user, test_db_session):
    from db.models import (
        ApprovalStatusEnum,
        BiocommonsGroup,
        GroupMembership,
    )
    from db.types import GroupEnum
    from tests.db.datagen import BiocommonsUserFactory

    tsi_group = BiocommonsGroup(
        group_id=GroupEnum.TSI,
        name="Threatened Species Initiative Bundle"
    )
    test_db_session.add(tsi_group)
    test_db_session.commit()

    tsi_users = BiocommonsUserFactory.batch(2)
    other_users = BiocommonsUserFactory.batch(2)

    for user in tsi_users + other_users:
        test_db_session.add(user)
    test_db_session.commit()

    for user in tsi_users:
        membership = GroupMembership(
            user_id=user.id,
            group_id=GroupEnum.TSI,
            approval_status=ApprovalStatusEnum.APPROVED
        )
        test_db_session.add(membership)
    test_db_session.commit()

    resp = test_client.get("/admin/users?filter_by=tsi")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    resp = test_client.get("/admin/users?filter_by=bpa_galaxy")
    assert resp.status_code == 404
    assert "Group 'bpa_galaxy' not found" in resp.json()["detail"]


def test_get_users_invalid_filter(test_client, as_admin_user, test_db_session):
    resp = test_client.get("/admin/users?filter_by=invalid_filter")
    assert resp.status_code == 400
    assert "Invalid filter_by value 'invalid_filter'" in resp.json()["detail"]


def test_get_users_search_by_email_exact(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="john.doe@example.com", username="johndoe")
    user2 = BiocommonsUserFactory.build(email="jane.smith@example.com", username="janesmith")
    user3 = BiocommonsUserFactory.build(email="bob.wilson@example.com", username="bobwilson")

    for user in [user1, user2, user3]:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?search=john.doe@example.com")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["email"] == "john.doe@example.com"


def test_get_users_search_by_email_partial(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="john.doe@example.com", username="johndoe")
    user2 = BiocommonsUserFactory.build(email="jane.smith@example.com", username="janesmith")
    user3 = BiocommonsUserFactory.build(email="bob.wilson@different.com", username="bobwilson")

    for user in [user1, user2, user3]:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?search=example.com")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    emails = [user["email"] for user in results]
    assert "john.doe@example.com" in emails
    assert "jane.smith@example.com" in emails
    assert "bob.wilson@different.com" not in emails


def test_get_users_search_by_username(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="john@example.com", username="johndoe")
    user2 = BiocommonsUserFactory.build(email="jane@example.com", username="janesmith")
    user3 = BiocommonsUserFactory.build(email="bob@example.com", username="bobwilson")

    for user in [user1, user2, user3]:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["username"] == "johndoe"


def test_get_users_search_by_username_partial(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="john@example.com", username="johnsmith")
    user2 = BiocommonsUserFactory.build(email="jane@example.com", username="johndoe")
    user3 = BiocommonsUserFactory.build(email="bob@example.com", username="bobwilson")

    for user in [user1, user2, user3]:
        test_db_session.add(user)
    test_db_session.commit()

    resp = test_client.get("/admin/users?search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    usernames = [user["username"] for user in results]
    assert "johnsmith" in usernames
    assert "johndoe" in usernames
    assert "bobwilson" not in usernames


def test_get_users_search_case_insensitive(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="John.Doe@Example.Com", username="JohnDoe")

    test_db_session.add(user1)
    test_db_session.commit()

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


def test_get_users_search_empty_string(test_client, as_admin_user, test_db_session):
    from tests.db.datagen import BiocommonsUserFactory

    users = BiocommonsUserFactory.batch(3)
    for user in users:
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


def test_get_users_search_with_filter(test_client, as_admin_user, test_db_session):
    from db.models import ApprovalStatusEnum, PlatformEnum, PlatformMembership
    from tests.db.datagen import BiocommonsUserFactory

    user1 = BiocommonsUserFactory.build(email="john@example.com", username="johndoe")
    user2 = BiocommonsUserFactory.build(email="jane@example.com", username="janesmith")

    for user in [user1, user2]:
        test_db_session.add(user)
    test_db_session.commit()

    membership = PlatformMembership(
        user_id=user1.id,
        platform_id=PlatformEnum.GALAXY,
        approval_status=ApprovalStatusEnum.APPROVED
    )
    test_db_session.add(membership)
    test_db_session.commit()

    resp = test_client.get("/admin/users?filter_by=galaxy&search=john")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["username"] == "johndoe"

    resp = test_client.get("/admin/users?filter_by=galaxy&search=jane")
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 0


def test_get_filter_options(test_client, as_admin_user):
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
    expected_ids = {"galaxy", "bpa_data_portal", "tsi", "bpa_galaxy"}
    assert option_ids == expected_ids

    option_dict = {opt["id"]: opt["name"] for opt in options}
    assert option_dict["galaxy"] == "Galaxy Australia"
    assert option_dict["bpa_data_portal"] == "Bioplatforms Australia Data Portal"
    assert option_dict["tsi"] == "Threatened Species Initiative Bundle"
    assert option_dict["bpa_galaxy"] == "Bioplatforms Australia Data Portal & Galaxy Australia Bundle"


def test_get_user(test_client, test_db_session, as_admin_user, persistent_factories):
    user = BiocommonsUserFactory.create_sync()
    resp = test_client.get(f"/admin/users/{user.id}")
    assert resp.status_code == 200
    assert resp.json() == user.model_dump(mode='json')


def test_get_approved_users(test_client, test_db_session, as_admin_user, persistent_factories):
    approved_users = BiocommonsUserFactory.create_batch_sync(3)
    for u in approved_users:
        u.add_platform_membership(platform=PlatformEnum.GALAXY, db_session=test_db_session, auto_approve=True)
    resp = test_client.get("/admin/users/approved")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    approved_ids = set(u.id for u in approved_users)
    for returned_user in resp.json():
        assert returned_user["id"] in approved_ids


def test_get_pending_users(test_client, test_db_session, as_admin_user, persistent_factories):
    pending_users = BiocommonsUserFactory.create_batch_sync(3)
    for u in pending_users:
        u.add_platform_membership(platform=PlatformEnum.GALAXY, db_session=test_db_session, auto_approve=False)
    resp = test_client.get("/admin/users/pending")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    expected_ids = set(u.id for u in pending_users)
    for returned_user in resp.json():
        assert returned_user["id"] in expected_ids


def test_get_revoked_users(test_client, test_db_session, as_admin_user, persistent_factories):
    revoked_users = BiocommonsUserFactory.create_batch_sync(3)
    for u in revoked_users:
        PlatformMembershipFactory.create_sync(user=u, platform_id=PlatformEnum.GALAXY, approval_status=ApprovalStatusEnum.REVOKED)
    test_db_session.commit()
    resp = test_client.get("/admin/users/revoked")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    expected_ids = set(u.id for u in revoked_users)
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


def test_resend_verification_email(test_client, as_admin_user, mock_auth0_client):
    user = Auth0UserDataFactory.build()
    response_data = EmailVerificationResponseFactory.build()
    mock_auth0_client.resend_verification_email.return_value = response_data
    resp = test_client.post(f"/admin/users/{user.user_id}/verification-email/resend")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Verification email resent."}


def test_get_user_details(test_client, test_db_session, as_admin_user, mock_auth0_client, persistent_factories):
    user = Auth0UserDataFactory.build()
    group = BiocommonsGroupFactory.create_sync(group_id="biocommons/group/tsi")
    db_user = BiocommonsUserFactory.create_sync(id=user.user_id, group_memberships=[], platform_memberships=[])
    group_membership = GroupMembershipFactory.create_sync(group=group, user=db_user, approval_status="approved")
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


def test_get_unverified_users(test_client, test_db_session, as_admin_user, persistent_factories):
    BiocommonsUserFactory.create_batch_sync(2, email_verified=True)
    BiocommonsUserFactory.create_batch_sync(3, email_verified=False)
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
