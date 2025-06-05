import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from freezegun import freeze_time

from auth.validator import get_current_user, user_is_admin
from main import app
from routers.admin import PaginationParams
from schemas import Resource, Service
from tests.datagen import (
    AccessTokenPayloadFactory,
    AppMetadataFactory,
    BiocommonsAuth0UserFactory,
    SessionUserFactory,
)

FROZEN_TIME = datetime(2025, 1, 1, 12, 0, 0)


@pytest.fixture
def frozen_time():
    """
    Freeze time so datetime.now() returns FROZEN_TIME.
    """
    with freeze_time("2025-01-01 12:00:00"):
        yield


@pytest.fixture
def mock_auth0_client(mocker):
    mock_client = mocker.patch("routers.admin.Auth0Client")
    return mock_client()


def test_pagination_params_start_index():
    """
    Test we can get the current start index given the page number and per_page.
    """
    params = PaginationParams(page=2, per_page=10)
    # start index for page 1 is 0, for page 2 is 0 + per_page = 10
    assert params.start_index == 10


def test_get_users_requires_admin_unauthorized(test_client, mocker):
    def get_nonadmin_user():
        payload = AccessTokenPayloadFactory.build(biocommons_roles=["User"])
        return SessionUserFactory.build(access_token=payload)

    app.dependency_overrides[get_current_user] = get_nonadmin_user
    mocker.patch("routers.admin.get_management_token", return_value="mock_token")
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


def test_get_users(test_client, as_admin_user, mock_auth0_client):
    users = BiocommonsAuth0UserFactory.batch(3)
    mock_auth0_client.get_users.return_value = users
    resp = test_client.get("/admin/users")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_get_users_pagination_params(test_client, as_admin_user, mock_auth0_client):
    users = BiocommonsAuth0UserFactory.batch(3)
    mock_auth0_client.get_users.return_value = users
    resp = test_client.get("/admin/users?page=2&per_page=10")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_get_users_invalid_params(test_client, as_admin_user, mock_auth0_client):
    users = BiocommonsAuth0UserFactory.batch(3)
    mock_auth0_client.get_users.return_value = users
    resp = test_client.get("/admin/users?page=0&per_page=500")
    assert resp.status_code == 422
    error_msg = resp.json()["detail"]
    assert "Invalid page params" in error_msg


def test_get_user(test_client, as_admin_user, mock_auth0_client):
    user = BiocommonsAuth0UserFactory.build()
    mock_auth0_client.get_user.return_value = user
    resp = test_client.get(f"/admin/users/{user.user_id}")
    assert resp.status_code == 200
    assert resp.json() == user.model_dump(mode='json')


def test_get_approved_users(test_client, as_admin_user, mock_auth0_client):
    approved_users = BiocommonsAuth0UserFactory.batch(3, app_metadata={"services": [{"name": "BPA", "status": "approved"}]})
    mock_auth0_client.get_approved_users.return_value = approved_users
    resp = test_client.get("/admin/users/approved")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    approved_ids = set(u.user_id for u in approved_users)
    for returned_user in resp.json():
        assert returned_user["app_metadata"]["services"][0]["status"] == "approved"
        assert returned_user["user_id"] in approved_ids


def test_get_pending_users(test_client, as_admin_user, mock_auth0_client):
    pending_users = BiocommonsAuth0UserFactory.batch(3, app_metadata={"services": [{"name": "BPA", "status": "pending"}]})
    mock_auth0_client.get_pending_users.return_value = pending_users
    resp = test_client.get("/admin/users/pending")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    pending_ids = set(u.user_id for u in pending_users)
    for returned_user in resp.json():
        assert returned_user["app_metadata"]["services"][0]["status"] == "pending"
        assert returned_user["user_id"] in pending_ids


def test_get_revoked(test_client, as_admin_user, mock_auth0_client):
    revoked_users = BiocommonsAuth0UserFactory.batch(3, app_metadata={"services": [{"name": "BPA", "status": "revoked"}]})
    mock_auth0_client.get_revoked_users.return_value = revoked_users
    resp = test_client.get("/admin/users/revoked")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    revoked_ids = set(u.user_id for u in revoked_users)
    for returned_user in resp.json():
        assert returned_user["app_metadata"]["services"][0]["status"] == "revoked"
        assert returned_user["user_id"] in revoked_ids


# Patch asyncio.run to work in the AnyIO worker thread
def run_in_new_loop(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_approve_service(test_client, as_admin_user, mock_auth0_client, mocker):
    """
    Test that our approved service endpoint tries to update the Auth0 user's metadata.

    Note this is currently pretty clunky due to the need to mock out asyncio.run.
    """
    # Build test user and metadata
    service = Service(
        name="Test Service",
        id="service1",
        status="pending",
        last_updated=FROZEN_TIME - timedelta(hours=1),
        updated_by=""
    )
    app_metadata = AppMetadataFactory.build(services=[service])
    user = BiocommonsAuth0UserFactory.build(app_metadata=app_metadata.model_dump(mode="json"))
    approving_user = BiocommonsAuth0UserFactory.build()

    # Mock Auth0 client behavior
    mock_auth0_client.get_user.side_effect = [user, approving_user]

    # Patch update_user_metadata as an AsyncMock
    mock_update = mocker.patch(
        "routers.admin.update_user_metadata",
        new_callable=mocker.AsyncMock,
        return_value={"status": "ok", "updated": True}
    )

    mocker.patch("routers.admin.asyncio.run", side_effect=run_in_new_loop)

    # Make the API call
    resp = test_client.post(f"/admin/users/{user.user_id}/services/{service.id}/approve")

    # Validate HTTP response
    assert resp.status_code == 200
    mock_update.assert_awaited_once()

    # Validate that update_user_metadata was called with correct data
    args, kwargs = mock_update.call_args
    assert kwargs["user_id"] == user.user_id
    assert kwargs["token"] == mock_auth0_client.management_token
    assert "services" in kwargs["metadata"]
    service_data = kwargs["metadata"]["services"][0]
    assert service_data["status"] == "approved"
    assert service_data["id"] == service.id
    assert service_data["updated_by"] == approving_user.email


def test_revoke_service(test_client, as_admin_user, mock_auth0_client, mocker):
    """
    Test that our approved service endpoint tries to update the Auth0 user's metadata.

    Note this is currently pretty clunky due to the need to mock out asyncio.run.
    """
    resource1 = Resource(name="Test Resource", id="resource1", status="approved")
    resource2 = Resource(name="Test Resource", id="resource2", status="approved")
    service = Service(
        name="Test Service",
        id="service1",
        status="approved",
        last_updated=FROZEN_TIME - timedelta(hours=1),
        updated_by="",
        resources=[resource1, resource2]
    )
    app_metadata = AppMetadataFactory.build(services=[service])
    user = BiocommonsAuth0UserFactory.build(app_metadata=app_metadata.model_dump(mode="json"))
    revoking_user = BiocommonsAuth0UserFactory.build()

    # Mock Auth0 client behavior
    mock_auth0_client.get_user.side_effect = [user, revoking_user]

    # Patch update_user_metadata as an AsyncMock
    mock_update = mocker.patch(
        "routers.admin.update_user_metadata",
        new_callable=mocker.AsyncMock,
        return_value={"status": "ok", "updated": True}
    )

    mocker.patch("routers.admin.asyncio.run", side_effect=run_in_new_loop)

    # Make the API call
    resp = test_client.post(f"/admin/users/{user.user_id}/services/{service.id}/revoke")

    # Validate HTTP response
    assert resp.status_code == 200
    mock_update.assert_awaited_once()

    # Validate that update_user_metadata was called with correct data
    args, kwargs = mock_update.call_args
    assert kwargs["user_id"] == user.user_id
    assert kwargs["token"] == mock_auth0_client.management_token
    assert "services" in kwargs["metadata"]
    service_data = kwargs["metadata"]["services"][0]
    assert service_data["status"] == "revoked"
    assert service_data["id"] == service.id
    assert service_data["updated_by"] == revoking_user.email
    for resource in service_data["resources"]:
        assert resource["status"] == "revoked"


def test_approve_resource(test_client, as_admin_user, mock_auth0_client, mocker):
    """
    Test that our approve resource endpoint tries to update the Auth0 user's metadata.
    """
    # Build test user and metadata
    resource = Resource(name="Test Resource", id="resource1", status="pending")
    service = Service(
        name="Test Service",
        id="service1",
        status="approved",
        last_updated=FROZEN_TIME - timedelta(hours=1),
        resources=[resource],
        updated_by=""
    )
    app_metadata = AppMetadataFactory.build(services=[service])
    user = BiocommonsAuth0UserFactory.build(app_metadata=app_metadata.model_dump(mode="json"))

    # Mock Auth0 client behavior
    mock_auth0_client.get_user.return_value = user

    # Patch update_user_metadata as an AsyncMock
    mock_update = mocker.patch(
        "routers.admin.update_user_metadata",
        new_callable=mocker.AsyncMock,
        return_value={"status": "ok", "updated": True}
    )

    mocker.patch("routers.admin.asyncio.run", side_effect=run_in_new_loop)

    # Make the API call
    resp = test_client.post(f"/admin/users/{user.user_id}/services/{service.id}/resources/{resource.id}/approve")

    # Validate HTTP response
    assert resp.status_code == 200
    mock_update.assert_awaited_once()

    # Validate that update_user_metadata was called with correct data
    args, kwargs = mock_update.call_args
    assert kwargs["user_id"] == user.user_id
    assert kwargs["token"] == mock_auth0_client.management_token
    assert "services" in kwargs["metadata"]
    service_data = kwargs["metadata"]["services"][0]
    resource_data = service_data["resources"][0]
    assert resource_data["status"] == "approved"
    assert resource_data["id"] == resource.id
