from datetime import datetime, timedelta

import pytest
from freezegun import freeze_time

from schemas.service import Resource, Service
from tests.datagen import AppMetadataFactory

FROZEN_TIME = datetime(2025, 1, 1, 12, 0, 0)


@pytest.fixture
def frozen_time():
    """
    Freeze time so datetime.now() returns FROZEN_TIME.
    """
    with freeze_time("2025-01-01 12:00:00"):
        yield


def test_approve_service(frozen_time):
    service = Service(name="Test Service", id="service1", status="pending",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    service.approve(updated_by="admin@example.com")
    assert service.status == "approved"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME


def test_approve_service_from_app_metadata(frozen_time):
    service = Service(name="Test Service", id="service1", status="pending",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    other = Service(name="Other Service", id="service2", status="pending",
                    last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    app_metadata = AppMetadataFactory.build(services=[service, other])
    app_metadata.approve_service(service_id="service1", updated_by="admin@example.com")
    assert service.status == "approved"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME
    assert other.status == "pending"


def test_revoke_service(frozen_time):
    service = Service(name="Test Service", id="service1", status="approved",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    service.revoke(updated_by="admin@example.com")
    assert service.status == "revoked"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME


def test_revoke_service_from_app_metadata(frozen_time):
    service = Service(name="Test Service", id="service1", status="approved",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    other = Service(name="Other Service", id="service2", status="approved",
                    last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    app_metadata = AppMetadataFactory.build(services=[service, other])
    app_metadata.revoke_service(service_id="service1", updated_by="admin@example.com")
    assert service.status == "revoked"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME
    assert other.status == "approved"


def test_approve_resource(frozen_time):
    resource = Resource(
        name="Test Resource",
        id="resource1",
        status="pending",
        initial_request_time=FROZEN_TIME
    )
    resource.approve()
    assert resource.status == "approved"
    assert resource.initial_request_time == FROZEN_TIME


def test_approve_resource_from_service(frozen_time):
    resource = Resource(
        name="Test Resource",
        id="resource1",
        status="pending",
        initial_request_time=FROZEN_TIME
    )
    service = Service(name="Test Service", id="service1", status="approved",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="",
                      resources=[resource])
    service.approve_resource(resource_id="resource1")
    assert resource.status == "approved"
    assert resource.initial_request_time == FROZEN_TIME


def test_approve_resource_from_pending_service(frozen_time):
    """
    Test that trying to approve a resource from a pending service raises an error.
    """
    resource = Resource(
        name="Test Resource",
        id="resource1",
        status="pending",
        initial_request_time=FROZEN_TIME
    )

    service = Service(name="Test Service", id="service1", status="pending",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="",
                      resources=[resource])
    with pytest.raises(PermissionError, match="Service must be approved before approving a resource."):
        service.approve_resource(resource_id="resource1")
    assert resource.status == "pending"
    assert resource.initial_request_time == FROZEN_TIME


def test_approve_resource_from_app_metadata(frozen_time):
    resource = Resource(
        name="Test Resource",
        id="resource1",
        status="pending",
        initial_request_time=FROZEN_TIME
    )
    service = Service(name="Test Service", id="service1", status="approved",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="",
                      resources=[resource])
    app_metadata = AppMetadataFactory.build(services=[service])
    app_metadata.approve_resource(service_id="service1", resource_id="resource1", updated_by="admin@example.com")

    assert resource.status == "approved"
    assert resource.initial_request_time == FROZEN_TIME
