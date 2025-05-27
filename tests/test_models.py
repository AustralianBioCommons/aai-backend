from datetime import datetime, timedelta

import pytest
from freezegun import freeze_time

from schemas.service import Service
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
    """
    Test we can approve a service and set metadata correctly..
    """
    service = Service(name="Test Service", id="service1", status="pending",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    service.approve(approved_by="admin@example.com")
    assert service.status == "approved"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME


def test_approve_service_from_app_metadata(frozen_time):
    """
    Test we can approve a service by ID from AppMetadata.
    """
    service = Service(name="Test Service", id="service1", status="pending",
                      last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    other = Service(name="Other Service", id="service2", status="pending",
                    last_updated=FROZEN_TIME - timedelta(hours=1), updated_by="")
    app_metadata = AppMetadataFactory.build(services=[service, other])
    app_metadata.approve_service(service_id="service1", approved_by="admin@example.com")
    assert service.status == "approved"
    assert service.updated_by == "admin@example.com"
    assert service.last_updated == FROZEN_TIME
    assert other.status == "pending"
