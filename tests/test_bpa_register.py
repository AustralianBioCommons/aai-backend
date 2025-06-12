from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from schemas import Service
from schemas.biocommons import BiocommonsRegisterData
from tests.datagen import AccessTokenPayloadFactory, BPARegistrationDataFactory


@pytest.fixture
def valid_registration_data():
    """Fixture that provides valid BPA registration data."""
    return BPARegistrationDataFactory.build(
        username="testuser",
        fullname="Test User",
        email="test@example.com",
        reason="Need access to BPA resources",
        password="SecurePass123!",
        organizations=BPARegistrationDataFactory.get_default_organizations(),
    ).model_dump()


@pytest.fixture
def mock_auth_token(mocker):
    token = AccessTokenPayloadFactory.build(
        sub="auth0|123456789",
        biocommons_roles=["acdc/indexd_admin"],
    )
    mocker.patch("auth.validator.verify_jwt", return_value=token)
    mocker.patch("auth.management.get_management_token", return_value="mock_token")
    mocker.patch("routers.bpa_register.get_management_token", return_value="mock_token")
    return token


def test_to_biocommons_register_data(valid_registration_data):
    bpa_data = BPARegistrationDataFactory.build()
    bpa_service = Service(
        name="Bioplatforms Australia",
        id="bpa",
        status="approved",
        last_updated=datetime.now(UTC),
        updated_by="",
    )
    register_data = BiocommonsRegisterData.from_bpa_registration(
        bpa_data, bpa_service=bpa_service
    )
    assert register_data.username == bpa_data.username
    assert register_data.name == bpa_data.fullname
    # Test we fill the registration_from field in app_metadata
    assert register_data.app_metadata.registration_from == "bpa"


def test_successful_registration(
    test_client, mock_auth_token, mocker, valid_registration_data
):
    """Test successful user registration with BPA service"""
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"user_id": "auth0|123"}

    mock_post = mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

    response = test_client.post("/bpa/register", json=valid_registration_data)

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"

    called_data = mock_post.call_args[1]["json"]
    assert called_data["email"] == valid_registration_data["email"]
    assert called_data["username"] == valid_registration_data["username"]
    assert called_data["name"] == valid_registration_data["fullname"]

    app_metadata = called_data["app_metadata"]
    assert len(app_metadata["services"]) == 1
    bpa_service = app_metadata["services"][0]
    assert bpa_service["name"] == "Bioplatforms Australia Data Portal"
    assert bpa_service["status"] == "pending"
    assert "last_updated" in bpa_service
    assert "updated_by" in bpa_service
    assert bpa_service["updated_by"] == valid_registration_data["email"]
    assert len(bpa_service["resources"]) == 2

    for resource in bpa_service["resources"]:
        assert "last_updated" in resource
        assert "updated_by" in resource
        assert resource["updated_by"] == valid_registration_data["email"]

    assert (
        called_data["user_metadata"]["bpa"]["registration_reason"]
        == valid_registration_data["reason"]
    )


# Other existing tests unchanged
