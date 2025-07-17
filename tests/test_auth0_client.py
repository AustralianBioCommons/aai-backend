import pytest
import respx
from httpx import Response

from tests.datagen import BiocommonsAuth0UserFactory


@respx.mock
def test_get_users_no_pagination(auth0_client):
    user = BiocommonsAuth0UserFactory.build()
    route = respx.get("https://example.auth0.com/api/v2/users").mock(
        return_value=Response(200, json=[user.model_dump(mode="json")])
    )

    result = auth0_client.get_users()

    assert route.called
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")


@respx.mock
def test_get_users_with_pagination(auth0_client):
    user = BiocommonsAuth0UserFactory.build()
    route = respx.get("https://example.auth0.com/api/v2/users").respond(
        200, json=[user.model_dump(mode="json")]
    )

    result = auth0_client.get_users(page=2, per_page=25)

    # Validate the actual request
    request = route.calls[0].request
    assert route.called
    assert request.url.params["page"] == "1"
    assert request.url.params["per_page"] == "25"
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")


@respx.mock
def test_get_user_by_id(auth0_client):
    user_id = "auth0|789"
    user = BiocommonsAuth0UserFactory.build(user_id=user_id)
    route = respx.get(f"https://example.auth0.com/api/v2/users/{user_id}").mock(
        return_value=Response(200, json=user.model_dump(mode="json"))
    )

    result = auth0_client.get_user(user_id)

    assert route.called
    assert result.model_dump(mode="json") == user.model_dump(mode="json")


@pytest.mark.parametrize(
    "method,query",
    [
        ("get_approved_users", 'app_metadata.services.status:"approved"'),
        ("get_pending_users", 'app_metadata.services.status:"pending"'),
        ("get_revoked_users", 'app_metadata.services.status:"revoked"'),
    ]
)
@respx.mock
def test_search_users_methods(auth0_client, method, query):
    user = BiocommonsAuth0UserFactory.build()
    route = respx.get("https://example.auth0.com/api/v2/users").respond(
        200, json=[user.model_dump(mode="json")]
    )

    result = getattr(auth0_client, method)(page=3, per_page=50)

    assert route.called
    request = route.calls[0].request
    assert request.url.params["q"] == query
    assert request.url.params["search_engine"] == "v3"
    assert request.url.params["page"] == "2"
    assert request.url.params["per_page"] == "50"
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")
