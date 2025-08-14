import pytest
import respx
from httpx import Response

from auth0.client import UsersWithTotals
from tests.datagen import (
    Auth0UserDataFactory,
    random_auth0_id,
    random_auth0_role_id,
)


@respx.mock
def test_get_users_no_pagination(test_auth0_client):
    user = Auth0UserDataFactory.build()
    route = respx.get("https://auth0.example.com/api/v2/users").mock(
        return_value=Response(200, json=[user.model_dump(mode="json")])
    )

    result = test_auth0_client.get_users()

    assert route.called
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")


@respx.mock
def test_get_users_with_pagination(test_auth0_client):
    user = Auth0UserDataFactory.build()
    route = respx.get("https://auth0.example.com/api/v2/users").respond(
        200, json=[user.model_dump(mode="json")]
    )

    result = test_auth0_client.get_users(page=2, per_page=25)

    # Validate the actual request
    request = route.calls[0].request
    assert route.called
    assert request.url.params["page"] == "1"
    assert request.url.params["per_page"] == "25"
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")


@respx.mock
def test_get_user_by_id(test_auth0_client):
    user_id = "auth0|789"
    user = Auth0UserDataFactory.build(user_id=user_id)
    route = respx.get(f"https://auth0.example.com/api/v2/users/{user_id}").mock(
        return_value=Response(200, json=user.model_dump(mode="json"))
    )

    result = test_auth0_client.get_user(user_id)

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
def test_search_users_methods(test_auth0_client, method, query):
    user = Auth0UserDataFactory.build()
    route = respx.get("https://auth0.example.com/api/v2/users").respond(
        200, json=[user.model_dump(mode="json")]
    )

    result = getattr(test_auth0_client, method)(page=3, per_page=50)

    assert route.called
    request = route.calls[0].request
    assert request.url.params["q"] == query
    assert request.url.params["search_engine"] == "v3"
    assert request.url.params["page"] == "2"
    assert request.url.params["per_page"] == "50"
    assert result[0].model_dump(mode="json") == user.model_dump(mode="json")


@respx.mock
def test_get_role_users(test_auth0_client):
    """
    Test we can get users for a role from Auth0 API
    """
    role_id = "auth0|role_id"
    users = Auth0UserDataFactory.batch(size=3)
    route = respx.get(f"https://auth0.example.com/api/v2/roles/{role_id}/users").respond(
        200, json=[u.model_dump(mode="json") for u in users]
    )
    result = test_auth0_client.get_role_users(role_id)
    assert route.called
    assert len(result) == 3
    for user in result:
        assert any(user.user_id == original.user_id for original in users)
    assert result[0].model_dump(mode="json") == users[0].model_dump(mode="json")


@respx.mock
def test_get_all_role_users(test_auth0_client):
    """
    Test we can get all users for a role from Auth0 API, automatically
    running through multiple pages if necessary.
    """
    role_id = "auth0|role_id"
    users = Auth0UserDataFactory.batch(size=150)
    batch1 = UsersWithTotals(users=users[:100], total=150, start=0, limit=100)
    batch2 = UsersWithTotals(users=users[100:], total=150, start=100, limit=100)
    route = respx.get(f"https://auth0.example.com/api/v2/roles/{role_id}/users").mock(
        side_effect=[Response(200, json=batch1.model_dump(mode="json")),
                     Response(200, json=batch2.model_dump(mode="json"))]
    )
    result = test_auth0_client.get_all_role_users(role_id)
    assert route.called
    assert route.call_count == 2
    assert len(result) == 150


@respx.mock
def test_add_roles_to_user(test_auth0_client):
    """
    Test we can add roles to a user in Auth0 API
    """
    user_id = random_auth0_id()
    role_id = random_auth0_role_id()
    route = respx.post(f"https://auth0.example.com/api/v2/users/{user_id}/roles").respond(204)
    test_auth0_client.add_roles_to_user(user_id, role_id)
    assert route.called
    call_data = route.calls[0].request.content
    # Check role_id is passed as a list
    assert call_data == b'{"roles":["' +role_id.encode() + b'"]}'
