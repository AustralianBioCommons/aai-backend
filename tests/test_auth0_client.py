import json

import pytest
import respx
from httpx import Response
from pydantic import ValidationError

from auth0.client import RoleUserData, RoleUsersWithTotals, UpdateUserData
from tests.datagen import (
    Auth0UserDataFactory,
    BiocommonsRegisterDataFactory,
    EmailVerificationResponseFactory,
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
    users = [
        {"user_id": random_auth0_id(), "name": "User 1"},
        {"user_id": random_auth0_id(), "name": "User 2"},
        {"user_id": random_auth0_id(), "name": "User 3"},
    ]
    route = respx.get(f"https://auth0.example.com/api/v2/roles/{role_id}/users").respond(200, json=users)
    result = test_auth0_client.get_role_users(role_id)
    assert route.called
    assert len(result) == 3
    for user in result:
        assert any(user.user_id == original["user_id"] for original in users)
    assert isinstance(result[0], RoleUserData)


@respx.mock
def test_get_all_role_users(test_auth0_client):
    """
    Test we can get all users for a role from Auth0 API, automatically
    running through multiple pages if necessary.
    """
    role_id = "auth0|role_id"
    users = [
        {"user_id": random_auth0_id(), "name": f"User {i}"}
        for i in range(150)
    ]
    batch1 = RoleUsersWithTotals(users=[RoleUserData(**data) for data in users[:100]], total=150, start=0, limit=100)
    batch2 = RoleUsersWithTotals(users=[RoleUserData(**data) for data in users[100:]], total=150, start=100, limit=100)
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


@respx.mock
def test_remove_roles_from_user(test_auth0_client):
    """
    Test we can remove roles from a user in Auth0 API
    """
    user_id = random_auth0_id()
    role_id = random_auth0_role_id()
    route = respx.delete(f"https://auth0.example.com/api/v2/users/{user_id}/roles").respond(204)
    test_auth0_client.remove_roles_from_user(user_id, role_id)
    assert route.called
    call_data = route.calls[0].request.content
    assert call_data == b'{"roles":["' + role_id.encode() + b'"]}'


@respx.mock
def test_create_user(test_auth0_client):
    """
    Test that we call the Auth0 API to create a user with the data we expect
    """
    register_data = BiocommonsRegisterDataFactory.build()
    # Mock the response from the Auth0 API, non-matching data
    auth0_data = Auth0UserDataFactory.build()
    route = respx.post("https://auth0.example.com/api/v2/users").respond(201, json=auth0_data.model_dump(mode="json"))
    test_auth0_client.create_user(register_data)
    assert route.called
    assert json.loads(route.calls.last.request.content) == register_data.model_dump(mode="json", exclude_none=True)


@respx.mock
def test_create_user_omits_none(test_auth0_client):
    """
    Test that None/null fields are omitted from the request to Auth0 API
    """
    register_data = BiocommonsRegisterDataFactory.build(name=None, user_metadata=None)
    # Mock the response from the Auth0 API, non-matching data
    auth0_data = Auth0UserDataFactory.build()
    route = respx.post("https://auth0.example.com/api/v2/users").respond(201, json=auth0_data.model_dump(mode="json"))
    test_auth0_client.create_user(register_data)
    assert route.called
    call_data = json.loads(route.calls.last.request.content)
    assert call_data == register_data.model_dump(mode="json", exclude_none=True)
    assert "name" not in call_data
    assert "user_metadata" not in call_data


@respx.mock
def test_resend_verification_email(test_auth0_client):
    """
    Test resending a verification email
    """
    user_id = random_auth0_id()
    # Expected response from Auth0 API
    resp_data = EmailVerificationResponseFactory.build()
    route = respx.post(
        "https://auth0.example.com/api/v2/jobs/verification-email"
    ).respond(201, json=resp_data.model_dump(mode="json"))
    resp = test_auth0_client.resend_verification_email(user_id)
    assert route.called
    call_data = json.loads(route.calls.last.request.content)
    assert call_data == {"user_id": user_id}
    assert resp == resp_data


def test_update_user_data_requires_connection():
    with pytest.raises(ValidationError, match="Must provide connection"):
        UpdateUserData(username="username")


@respx.mock
def test_update_user(test_auth0_client):
    user_id = random_auth0_id()
    returned_user = Auth0UserDataFactory.build(user_id=user_id, username="updated_username")
    route = respx.patch(f"https://auth0.example.com/api/v2/users/{user_id}").respond(200, json=returned_user.model_dump(mode="json"))
    update_data = UpdateUserData(username="username", connection="Username-Password-Authentication")
    resp = test_auth0_client.update_user(user_id, update_data)
    assert resp.username == "updated_username"
    assert route.called
