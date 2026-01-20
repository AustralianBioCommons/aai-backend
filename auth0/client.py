__all__ = ["Auth0Client"]

from typing import Optional, Type, TypeVar

import httpx
from fastapi import Depends
from httpx import HTTPStatusError
from pydantic import BaseModel, EmailStr, HttpUrl, model_validator

from auth.management import get_management_token
from config import Settings, get_settings
from schemas.biocommons import (
    Auth0UserData,
    BiocommonsAppMetadata,
    BiocommonsPassword,
    BiocommonsRegisterData,
)


class RoleData(BaseModel):
    """
    Data returned by Auth0 API for a role.
    """
    id: str
    name: str
    description: str


class RolesWithTotals(BaseModel):
    """
    Response from Auth0 roles API when include_totals is True.

    :var start: 0-based page number
    :var limit: number of items per page
    :var total: total number of items
    """
    roles: list[RoleData]
    start: int
    limit: int
    total: int


class UsersWithTotals(BaseModel):
    """
    Response from Auth0 users API when include_totals is True.

    :var start: index of the first item
    :var limit: number of items per page
    :var total: total number of items
    """
    users: list[Auth0UserData]
    start: int
    limit: int
    total: int


class RoleUserData(BaseModel):
    """
    Minimal payload returned by the Auth0 role users endpoint.
    """

    user_id: str
    email: EmailStr | None = None
    name: str | None = None
    nickname: str | None = None
    picture: HttpUrl | None = None

    model_config = {"extra": "ignore"}


class RoleUsersWithTotals(BaseModel):
    """
    Response wrapper for role users when include_totals is True.
    """

    users: list[RoleUserData]
    start: int
    limit: int
    total: int


class EmailVerificationResponse(BaseModel):
    status: str
    type: str
    created_at: Optional[str] = None
    id: str


class IdentityData(BaseModel):
    user_id: str
    provider: str


class EmailVerificationRequest(BaseModel):
    user_id: str
    client_id: Optional[str] = None
    identity: Optional[IdentityData] = None
    organization_id: Optional[str] = None


class UpdateUserData(BaseModel):
    """
    Data sent to PATCH /api/v2/users/{user_id} to update user data.
    Only include the fields you want to update.
    """
    _connection_required_fields = ["email", "email_verified", "password", "username"]
    # NOTE: app_metadata will be merged instead of replaced when updating
    app_metadata: Optional[BiocommonsAppMetadata] = None
    blocked: Optional[bool] = None
    email: Optional[EmailStr] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    family_name: Optional[str] = None
    given_name: Optional[str] = None
    nickname: Optional[str] = None
    password: Optional[BiocommonsPassword] = None
    picture: Optional[HttpUrl] = None
    username: Optional[str] = None
    connection: Optional[str] = None

    @model_validator(mode="after")
    def validate_connection_required(self):
        needs_connection = any(getattr(self, field) is not None
                               for field in self._connection_required_fields)
        if needs_connection and self.connection is None:
            raise ValueError("Must provide connection when updating any of the connection-related fields.")
        return self


class Auth0Client:
    """
    Implements the Auth0 management API.
    """

    def __init__(self, domain: str, management_token: str):
        self.domain = domain
        self.management_token = management_token
        self._client = httpx.Client(headers={"Authorization": f"Bearer {management_token}"})

    T = TypeVar('T', bound=BaseModel)

    @staticmethod
    def _convert_list(resp: httpx.Response, model: Type[T]) -> list[T]:
        """Convert a list of data to the given pydantic model."""
        return [model(**item) for item in resp.json()]

    @staticmethod
    def _convert_users(resp: httpx.Response):
        return Auth0Client._convert_list(resp, Auth0UserData)

    @staticmethod
    def _convert_roles(resp: httpx.Response):
        return Auth0Client._convert_list(resp, RoleData)

    def get_users(self, page: Optional[int] = None, per_page: Optional[int] = None, include_totals: Optional[bool] = None,  q: Optional[str] = None) -> list[Auth0UserData] | UsersWithTotals:
        params = {}
        if page is not None:
            # Convert from 1-based pagination to 0-based.
            page = page - 1
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        if include_totals is not None:
            params["include_totals"] = include_totals
        if q is not None:
            params["q"] = q
            params["search_engine"] = "v3"
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url, params=params)
        resp.raise_for_status()
        if include_totals:
            return UsersWithTotals(**resp.json())
        return self._convert_users(resp)

    def get_user(self, user_id: str) -> Auth0UserData:
        url = f"https://{self.domain}/api/v2/users/{user_id}"
        resp = self._client.get(url)
        resp.raise_for_status()
        return Auth0UserData(**resp.json())

    def create_user(self, user: BiocommonsRegisterData) -> Auth0UserData:
        url = f"https://{self.domain}/api/v2/users"
        # Exclude None values to avoid validation errors.
        resp = self._client.post(url, json=user.model_dump(mode="json", exclude_none=True))
        resp.raise_for_status()
        return Auth0UserData(**resp.json())

    def update_user(self, user_id: str, update_data: UpdateUserData) -> Auth0UserData:
        """
        Send a PATCH request to the /users/{user_id} endpoint to update the included fields.
        """
        url = f"https://{self.domain}/api/v2/users/{user_id}"
        # Make sure we exclude None to not update fields with null values.
        data = update_data.model_dump(mode="json", exclude_none=True)
        try:
            resp = self._client.patch(url, json=data)
            resp.raise_for_status()
        except HTTPStatusError as exc:
            raise ValueError(f"Failed to update user {user_id}: {exc.response.json()}") from exc
        return Auth0UserData(**resp.json())

    def check_user_password(self, username: str, password: str, settings: Settings) -> bool:
        """
        Verify a user's password by using the password-realm grant type
        """
        url = f"https://{settings.auth0_domain}/oauth/token"
        data = {
            "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
            "username": username,
            "password": password,
            "audience": f"https://{settings.auth0_domain}/api/v2/",
            "client_id": settings.auth0_management_id,
            "client_secret": settings.auth0_management_secret,
            "realm": settings.auth0_db_connection,
            "scope": "openid",
        }
        # We don't want the management token here so not using self._client
        resp = httpx.post(url, data=data)
        if resp.status_code in {400, 403}:
            error = resp.json().get("error")
            if error == "invalid_grant":
                return False
        resp.raise_for_status()
        return True

    def delete_user_refresh_tokens(self, user_id: str) -> bool:
        """
        Delete all refresh tokens for a user.
        """
        url = f"https://{self.domain}/api/v2/users/{user_id}/refresh-tokens"
        resp = self._client.delete(url)
        resp.raise_for_status()
        return True

    def add_roles_to_user(self, user_id: str, role_id: str | list[str]) -> bool:
        """
        Add one or more roles to a user. The role(s) must already exist.
        """
        url = f"https://{self.domain}/api/v2/users/{user_id}/roles"
        if isinstance(role_id, str):
            role_id = [role_id]
        resp = self._client.post(url, json={"roles": role_id})
        resp.raise_for_status()
        return True

    def remove_roles_from_user(self, user_id: str, role_id: str | list[str]):
        """
        Remove one or more roles from a user.
        """
        url = f"https://{self.domain}/api/v2/users/{user_id}/roles"
        if isinstance(role_id, str):
            role_id = [role_id]
        # httpx.Client.delete() no longer accepts json payloads (0.28+), so use request()
        resp = self._client.request("DELETE", url, json={"roles": role_id})
        resp.raise_for_status()
        return True

    def search_users_by_email(self, email: str) -> list[Auth0UserData]:
        url = f"https://{self.domain}/api/v2/users-by-email"
        resp = self._client.get(url, params={"email": email})
        return self._convert_users(resp)

    def _search_users(self, query: str, page: Optional[int] = None, per_page: Optional[int] = None) -> list[Auth0UserData]:
        params = {"q": query, "search_engine": "v3"}
        if page is not None:
            # Convert from 1-based pagination to 0-based.
            page = page - 1
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        url = f"https://{self.domain}/api/v2/users"
        # TODO: set primary_order=false for faster search?
        #   https://auth0.com/docs/manage-users/user-search/user-search-best-practices
        resp = self._client.get(
            url,
            params={
                "q": query,
                "search_engine": "v3",
                "page": page,
                "per_page": per_page
            }
        )
        return self._convert_users(resp)

    def get_roles(self,
                  name_filter: Optional[str] = None,
                  include_totals: Optional[bool] = None,
                  page: Optional[int] = None,
                  per_page: Optional[int] = None) -> list[RoleData] | RolesWithTotals:
        params = {}
        if name_filter is not None:
            params["name_filter"] = name_filter
        if include_totals is not None:
            params["include_totals"] = include_totals
        if page is not None:
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        url = f"https://{self.domain}/api/v2/roles"
        resp = self._client.get(url, params=params)
        resp.raise_for_status()
        if include_totals:
            return RolesWithTotals(**resp.json())
        else:
            return self._convert_roles(resp)

    def get_all_roles(self) -> list[RoleData]:
        """
        Iterate through pages to get all roles.
        """
        page = 0
        per_page = 100
        roles = []
        while True:
            page_roles: RolesWithTotals = self.get_roles(page=page, per_page=per_page, include_totals=True)
            roles.extend(page_roles.roles)
            if len(roles) >= page_roles.total:
                break
            page += 1
        return roles

    def get_role_by_name(self, name: str) -> RoleData:
        """
        Get a role by name.
        Raises ValueError if not found, or multiple roles are found.
        """
        roles: list[RoleData] = self.get_roles(name_filter=name)
        if len(roles) == 0:
            raise ValueError(f"Role with name {name} not found.")
        elif len(roles) > 1:
            raise ValueError(f"{len(roles)} duplicate roles with name {name} were found.")
        return roles[0]

    def get_role_by_id(self, role_id: str) -> RoleData:
        url = f"https://{self.domain}/api/v2/roles/{role_id}"
        resp = self._client.get(url)
        resp.raise_for_status()
        return RoleData(**resp.json())

    def get_role_users(self, role_id: str, page: Optional[int] = None, per_page: Optional[int] = None, include_totals: Optional[bool] = False) -> list[RoleUserData] | RoleUsersWithTotals:
        url = f"https://{self.domain}/api/v2/roles/{role_id}/users"
        params = {}
        if page is not None:
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        if include_totals is not None:
            params["include_totals"] = include_totals
        resp = self._client.get(url, params=params or None)
        resp.raise_for_status()
        if include_totals:
            return RoleUsersWithTotals(**resp.json())
        return [RoleUserData(**raw) for raw in resp.json()]

    def get_all_role_users(self, role_id: str) -> list[RoleUserData]:
        page = 0
        per_page = 100
        users = []
        while True:
            page_users: RoleUsersWithTotals = self.get_role_users(role_id, page=page, per_page=per_page, include_totals=True)
            users.extend(page_users.users)
            if len(users) >= page_users.total:
                break
            page += 1
        return users

    def create_role(self, name: str, description: str) -> RoleData:
        url = f"https://{self.domain}/api/v2/roles"
        resp = self._client.post(url, json={"name": name, "description": description})
        resp.raise_for_status()
        return RoleData(**resp.json())

    def get_or_create_role(self, name: str, description: str) -> RoleData:
        try:
            role = self.get_role_by_name(name)
        except ValueError:
            role = self.create_role(name, description)
        return role

    def resend_verification_email(self, user_id: str) -> EmailVerificationResponse:
        url = f"https://{self.domain}/api/v2/jobs/verification-email"
        request_body = EmailVerificationRequest(user_id=user_id)
        resp = self._client.post(url, json=request_body.model_dump(mode="json", exclude_none=True))
        resp.raise_for_status()
        return EmailVerificationResponse(**resp.json())

    def trigger_password_change(self, user_email: str, client_id: str, settings: Settings) -> bool:
        # NOTE: Authentication API, not management API
        url = f"https://{self.domain}/dbconnections/change_password"
        resp = self._client.post(
            url,
            json={"email": user_email,
                  "client_id": client_id,
                  "connection": settings.auth0_db_connection,}
        )
        resp.raise_for_status()
        return True


def get_auth0_client(settings: Settings = Depends(get_settings),
                     management_token: str = Depends(get_management_token)):
    return Auth0Client(settings.auth0_domain, management_token=management_token)
