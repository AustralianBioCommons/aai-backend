__all__ = ["Auth0Client"]

from typing import Optional, Type, TypeVar

import httpx
from fastapi import Depends
from pydantic import BaseModel

from auth.management import get_management_token
from config import Settings, get_settings
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData


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

    :var start: 0-based page number
    :var limit: number of items per page
    :var total: total number of items
    """
    users: list[Auth0UserData]
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

    def get_users(self, page: Optional[int] = None, per_page: Optional[int] = None, include_totals: Optional[bool] = None) -> list[Auth0UserData] | UsersWithTotals:
        params = {}
        if page is not None:
            # Convert from 1-based pagination to 0-based.
            page = page - 1
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        if include_totals is not None:
            params["include_totals"] = include_totals
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url, params=params)
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

    def add_roles_to_user(self, user_id: str, role_id: str | list[str]):
        """
        Add one or more roles to a user. The role(s) must already exist.
        """
        url = f"https://{self.domain}/api/v2/users/{user_id}/roles"
        if isinstance(role_id, str):
            role_id = [role_id]
        resp = self._client.post(url, json={"roles": role_id})
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

    def get_approved_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[Auth0UserData]:
        # TODO: also search for approved resources? (with OR)
        approved_query = 'app_metadata.services.status:"approved"'
        return self._search_users(approved_query, page, per_page)

    def get_pending_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[Auth0UserData]:
        pending_query = 'app_metadata.services.status:"pending"'
        return self._search_users(pending_query, page, per_page)

    def get_revoked_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[Auth0UserData]:
        revoked_query = 'app_metadata.services.status:"revoked"'
        return self._search_users(revoked_query, page, per_page)

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

    def get_role_users(self, role_id: str, page: Optional[int] = None, per_page: Optional[int] = None, include_totals: Optional[bool] = False) -> list[Auth0UserData] | UsersWithTotals:
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
            return UsersWithTotals(**resp.json())
        return self._convert_users(resp)

    def get_all_role_users(self, role_id: str) -> list[Auth0UserData]:
        page = 0
        per_page = 100
        users = []
        while True:
            page_users: UsersWithTotals = self.get_role_users(role_id, page=page, per_page=per_page, include_totals=True)
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


def get_auth0_client(settings: Settings = Depends(get_settings),
                     management_token: str = Depends(get_management_token)):
    return Auth0Client(settings.auth0_domain, management_token=management_token)
