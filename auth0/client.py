__all__ = ["Auth0Client"]

import httpx

from auth0.schemas import Auth0UserResponse


class Auth0Client:

    def __init__(self, domain: str, management_token: str):
        self.domain = domain
        self.management_token = management_token
        self._client = httpx.Client(headers={"Authorization": f"Bearer {management_token}"})

    @staticmethod
    def _convert_users(resp: httpx.Response):
        """Convert a list of Auth0UserResponse objects from a response."""
        return [Auth0UserResponse(**user) for user in resp.json()]

    def get_users(self) -> list[Auth0UserResponse]:
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url)
        return self._convert_users(resp)

    def get_user(self, user_id: str) -> Auth0UserResponse:
        url = f"https://{self.domain}/api/v2/users/{user_id}"
        resp = self._client.get(url)
        return Auth0UserResponse(**resp.json())

    def get_approved_users(self) -> list[Auth0UserResponse]:
        # TODO: also search for approved resources? (with OR)
        approved_query = 'app_metadata.services.status:"approved"'
        url = f"https://{self.domain}/api/v2/users"
        # TODO: set primary_order=false for faster search?
        #   https://auth0.com/docs/manage-users/user-search/user-search-best-practices
        resp = self._client.get(url, params={"q": approved_query, "search_engine": "v3"})
        return self._convert_users(resp)

    def get_pending_users(self) -> list[Auth0UserResponse]:
        pending_query = 'app_metadata.services.status:"pending"'
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url, params={"q": pending_query, "search_engine": "v3"})
        return [Auth0UserResponse(**user) for user in resp.json()]
