__all__ = ["Auth0Client"]

import httpx

from auth0.schemas import Auth0UserResponse


class Auth0Client:

    def __init__(self, domain: str, management_token: str):
        self.domain = domain
        self._client = httpx.Client(headers={"Authorization": f"Bearer {management_token}"})

    def get_users(self) -> list[Auth0UserResponse]:
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url)
        return resp.json()

    def get_user(self, user_id: str) -> Auth0UserResponse:
        url = f"https://{self.domain}/api/v2/users/{user_id}"
        resp = self._client.get(url)
        return resp.json()
