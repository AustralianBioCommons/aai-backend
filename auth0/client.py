__all__ = ["Auth0Client"]

import httpx

from auth0.schemas import Auth0UserResponse


class Auth0Client:

    def __init__(self, domain: str):
        self.domain = domain

    def get_users(self, access_token: str) -> list[Auth0UserResponse]:
        url = f"https://{self.domain}/api/v2/users"
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = httpx.get(url, headers=headers)
        return resp.json()
