__all__ = ["Auth0Client"]

from typing import Optional

import httpx

from schemas.biocommons import BiocommonsAuth0User


class Auth0Client:

    def __init__(self, domain: str, management_token: str):
        self.domain = domain
        self.management_token = management_token
        self._client = httpx.Client(headers={"Authorization": f"Bearer {management_token}"})

    @staticmethod
    def _convert_users(resp: httpx.Response):
        """Convert a list of Auth0UserResponse objects from a response."""
        return [BiocommonsAuth0User(**user) for user in resp.json()]

    def get_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[BiocommonsAuth0User]:
        params = {}
        if page is not None:
            # Convert from 1-based pagination to 0-based.
            page = page - 1
            params["page"] = page
        if per_page is not None:
            params["per_page"] = per_page
        url = f"https://{self.domain}/api/v2/users"
        resp = self._client.get(url, params=params)
        return self._convert_users(resp)

    def get_user(self, user_id: str) -> BiocommonsAuth0User:
        url = f"https://{self.domain}/api/v2/users/{user_id}"
        resp = self._client.get(url)
        return BiocommonsAuth0User(**resp.json())

    def search_users_by_email(self, email: str) -> list[BiocommonsAuth0User]:
        url = f"https://{self.domain}/api/v2/users-by-email"
        resp = self._client.get(url, params={"email": email})
        return self._convert_users(resp)

    def _search_users(self, query: str, page: Optional[int] = None, per_page: Optional[int] = None) -> list[BiocommonsAuth0User]:
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

    def get_approved_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[BiocommonsAuth0User]:
        # TODO: also search for approved resources? (with OR)
        approved_query = 'app_metadata.services.status:"approved"'
        return self._search_users(approved_query, page, per_page)

    def get_pending_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[BiocommonsAuth0User]:
        pending_query = 'app_metadata.services.status:"pending"'
        return self._search_users(pending_query, page, per_page)

    def get_revoked_users(self, page: Optional[int] = None, per_page: Optional[int] = None) -> list[BiocommonsAuth0User]:
        revoked_query = 'app_metadata.services.status:"revoked"'
        return self._search_users(revoked_query, page, per_page)
