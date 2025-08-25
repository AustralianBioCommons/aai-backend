__all__ = ["CKANClient", "get_ckan_client"]

from typing import Optional

import httpx
from fastapi import Depends
from pydantic import BaseModel

from config import Settings, get_settings


class OrgOut(BaseModel):
    """
    Minimal org payload for the portal dropdown.
    """
    id: str
    name: str
    title: str


class CKANClient:
    """
    Tiny client for CKAN Action API calls used by aai-backend.
    """

    ACTION_AUTOREGISTER_ORGS = "/api/3/action/ytp_request_autoregister_organization_list"

    def __init__(self, base_url: str, api_key: Optional[str], timeout_s: float, verify_ssl: bool):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        headers = {}
        if api_key:
            # CKAN expects the API key in the Authorization header (no Bearer prefix)
            headers["Authorization"] = api_key
        # Mirror the style of Auth0Client: keep a single sync client instance
        self._client = httpx.Client(headers=headers, timeout=timeout_s, verify=verify_ssl)

    def get_autoregister_organizations(self) -> list[OrgOut]:
        """
        Calls the CKAN action exposed by ckanext-ytp-request to fetch the
        list of orgs eligible for auto-registration.
        """
        url = f"{self.base_url}{self.ACTION_AUTOREGISTER_ORGS}"
        resp = self._client.post(url, json={})
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("success"):
            # CKAN Action API returns {"success": false, "error": {...}} on failure
            raise ValueError("CKAN action reported success=false")
        result = payload.get("result") or []
        return [OrgOut(**item) for item in result]


def get_ckan_client(settings: Settings = Depends(get_settings)) -> CKANClient:
    """
    FastAPI dependency that wires CKAN config from Settings.
    """
    return CKANClient(
        base_url=settings.ckan_base_url,
        api_key=settings.ckan_api_key,
        timeout_s=settings.ckan_timeout_s,
        verify_ssl=settings.ckan_verify_ssl,
    )
