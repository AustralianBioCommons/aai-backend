from typing import List

import httpx

CKAN_BASE_URL = "https://data.bioplatforms.com"
CKAN_ORG_LIST_ENDPOINT = "/api/3/action/organization_list"

async def get_organization_list(api_key: str) -> List[str]:
    headers = {"Authorization": api_key}
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{CKAN_BASE_URL}{CKAN_ORG_LIST_ENDPOINT}", headers=headers)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise ValueError("Failed to fetch organization list.")
        return data["result"]
