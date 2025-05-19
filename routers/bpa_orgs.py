from fastapi import APIRouter, Query, HTTPException
from typing import List
import httpx

router = APIRouter()

CKAN_BASE_URL = "https://data.bioplatforms.com"
CKAN_ORG_LIST_ENDPOINT = "/api/3/action/organization_list"

@router.get("/external/bioplatforms/orgs", response_model=List[str])
async def fetch_bioplatforms_orgs(api_key: str = Query(..., description="CKAN API Key")):
    headers = {"Authorization": api_key}
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{CKAN_BASE_URL}{CKAN_ORG_LIST_ENDPOINT}", headers=headers)
            response.raise_for_status()
            data = response.json()
        if not data.get("success"):
            raise HTTPException(status_code=502, detail="CKAN API call failed")
        return data["result"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))