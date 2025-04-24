import httpx
from fastapi import APIRouter, Depends, HTTPException

from auth.config import get_settings
from auth.management import get_management_token
from auth.validator import get_current_user


router = APIRouter()
settings = get_settings()


async def fetch_user_data(user_id: str, token: str):
    url = f"https://{settings.auth0_domain}/api/v2/users/{user_id}"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail="Failed to fetch user data"
            )
        return response.json()

@router.get("/me/services")
async def get_all_services(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    return {"services": services}

@router.get("/me/services/approved")
async def get_approved_services(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    approved_services = [service for service in services if service.get("status") == "approved"]
    return {"approved_services": approved_services}

@router.get("/me/services/pending")
async def get_pending_services(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    pending_services = [service for service in services if service.get("status") == "pending"]
    return {"pending_services": pending_services}

@router.get("/me/resources")
async def get_all_resources(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    resources = [
        resource
        for service in services
        for resource in service.get("resources", [])
    ]
    return {"resources": resources}

@router.get("/me/resources/approved")
async def get_approved_resources(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    approved_resources = [
        resource
        for service in services
        for resource in service.get("resources", [])
        if resource.get("status") == "approved"
    ]
    return {"approved_resources": approved_resources}

@router.get("/me/resources/pending")
async def get_pending_resources(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    pending_resources = [
        resource
        for service in services
        for resource in service.get("resources", [])
        if resource.get("status") == "pending"
    ]
    return {"pending_resources": pending_resources}

@router.get("/me/all/pending")
async def get_all_pending(user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    pending_services = [service for service in services if service.get("status") == "pending"]
    pending_resources = [
        resource
        for service in services
        for resource in service.get("resources", [])
        if resource.get("status") == "pending"
    ]
    return {"pending_services": pending_services, "pending_resources": pending_resources}
