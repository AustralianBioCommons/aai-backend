import httpx
from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone

from auth.config import get_settings
from auth.management import get_management_token
from auth.validator import get_current_user
from schemas.user import User
from schemas.requests import ServiceRequest, ResourceRequest

router = APIRouter()

settings = get_settings()


async def fetch_user_data(user_id: str, token: str):
    url = f"https://{settings.auth0_domain}/api/v2/users/{user_id}"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail="Failed to fetch user data"
            )
        return response.json()


async def update_user_metadata(user_id: str, token: str, metadata: dict):
    """Utility function to update user metadata in Auth0"""
    url = f"https://{settings.auth0_domain}/api/v2/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient() as client:
        response = await client.patch(
            url, headers=headers, json={"app_metadata": metadata}
        )
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail="Failed to update user metadata",
            )
        return response.json()


@router.get("/me/services")
async def get_all_services(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    return {"services": services}


@router.get("/me/services/approved")
async def get_approved_services(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    approved_services = [
        service for service in services if service.get("status") == "approved"
    ]
    return {"approved_services": approved_services}


@router.get("/me/services/pending")
async def get_pending_services(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    pending_services = [
        service for service in services if service.get("status") == "pending"
    ]
    return {"pending_services": pending_services}


@router.get("/me/resources")
async def get_all_resources(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    resources = [
        resource for service in services for resource in service.get("resources", [])
    ]
    return {"resources": resources}


@router.get("/me/resources/approved")
async def get_approved_resources(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
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
async def get_pending_resources(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
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
async def get_all_pending(user: User = Depends(get_current_user)):
    user_id = user.access_token.sub
    token = get_management_token()
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])
    pending_services = [
        service for service in services if service.get("status") == "pending"
    ]
    pending_resources = [
        resource
        for service in services
        for resource in service.get("resources", [])
        if resource.get("status") == "pending"
    ]
    return {
        "pending_services": pending_services,
        "pending_resources": pending_resources,
    }


@router.post("/request/service")
async def request_service(
    service_request: ServiceRequest, user: User = Depends(get_current_user)
):
    """Submit a request for a service"""
    # Validate that the user_id matches the authenticated user
    if user.access_token.sub != service_request.user_id:
        raise HTTPException(
            status_code=403,
            detail="User ID in request does not match authenticated user",
        )

    user_id = user.access_token.sub
    token = get_management_token()

    # Fetch current user data
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])

    # Check if service request already exists
    if any(s.get("id") == service_request.id for s in services):
        raise HTTPException(
            status_code=400,
            detail=f"Service request with ID {service_request.id} already exists",
        )

    # Create new service request
    new_service = {
        "name": service_request.name,
        "id": service_request.id,
        "status": "pending",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "updated_by": user_id,
        "resources": [],
    }

    # Append new service to existing services
    services.append(new_service)

    # Update user metadata
    updated_metadata = user_data.get("app_metadata", {})
    updated_metadata["services"] = services

    await update_user_metadata(user_id, token, updated_metadata)
    return {"message": "Service request submitted successfully", "service": new_service}


@router.post("/request/{service_id}/{resource_id}")
async def request_resource(
    service_id: str,
    resource_id: str,
    resource_request: ResourceRequest,
    user: User = Depends(get_current_user),
):
    """Submit a request for a resource within a service"""
    # Validate that the user_id matches the authenticated user
    if user.access_token.sub != resource_request.user_id:
        raise HTTPException(
            status_code=403,
            detail="User ID in request does not match authenticated user",
        )

    # Validate service_id in path matches request body
    if service_id != resource_request.service_id:
        raise HTTPException(
            status_code=400,
            detail="Service ID in path does not match request body",
        )

    user_id = user.access_token.sub
    token = get_management_token()

    # Fetch current user data
    user_data = await fetch_user_data(user_id, token)
    services = user_data.get("app_metadata", {}).get("services", [])

    # Find the service
    service = next((s for s in services if s.get("id") == service_id), None)

    if not service:
        raise HTTPException(
            status_code=404, detail=f"Service with ID {service_id} not found"
        )

    # Check if service status is approved
    if service.get("status") != "approved":
        raise HTTPException(
            status_code=400,
            detail="Cannot request resources for a service that is not approved",
        )

    # Check if resource request already exists
    if any(r.get("id") == resource_id for r in service.get("resources", [])):
        raise HTTPException(
            status_code=400,
            detail=f"Resource request with ID {resource_id} already exists",
        )

    # Create new resource request
    new_resource = {
        "name": resource_request.name,
        "id": resource_id,
        "status": "pending",
    }

    # Initialize resources list if it doesn't exist
    if "resources" not in service:
        service["resources"] = []

    # Append new resource and update timestamp
    service["resources"].append(new_resource)
    service["last_updated"] = datetime.now(timezone.utc).isoformat()
    service["updated_by"] = user_id

    # Update user metadata
    updated_metadata = user_data.get("app_metadata", {})
    updated_metadata["services"] = services

    await update_user_metadata(user_id, token, updated_metadata)
    return {
        "message": "Resource request submitted successfully",
        "service": service,
        "resource": new_resource,
    }
