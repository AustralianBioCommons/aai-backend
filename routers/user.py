from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth.validator import get_current_user
from schemas.biocommons import BiocommonsAuth0User
from schemas.requests import ResourceRequest, ServiceRequest
from schemas.service import Resource, Service
from schemas.user import User

router = APIRouter(
    prefix="/me", tags=["user"], responses={401: {"description": "Unauthorized"}}
)


async def get_user_data(user: User, settings: Settings) -> BiocommonsAuth0User:
    """Fetch and return user data from Auth0."""
    url = f"https://{settings.auth0_domain}/api/v2/users/{user.access_token.sub}"
    token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {token}"}

    try:
        async with AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=403,
                    detail="Failed to fetch user data",
                )
            return BiocommonsAuth0User(**response.json())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=403, detail=f"Failed to fetch user data: {str(e)}"
        )


async def update_user_metadata(
    user_id: str, token: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Utility function to update user metadata in Auth0."""
    url = f"https://{get_settings().auth0_domain}/api/v2/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        async with AsyncClient() as client:
            response = await client.patch(
                url, headers=headers, json={"app_metadata": metadata}
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=403,
                    detail="Failed to update user metadata",
                )
            return response.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=403,
            detail=f"Failed to update user metadata: {str(e)}",
        )


@router.get("/services", response_model=Dict[str, List[Service]])
async def get_services(user: User = Depends(get_current_user)):
    """Get all services for the authenticated user."""
    user_data = await get_user_data(user)
    return {"services": user_data.app_metadata.services}


@router.get("/services/approved", response_model=Dict[str, List[Service]])
async def get_approved_services(user: User = Depends(get_current_user)):
    """Get approved services for the authenticated user."""
    user_data = await get_user_data(user)
    return {"approved_services": user_data.approved_services}


@router.get("/services/pending", response_model=Dict[str, List[Service]])
async def get_pending_services(user: User = Depends(get_current_user)):
    """Get pending services for the authenticated user."""
    user_data = await get_user_data(user)
    return {"pending_services": user_data.pending_services}


@router.get("/resources", response_model=Dict[str, List[Resource]])
async def get_resources(user: User = Depends(get_current_user)):
    """Get all resources for the authenticated user."""
    user_data = await get_user_data(user)
    return {"resources": user_data.app_metadata.get_all_resources()}


@router.get("/resources/approved", response_model=Dict[str, List[Resource]])
async def get_approved_resources(user: User = Depends(get_current_user)):
    """Get approved resources for the authenticated user."""
    user_data = await get_user_data(user)
    return {"approved_resources": user_data.approved_resources}


@router.get("/resources/pending", response_model=Dict[str, List[Resource]])
async def get_pending_resources(user: User = Depends(get_current_user)):
    """Get pending resources for the authenticated user."""
    user_data = await get_user_data(user)
    return {"pending_resources": user_data.pending_resources}


@router.get("/all/pending", response_model=Dict[str, List[Any]])
async def get_all_pending(user: User = Depends(get_current_user)):
    """Get all pending services and resources."""
    user_data = await get_user_data(user)
    return {
        "pending_services": user_data.pending_services,
        "pending_resources": user_data.pending_resources,
    }


@router.post(
    "/request/service",
    response_model=Dict[str, Any],
    responses={
        400: {"description": "Bad Request - Service already exists"},
        403: {"description": "Forbidden - User ID mismatch"},
        500: {"description": "Internal server error"},
    },
)
async def request_service(
    service_request: ServiceRequest, user: User = Depends(get_current_user),
        settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Submit a request for a service."""
    if user.access_token.sub != service_request.user_id:
        raise HTTPException(
            status_code=403,
            detail="User ID in request does not match authenticated user",
        )

    user_data = await get_user_data(user, settings=settings)

    if any(s.id == service_request.id for s in user_data.app_metadata.services):
        raise HTTPException(
            status_code=400,
            detail=f"Service request with ID {service_request.id} already exists",
        )

    new_service = Service(
        name=service_request.name,
        id=service_request.id,
        status="pending",
        last_updated=datetime.now(timezone.utc),
        updated_by=user.access_token.sub,
        resources=[],
    )

    user_data.app_metadata.services.append(new_service)
    await update_user_metadata(
        user.access_token.sub,
        get_management_token(settings=settings),
        user_data.app_metadata.model_dump(),
    )

    return {
        "message": "Service request submitted successfully",
        "service": new_service.model_dump(mode="json"),
    }


@router.post(
    "/request/{service_id}/{resource_id}",
    response_model=Dict[str, Any],
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Service not found"},
        500: {"description": "Internal server error"},
    },
)
async def request_resource(
    service_id: str,
    resource_id: str,
    resource_request: ResourceRequest,
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Submit a request for a resource within a service."""
    if user.access_token.sub != resource_request.user_id:
        raise HTTPException(
            status_code=403,
            detail="User ID in request does not match authenticated user",
        )

    if service_id != resource_request.service_id:
        raise HTTPException(
            status_code=400, detail="Service ID in path does not match request body"
        )

    user_data = await get_user_data(user)
    service = user_data.app_metadata.get_service_by_id(service_id)

    if not service:
        raise HTTPException(
            status_code=404, detail=f"Service with ID {service_id} not found"
        )

    if service.status != "approved":
        raise HTTPException(
            status_code=400,
            detail="Cannot request resources for a service that is not approved",
        )

    if any(r.id == resource_id for r in service.resources):
        raise HTTPException(
            status_code=400,
            detail=f"Resource request with ID {resource_id} already exists",
        )

    new_resource = Resource(
        name=resource_request.name, id=resource_id, status="pending"
    )

    service.resources.append(new_resource)
    service.last_updated = datetime.now(timezone.utc)
    service.updated_by = user.access_token.sub

    await update_user_metadata(
        user.access_token.sub,
        get_management_token(settings=settings),
        user_data.app_metadata.model_dump(),
    )

    return {
        "message": "Resource request submitted successfully",
        "service": service.model_dump(mode="json"),
        "resource": new_resource.model_dump(mode="json"),
    }
