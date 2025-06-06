from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient

from auth.config import Settings, get_settings
from auth.management import get_management_token
from schemas.biocommons import BiocommonsRegisterData
from schemas.bpa import BPARegistrationRequest
from schemas.service import Resource, Service

router = APIRouter(prefix="/bpa", tags=["bpa", "registration"])


@router.post(
    "/register",
    response_model=Dict[str, Any],
    responses={
        400: {"description": "Bad Request - Validation error"},
        409: {"description": "Conflict - User already exists"},
        500: {"description": "Internal server error"},
    },
)
async def register_bpa_user(
    registration: BPARegistrationRequest, settings: Settings = Depends(get_settings)
) -> Dict[str, Any]:
    """Register a new BPA user with selected organization resources."""
    url = f"https://{settings.auth0_domain}/api/v2/users"
    token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Create BPA resources for selected organizations
    bpa_resources = []
    for org_id, is_selected in registration.organizations.items():
        if not is_selected:
            continue
        if org_id not in settings.organizations:
            raise HTTPException(
                status_code=400, detail=f"Invalid organization ID: {org_id}"
            )
        resource = Resource(
            id=org_id, name=settings.organizations[org_id], status="pending"
        ).model_dump(mode="json")
        bpa_resources.append(resource)

    # Create BPA service
    bpa_service = Service(
        name="BPA",
        id="bpa",
        status="pending",
        last_updated=datetime.now(timezone.utc),
        updated_by="system",
        resources=bpa_resources,
    )

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_bpa_registration(
        registration=registration, bpa_service=bpa_service
    )

    try:
        async with AsyncClient() as client:
            response = await client.post(
                url, headers=headers, json=user_data.model_dump(mode="json")
            )
            if response.status_code != 201:
                raise HTTPException(
                    status_code=400,
                    detail=f"Registration failed: {response.json()['message']}",
                )
            return {"message": "User registered successfully", "user": response.json()}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )
