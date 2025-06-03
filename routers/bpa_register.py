from datetime import datetime, timezone
from typing import Any, Dict

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from auth.config import Settings, get_settings
from auth.management import get_management_token
from auth0.client import Auth0Client
from schemas.bpa import BPARegisterData
from schemas.service import Resource, Service

router = APIRouter(prefix="/bpa", tags=["bpa", "registration"])


class BPARegistrationRequest(BaseModel):
    username: str
    fullname: str
    email: EmailStr
    reason: str
    password: str
    organizations: Dict[str, bool]


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
    registration: BPARegistrationRequest,
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Register a new BPA user with selected organization resources."""
    token = get_management_token(settings)
    auth0 = Auth0Client(domain=settings.auth0_domain, management_token=token)

    # Create BPA resources
    bpa_resources = []
    for org_id, is_selected in registration.organizations.items():
        if is_selected:
            if org_id not in settings.organizations:
                raise HTTPException(status_code=400, detail=f"Invalid organization ID: {org_id}")
            bpa_resources.append(
                Resource(id=org_id, name=settings.organizations[org_id], status="pending").model_dump(mode="json")
            )

    bpa_service = Service(
        name="BPA",
        id="bpa",
        status="pending",
        last_updated=datetime.now(timezone.utc),
        updated_by="system",
        resources=bpa_resources,
    )

    user_data = BPARegisterData.from_registration(registration, bpa_service)

    try:
        response = auth0.create_user(user_data.model_dump())
        return {"message": "User registered successfully", "user": response}
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {e.response.json()['message']}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {str(e)}")
