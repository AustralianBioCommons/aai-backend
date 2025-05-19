from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel, EmailStr

from auth.config import Settings, get_settings
from auth.management import get_management_token
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
    registration: BPARegistrationRequest, settings: Settings = Depends(get_settings)
) -> Dict[str, Any]:
    """Register a new BPA user with selected organization resources."""
    url = f"https://{settings.auth0_domain}/api/v2/users"
    token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Create BPA resources for selected organizations
    bpa_resources = []
    valid_org_ids = {org["id"] for org in settings.organizations}

    for org_id, is_selected in registration.organizations.items():
        if not is_selected:
            continue
        if org_id not in valid_org_ids:
            raise HTTPException(
                status_code=400, detail=f"Invalid organization ID: {org_id}"
            )
        org_name = next(
            (org["name"] for org in settings.organizations if org["id"] == org_id),
            None,
        )
        resource = Resource(id=org_id, name=org_name, status="pending").model_dump(
            mode="json"
        )
        bpa_resources.append(resource)

    # Create initial BPA service
    bpa_service = Service(
        name="BPA",
        id="bpa",
        status="pending",
        last_updated=datetime.now(timezone.utc),
        updated_by="system",
        resources=bpa_resources,
    )

    user_data = {
        "email": registration.email,
        "password": registration.password,
        "connection": "Username-Password-Authentication",
        "username": registration.username,
        "name": registration.fullname,
        "nickname": registration.username,
        "email_verified": False,
        "blocked": False,
        "verify_email": True,
        "user_metadata": {"registration_reason": registration.reason},
        "app_metadata": {
            "groups": [],
            "services": [bpa_service.model_dump(mode="json")],
        },
    }

    name_parts = registration.fullname.split(maxsplit=1)
    if len(name_parts) > 1:
        user_data["given_name"] = name_parts[0]
        user_data["family_name"] = name_parts[1]
    else:
        user_data["given_name"] = registration.fullname
        user_data["family_name"] = ""

    try:
        async with AsyncClient() as client:
            response = await client.post(url, headers=headers, json=user_data)

            if response.status_code == 409:
                raise HTTPException(
                    status_code=409,
                    detail="User with this email or username already exists",
                )

            if response.status_code != 201:
                raise HTTPException(
                    status_code=400, detail=f"Failed to create user: {response.text}"
                )

            return {"message": "User registered successfully", "user": response.json()}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )
