from typing import Annotated, Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient

from auth.management import get_management_token
from auth.validator import get_current_user
from config import Settings, get_settings
from schemas.biocommons import Auth0UserData
from schemas.user import SessionUser

router = APIRouter(
    prefix="/me", tags=["user"], responses={401: {"description": "Unauthorized"}}
)


async def get_user_data(
    user: SessionUser, settings: Annotated[Settings, Depends(get_settings)]
) -> Auth0UserData:
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
            return Auth0UserData(**response.json())
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


@router.get("/is-admin")
async def check_is_admin(
    user: Annotated[SessionUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Check if the current user has admin privileges."""
    return {"is_admin": user.is_admin(settings)}


@router.get("/all/pending", response_model=Dict[str, List[Any]])
async def get_all_pending(
    user: Annotated[SessionUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Get all pending services and resources."""
    user_data = await get_user_data(user, settings)
    return {
        "pending_services": user_data.pending_services,
        "pending_resources": user_data.pending_resources,
    }
