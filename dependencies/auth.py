from typing import Annotated

from fastapi import Depends, HTTPException

from auth.validator import verify_action_token
from config import Settings, get_settings
from schemas.auth0 import Auth0ActionToken


def require_action_token(purpose: str | None = None):
    """
    Dependency that verifies the session_token (from query params),
    and checks for the specified purpose, if present
    """
    def check_action_token(session_token: str, settings: Annotated[Settings, Depends(get_settings)]):
        payload = verify_action_token(session_token, settings=settings)
        if purpose is not None:
            if payload.get("purpose", None) != purpose:
                raise HTTPException(status_code=401, detail="invalid purpose")
        return Auth0ActionToken(**payload)
    return check_action_token
