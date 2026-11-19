from typing import Annotated

from fastapi import Depends, HTTPException
from pydantic import ValidationError

from auth.validator import verify_action_token
from config import Settings, get_settings
from schemas.auth0 import Auth0ActionToken


def require_action_token(
    purpose: str | None = None,
    token_model: type[Auth0ActionToken] = Auth0ActionToken,
):
    """
    Dependency that verifies the session_token (from query params),
    and checks for the specified purpose, if present
    """
    def check_action_token(session_token: str, settings: Annotated[Settings, Depends(get_settings)]):
        payload = verify_action_token(session_token, settings=settings)
        if purpose is not None:
            if payload.get("purpose", None) != purpose:
                raise HTTPException(status_code=401, detail="invalid purpose")
        try:
            return token_model(**payload)
        except ValidationError as exc:
            raise HTTPException(status_code=401, detail="invalid action token payload") from exc
    return check_action_token
