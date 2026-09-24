from enum import StrEnum
from logging import getLogger
from typing import Annotated

from fastapi import HTTPException
from fastapi.params import Depends
from starlette import status

from auth.user_permissions import get_db_user
from db.models import BiocommonsUser

logger = getLogger("uvicorn.error")


class AccountActions(StrEnum):
    CHANGE_EMAIL = 'change_email'
    CHANGE_PASSWORD = 'change_password'
    CHANGE_USERNAME = 'change_username'
    CHANGE_NAME = 'change_name'


def account_action_allowed(action: AccountActions, user: BiocommonsUser) -> bool:
    """
    Check if a user can perform an action, based on account type.
    """
    # All actions currently allowed for Auth0 users
    if user.account_type == "auth0":
        return True
    elif user.account_type == "aaf":
        match action:
            case AccountActions.CHANGE_EMAIL:
                return False
            case AccountActions.CHANGE_USERNAME:
                # TODO: username change code currently assumes the
                #   Auth0 DB connection, so disable for AAF for now
                return False
            case AccountActions.CHANGE_PASSWORD:
                return False
            case AccountActions.CHANGE_NAME:
                # TODO: Assuming we allow users to set their name and don't
                #   auto-update from AAF
                return True
    logger.warning(f"Unexpected account type ({user.account_type})/action ({action}. Disallowing by default.")
    return False


def require_account_permission(action: AccountActions) -> Depends:
    """
    FastAPI dependency that checks if the user can perform an action, based on account type.
    """
    def require_account_action(
        user: Annotated[BiocommonsUser | None, Depends(get_db_user)],
    ) -> BiocommonsUser:
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User account not found.",
            )
        if not account_action_allowed(action, user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return user

    return Depends(require_account_action)
