from typing import Annotated

from fastapi import Depends, HTTPException
from sqlmodel import Session
from starlette import status

from auth.validator import oauth2_scheme, verify_jwt
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from schemas.user import SessionUser


def get_session_user(
    token: str = Depends(oauth2_scheme), settings: Settings = Depends(get_settings)
) -> SessionUser:
    """
    Get the current user's session data (access token).
    """
    access_token = verify_jwt(token, settings=settings)
    return SessionUser(access_token=access_token)


def get_db_user(
    current_user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)], ) -> BiocommonsUser | None:
    """
    Get the user's DB record.
    """
    user = db_session.get(BiocommonsUser, current_user.access_token.sub)
    return user


def user_is_general_admin(
    current_user: Annotated[SessionUser, Depends(get_session_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
) -> SessionUser:
    """
    Check if user has general admin privileges.
    This can come from:
        * A role listed in settings.admin_roles (for BioCommons admins)
        * A role listed in a group/platform's admin_roles in the DB (for platform sysadmins/project managers)
    """
    if current_user.is_biocommons_admin(settings=settings):
        return current_user
    if db_user is not None:
        if db_user.is_any_platform_admin(access_token=current_user.access_token, db_session=db_session):
            return current_user
        if db_user.is_any_group_admin(access_token=current_user.access_token, db_session=db_session):
            return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You must be an admin to access this endpoint.",
    )
