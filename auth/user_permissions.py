from typing import Annotated

from fastapi import Depends, HTTPException
from sqlmodel import Session
from starlette import status

from auth.validator import oauth2_scheme, verify_jwt
from config import Settings, get_settings
from db.models import BiocommonsGroup, BiocommonsUser, Platform
from db.setup import get_db_session
from schemas.biocommons import ServiceIdParam, UserIdParam
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


def user_is_biocommons_admin(
    current_user: Annotated[SessionUser, Depends(get_session_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionUser:
    if current_user.is_biocommons_admin(settings=settings):
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You must be an admin to access this endpoint.",
    )


def has_platform_admin_permission(
    platform_id: str,
    current_user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
) -> bool:
    """
    Check if user has platform admin privileges.
    """
    platform = Platform.get_by_id(platform_id, db_session)
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Platform '{platform_id}' not found",
        )
    return platform.user_is_admin(current_user)


def has_admin_permission_for_user(
    user_id: str,
    admin: Annotated[SessionUser, Depends(user_is_general_admin)],
    db_session: Annotated[Session, Depends(get_db_session)],
) -> bool:
    """
    Check if the current admin has the right to manage the specified user,
    as either a platform admin or a group admin.
    """
    platform_permission = has_platform_admin_permission_for_user(
        user_id=user_id,
        admin=admin,
        db_session=db_session,
    )
    group_permission = has_group_admin_permission_for_user(
        user_id=user_id,
        admin=admin,
        db_session=db_session,
    )
    return platform_permission or group_permission


def has_platform_admin_permission_for_user(
    user_id: str,
    admin: Annotated[SessionUser, Depends(user_is_general_admin)],
    db_session: Annotated[Session, Depends(get_db_session)],
) -> bool:
    """
    Check if the current admin has the right to manage the specified user,
    based on platform admin roles.
    """
    user_in_db = BiocommonsUser.get_by_id(user_id, session=db_session)
    if user_in_db is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )
    admin_platforms = Platform.get_for_admin_roles(
        role_names=admin.access_token.biocommons_roles,
        session=db_session,
    )
    for membership in user_in_db.platform_memberships:
        if membership.platform in admin_platforms:
            return True
    return False


def has_group_admin_permission_for_user(
        user_id: str,
        admin: Annotated[SessionUser, Depends(user_is_general_admin)],
        db_session: Annotated[Session, Depends(get_db_session)],
) -> bool:
    """
    Check if the current admin has the right to manage the specified user,
    based on group admin roles.
    """
    user_in_db = BiocommonsUser.get_by_id(user_id, session=db_session)
    admin_groups = BiocommonsGroup.get_for_admin_roles(
        role_names=admin.access_token.biocommons_roles,
        session=db_session,
    )
    for membership in user_in_db.group_memberships:
        if membership.group in admin_groups:
            return True
    return False


def require_admin_permission_for_user(
        user_id: Annotated[str, UserIdParam],
        admin: Annotated[SessionUser, Depends(user_is_general_admin)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """
    Dependency for checking if the current admin has the right to manage the
    specified user (user_id should be a path parameter).
    Raises an HTTPException if not.
    """
    if not has_admin_permission_for_user(user_id, admin, db_session):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to manage this user.",
        )
    return True


def require_admin_permission_for_platform(
        platform_id: Annotated[str, ServiceIdParam],
        admin: Annotated[SessionUser, Depends(user_is_general_admin)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """
    Dependency for checking if the current admin has the right to manage the
    platform (platform_id should be a path parameter).

    Raises HTTPException if the admin doesn't have permission.
    """
    platform = Platform.get_by_id(platform_id, db_session)
    if not platform.user_is_admin(admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to manage this platform.",
        )


def require_admin_permission_for_group(
        group_id: Annotated[str, ServiceIdParam],
        admin: Annotated[SessionUser, Depends(user_is_general_admin)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """
    Dependency for checking if the current admin has the right to manage the
    group (group_id should be a path parameter).
    """
    group = BiocommonsGroup.get_by_id_or_404(group_id, db_session)
    if not group.user_is_admin(admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to manage this group.",
        )
    return True
