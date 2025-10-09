from typing import Annotated

import httpx
from cachetools import TTLCache
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwk, jwt
from jose.exceptions import JWTError
from sqlmodel import Session

from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

KEY_CACHE = TTLCache(maxsize=10, ttl=30 * 60)


def verify_jwt(token: str, settings: Settings) -> AccessTokenPayload:
    try:
        rsa_key = get_rsa_key(token, settings=settings)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if rsa_key is None:
        raise HTTPException(
            status_code=401, detail="Couldn't find a matching signing key."
        )

    try:
        # Issuer may be the Auth0 tenant domain, or the custom domain
        #   used for the app. Allow for both
        issuers = [f"https://{settings.auth0_domain}/"]
        if settings.auth0_issuer is not None:
            issuers.append(settings.auth0_issuer)
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=settings.auth0_algorithms,
            audience=settings.auth0_audience,
            issuer=issuers,
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    roles_claim = "https://biocommons.org.au/roles"
    if roles_claim not in payload:
        raise HTTPException(
            status_code=403, detail=f"Missing required claim: {roles_claim}"
        )

    return AccessTokenPayload(**payload)


def _fetch_rsa_keys(auth0_domain: str) -> dict:
    cache_key = f"jwks_{auth0_domain}"
    if cache_key in KEY_CACHE:
        return KEY_CACHE[cache_key]
    jwks_url = f"https://{auth0_domain}/.well-known/jwks.json"
    response = httpx.get(jwks_url)
    keys = response.json()
    KEY_CACHE[cache_key] = keys
    return keys


def get_rsa_key(token: str, settings: Settings, retry_on_failure: bool = True) -> jwk.RSAKey | None:  # type: ignore
    jwks = _fetch_rsa_keys(settings.auth0_domain)
    unverified_header = jwt.get_unverified_header(token)

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return jwk.construct(key)

    # Retry without cache on failure
    if retry_on_failure:
        KEY_CACHE.clear()
        return get_rsa_key(token, settings, retry_on_failure=False)

    return None


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
