from functools import lru_cache
from typing import Annotated

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwk, jwt
from jose.exceptions import JWTError

from config import Settings, get_settings
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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


@lru_cache(maxsize=100)
def _fetch_rsa_keys(auth0_domain: str) -> dict:
    jwks_url = f"https://{auth0_domain}/.well-known/jwks.json"
    response = httpx.get(jwks_url)
    return response.json()


def get_rsa_key(token: str, settings: Settings) -> jwk.RSAKey | None:  # type: ignore
    jwks = _fetch_rsa_keys(settings.auth0_domain)
    unverified_header = jwt.get_unverified_header(token)

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return jwk.construct(key)

    return None


def get_current_user(
    token: str = Depends(oauth2_scheme), settings: Settings = Depends(get_settings)
) -> SessionUser:
    access_token = verify_jwt(token, settings=settings)
    return SessionUser(access_token=access_token)


def user_is_admin(
    current_user: Annotated[SessionUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionUser:
    if not current_user.is_admin(settings=settings):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must be an admin to access this endpoint.",
        )
    return current_user
