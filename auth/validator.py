from typing import Dict

import httpx
from fastapi import HTTPException
from jose import jwt, jwk
from jose.exceptions import JWTError
from pydantic import ValidationError

from auth.config import get_settings
from schemas.tokens import AccessTokenPayload


def get_rsa_key(token: str) -> jwk.RSAKey | None:
    settings = get_settings()
    jwks_url = f"https://{settings.auth0_domain}/.well-known/jwks.json"
    response = httpx.get(jwks_url)
    jwks = response.json()
    unverified_header = jwt.get_unverified_header(token)

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return jwk.RSAKey(**key)
    return None


def verify_jwt(token: str) -> AccessTokenPayload:
    settings = get_settings()
    try:
        rsa_key = get_rsa_key(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    if rsa_key is None:
        raise HTTPException(status_code=401, detail="Couldn't find a matching signing key.")

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=settings.auth0_algorithms,
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/"
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    roles_claim = "biocommons.org.au/roles"
    if roles_claim not in payload:
        raise HTTPException(status_code=403, detail=f"Missing required claim: {roles_claim}")

    roles = payload[roles_claim]
    if not isinstance(roles, list) or not any("admin" in role.lower() for role in roles):
        raise HTTPException(status_code=403, detail=f"Access denied: Insufficient permissions")

    return AccessTokenPayload(**payload)
