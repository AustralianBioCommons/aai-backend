import httpx
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwk, jwt
from jose.exceptions import JWTError

from auth.config import Settings
from schemas.tokens import AccessTokenPayload
from schemas.user import User

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
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=settings.auth0_algorithms,
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/",
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    roles_claim = "biocommons.org.au/roles"
    if roles_claim not in payload:
        raise HTTPException(
            status_code=403, detail=f"Missing required claim: {roles_claim}"
        )

    roles = payload[roles_claim]
    if not isinstance(roles, list) or not any(
        "admin" in role.lower() for role in roles
    ):
        raise HTTPException(
            status_code=403, detail="Access denied: Insufficient permissions"
        )

    return AccessTokenPayload(**payload)


def get_rsa_key(token: str, settings: Settings) -> jwk.RSAKey | None:  # type: ignore
    jwks_url = f"https://{settings.auth0_domain}/.well-known/jwks.json"
    response = httpx.get(jwks_url)
    jwks = response.json()
    unverified_header = jwt.get_unverified_header(token)

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return jwk.construct(key)

    return None


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    access_token = verify_jwt(token)
    return User(access_token=access_token)
