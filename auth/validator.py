from jose import jwt
from jose.exceptions import JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from typing import Dict
import httpx

from auth.config import get_settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_jwt(token: str) -> Dict:
    settings = get_settings()
    try:
        jwks_url = f"https://{settings.auth0_domain}/.well-known/jwks.json"
        response = httpx.get(jwks_url)
        jwks = response.json()

        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }

        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=settings.auth0_algorithms,
                audience=settings.auth0_audience,
                issuer=f"https://{settings.auth0_domain}/"
            )

            roles_claim = "biocommons.org.au/roles"
            if roles_claim not in payload:
                raise HTTPException(status_code=403, detail=f"Missing required claim: {roles_claim}")

            roles = payload[roles_claim]
            if not isinstance(roles, list) or not any("admin" in role.lower() for role in roles):
                raise HTTPException(status_code=403, detail=f"Access denied: Insufficient permissions")

            return payload

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    raise HTTPException(status_code=401, detail="Unable to verify token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    return verify_jwt(token)