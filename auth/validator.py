from dotenv import load_dotenv
from jose import jwt
from jose.exceptions import JWTError
from fastapi import HTTPException
from typing import Dict
import httpx
import os
import json

load_dotenv()

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS = json.loads(os.getenv("AUTH0_ALGORITHMS", '["RS256"]'))

def verify_jwt(token: str) -> Dict:
    try:
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
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
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
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