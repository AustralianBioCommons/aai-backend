import json

import httpx
import jwt
from cachetools import TTLCache
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import ExpiredSignatureError, InvalidIssuerError, InvalidTokenError

from config import Settings
from schemas.tokens import AccessTokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

KEY_CACHE = TTLCache(maxsize=10, ttl=30 * 60)


def verify_jwt(token: str, settings: Settings) -> AccessTokenPayload:
    try:
        rsa_key = get_rsa_key(token, settings=settings)
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if rsa_key is None:
        raise HTTPException(
            status_code=401, detail="Couldn't find a matching signing key."
        )

    # Issuer may be the Auth0 tenant domain, or the custom domain
    # used for the app. Try both values.
    issuers = [f"https://{settings.auth0_domain}/"]
    if settings.auth0_issuer is not None:
        issuers.append(settings.auth0_issuer)

    payload = None
    last_error: InvalidTokenError | None = None
    for issuer in issuers:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=settings.auth0_algorithms,
                audience=settings.auth0_audience,
                issuer=issuer,
            )
            break
        except InvalidIssuerError as e:
            last_error = e
            continue
        except InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if payload is None:
        error_detail = str(last_error) if last_error else "Invalid issuer"
        raise HTTPException(status_code=401, detail=f"Invalid token: {error_detail}")

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


def get_rsa_key(token: str, settings: Settings, retry_on_failure: bool = True):
    jwks = _fetch_rsa_keys(settings.auth0_domain)
    unverified_header = jwt.get_unverified_header(token)

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return RSAAlgorithm.from_jwk(json.dumps(key))

    # Retry without cache on failure
    if retry_on_failure:
        KEY_CACHE.clear()
        return get_rsa_key(token, settings, retry_on_failure=False)

    return None


def verify_action_token(token: str, settings: Settings) -> dict:
    """
    Verify a JWT passed by an Auth0 action
    """
    # Use Auth0 client secret as decode key
    secret = settings.auth0_management_secret
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={
                "require": ["exp"],
                "verify_exp": True,
            }
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="session_token expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid session_token")
    return payload
