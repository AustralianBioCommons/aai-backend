import json
import logging

import httpx
import jwt
from cachetools import TTLCache
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import ExpiredSignatureError, InvalidIssuerError, InvalidTokenError

from config import Settings
from schemas.tokens import AccessTokenPayload

logger = logging.getLogger(__name__)

KEY_CACHE = TTLCache(maxsize=10, ttl=30 * 60)


def verify_jwt(token: str, settings: Settings) -> AccessTokenPayload:
    try:
        rsa_key = get_rsa_key(token, settings=settings)
    except InvalidTokenError as e:
        logger.warning("JWT rejected during RSA key lookup: %s", e)
        raise HTTPException(status_code=401, detail="Not authorized")

    if rsa_key is None:
        logger.warning("JWT rejected: no matching signing key found")
        raise HTTPException(
            status_code=401, detail="Not authorized"
        )

    # Issuer may be the Auth0 tenant domain, or the custom domain
    # used for the app. Try both values.
    issuers = [f"https://{settings.auth0_domain}/"]
    if settings.auth0_issuer is not None:
        issuers.append(settings.auth0_issuer)

    payload = None
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
            logger.warning("JWT rejected due to invalid issuer: %s", e)
            continue
        except InvalidTokenError as e:
            logger.warning("JWT rejected during decode: %s", e)
            raise HTTPException(status_code=401, detail="Not authorized")

    if payload is None:
        logger.warning("JWT rejected: issuer validation failed for all configured issuers")
        raise HTTPException(status_code=401, detail="Not authorized")

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
    key_id = unverified_header.get("kid")
    if not key_id:
        raise InvalidTokenError("Token header missing kid")

    for key in jwks["keys"]:
        if key.get("kid") == key_id:
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
