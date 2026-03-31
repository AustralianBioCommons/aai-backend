import asyncio
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

logger = logging.getLogger("uvicorn.error")

KEY_CACHE_TIMEOUT = 6 * 60 * 60  # 6 hours
KEY_CACHE = TTLCache(maxsize=10, ttl=KEY_CACHE_TIMEOUT)
KEY_CACHE_LOCK = asyncio.Lock()


async def verify_jwt(token: str, settings: Settings) -> AccessTokenPayload:
    try:
        rsa_key = await get_rsa_key(token, settings=settings)
    except InvalidTokenError as e:
        logger.warning(f"JWT rejected during RSA key lookup: {e}")
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
    last_issuer_error = None
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
            last_issuer_error = e
            continue
        except InvalidTokenError as e:
            logger.warning(f"JWT rejected during decode: {e}")
            raise HTTPException(status_code=401, detail="Not authorized")

    if payload is None:
        logger.warning(
            f"JWT rejected: issuer validation failed for all configured issuers: {last_issuer_error}"
        )
        raise HTTPException(status_code=401, detail="Not authorized")

    roles_claim = "https://biocommons.org.au/roles"
    if roles_claim not in payload:
        raise HTTPException(
            status_code=403, detail=f"Missing required claim: {roles_claim}"
        )

    return AccessTokenPayload(**payload)


async def _fetch_rsa_keys(auth0_domain: str) -> dict:
    """
    Try to get cached keys if possible, otherwise
    refresh from Auth0
    """
    cache_key = f"jwks_{auth0_domain}"
    if cache_key in KEY_CACHE:
        return KEY_CACHE[cache_key]

    # Lock so we don't do the lookup multiple times
    #   if multiple requests come in while cache is expired
    async with KEY_CACHE_LOCK:
        # Check again: another request may have refreshed while
        #   this was waiting
        cached = KEY_CACHE.get(cache_key, None)
        if cached is not None:
            return cached

        try:
            metadata_url = f"https://{auth0_domain}/.well-known/openid-configuration"
            async with httpx.AsyncClient() as client:
                metadata_response = await client.get(metadata_url)
                metadata_response.raise_for_status()
                metadata = metadata_response.json()

                jwks_url = metadata["jwks_uri"]
                response = await client.get(jwks_url)
                response.raise_for_status()
                keys = response.json()
        except KeyError as exc:
            logger.error(f"OIDC metadata from {metadata_url} did not include jwks_uri")
            raise InvalidTokenError("Failed to fetch JWKS") from exc
        except (httpx.HTTPError, ValueError) as exc:
            logger.error(
                f"Failed to fetch OIDC metadata or JWKS for domain {auth0_domain}: {exc}"
            )
            # Do not cache on error
            raise InvalidTokenError("Failed to fetch JWKS") from exc
        KEY_CACHE[cache_key] = keys
        return keys


async def get_rsa_key(token: str, settings: Settings, retry_on_failure: bool = True):
    jwks = await _fetch_rsa_keys(settings.auth0_domain)
    unverified_header = jwt.get_unverified_header(token)
    key_id = unverified_header.get("kid")
    if not key_id:
        raise InvalidTokenError("Token header missing kid")

    for key in jwks["keys"]:
        if key.get("kid") == key_id:
            return RSAAlgorithm.from_jwk(json.dumps(key))

    # Retry without cache on failure (but only once, to prevent infinite retry)
    if retry_on_failure:
        async with KEY_CACHE_LOCK:
            KEY_CACHE.clear()
        return await get_rsa_key(token, settings, retry_on_failure=False)

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
