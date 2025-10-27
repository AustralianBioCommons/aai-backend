import httpx
from cachetools import TTLCache
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwk, jwt
from jose.exceptions import JWTError

from config import Settings
from schemas.tokens import AccessTokenPayload

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
