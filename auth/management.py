from typing import Annotated

import httpx
from cachetools import TTLCache
from fastapi import Depends

from config import Settings, get_settings

TOKEN_CACHE = TTLCache(maxsize=1, ttl=60)


def get_management_token(settings: Annotated[Settings, Depends(get_settings)]):
    global TOKEN_CACHE
    cache_key = (settings.auth0_management_id, settings.auth0_management_secret)
    token = TOKEN_CACHE.get(cache_key)
    if token:
        return token
    # Note: need to call the default auth0 domain here, not the custom
    #  domain
    url = f"https://{settings.auth0_domain}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": settings.auth0_management_id,
        "client_secret": settings.auth0_management_secret,
        "audience": f"https://{settings.auth0_domain}/api/v2/",
    }
    response = httpx.post(url, json=payload)
    response.raise_for_status()
    data = response.json()
    token = data["access_token"]
    # Update cache
    ttl_seconds = int(data.get("expires_in", 60 * 60))
    effective_ttl = max(1, ttl_seconds - 30)
    # Update TOKEN_CACHE based on actual expiry time
    if TOKEN_CACHE.ttl != effective_ttl:
        TOKEN_CACHE = TTLCache(maxsize=1, ttl=effective_ttl)
    TOKEN_CACHE[cache_key] = token
    return token
