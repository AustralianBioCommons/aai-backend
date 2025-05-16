import httpx

from .config import Settings


def get_management_token(settings: Settings):
    url = f"https://{settings.auth0_domain}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": settings.auth0_management_id,
        "client_secret": settings.auth0_management_secret,
        "audience": f"https://{settings.auth0_domain}/api/v2/",
    }
    response = httpx.post(url, json=payload)
    response.raise_for_status()
    return response.json()["access_token"]
