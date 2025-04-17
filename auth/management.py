import os
import requests
from .config import get_settings


def get_management_token():
    settings = get_settings()
    url = f'https://{os.getenv("AUTH0_DOMAIN")}/oauth/token'
    payload = {
        'grant_type': 'client_credentials',
        'client_id': settings.auth0_management_id,
        'client_secret': settings.auth0_management_secret,
        'audience': f'https://{settings.auth0_domain}/api/v2/'
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()['access_token']