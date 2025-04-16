import os
import requests
from dotenv import load_dotenv

load_dotenv()

def get_management_token():
    url = f'https://{os.getenv("AUTH0_DOMAIN")}/oauth/token'
    payload = {
        'grant_type': 'client_credentials',
        'client_id': os.getenv('AUTH0_MANAGEMENT_ID'),
        'client_secret': os.getenv('AUTH0_MANAGEMENT_SECRET'),
        'audience': f'https://{os.getenv("AUTH0_DOMAIN")}/api/v2/'
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()['access_token']