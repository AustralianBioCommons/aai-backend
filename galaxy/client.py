from typing import Annotated

from fastapi import Depends
from httpx import Client

from galaxy.config import GalaxySettings, get_galaxy_settings
from galaxy.schemas import GalaxyUserModel


class GalaxyClient:
    """
    Client for making requests to the Galaxy API.
    """

    def __init__(self, galaxy_url: str, api_key: str):
        """
        :param galaxy_url: Base URL of the Galaxy instance.
        :param api_key: API key for a galaxy user.
        """
        self.url = galaxy_url
        self.api_key = api_key
        self.client = Client(base_url=self.url, headers={'x-api-key': self.api_key})

    def username_exists(self, username: str) -> bool:
        """
        Check if a username already exists in Galaxy.
        Note the user search in the current Galaxy API will return
        partial matches, so we need to check the returned users
        for an exact match.
        """
        resp = self.client.get("/api/users", params={"f_name": username})
        returned_users = [GalaxyUserModel(**u) for u in resp.json()]
        for user in returned_users:
            if user.username == username:
                return True
        return False


def get_galaxy_client(settings: Annotated[GalaxySettings, Depends(get_galaxy_settings)]):
    return GalaxyClient(galaxy_url=settings.galaxy_url, api_key=settings.galaxy_api_key)
