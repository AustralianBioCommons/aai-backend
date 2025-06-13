import httpx
import pytest

from galaxy.client import GalaxyClient
from tests.galaxy.data_generation import GalaxyUserFactory


@pytest.fixture
def galaxy_client():
    return GalaxyClient(galaxy_url="https://galaxy.example.com",
                        api_key="dummy-key")


def test_username_exists(galaxy_client, respx_mock):
    user1 = GalaxyUserFactory.build(username="user1")
    user2 = GalaxyUserFactory.build(username="user2")
    respx_mock.get("https://galaxy.example.com/api/users").mock(
        return_value=httpx.Response(
            200,
            json=[user1.model_dump(mode="json"),
                  user2.model_dump(mode="json")]
        )
    )
    assert galaxy_client.username_exists("user1")
    assert not galaxy_client.username_exists("other_user")
