from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory

from routers.bpa_register import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.service import Auth0User
from schemas.tokens import AccessTokenPayload
from schemas.user import User


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]): ...


class UserFactory(ModelFactory[User]): ...


class Auth0UserFactory(ModelFactory[Auth0User]): ...


class GalaxyRegistrationDataFactory(ModelFactory[GalaxyRegistrationData]):

    @post_generated
    @classmethod
    def password_confirmation(cls, password: str) -> str:
        """
        Use the same value as password for password_confirmation.
        """
        return password


class BPARegistrationDataFactory(ModelFactory[BPARegistrationRequest]):
    """Factory for generating BPA registration test data."""

    @classmethod
    def get_default_organizations(cls) -> dict:
        """Default organization selection."""
        return {
            "bpa-bioinformatics-workshop": True,
            "cipps": False,
            "ausarg": True,
        }
