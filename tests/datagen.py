import random

from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory

from auth0.schemas import Auth0UserResponse
from schemas.biocommons import BiocommonsAppMetadata, BiocommonsAuth0User
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.tokens import AccessTokenPayload
from schemas.user import User


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]): ...


class Auth0UserResponseFactory(ModelFactory[Auth0UserResponse]):

    @classmethod
    def user_id(cls) -> str:
        return "auth0|" + ''.join(random.choices('0123456789abcdef', k=24))


class UserFactory(ModelFactory[User]): ...


class Auth0UserFactory(ModelFactory[BiocommonsAuth0User]): ...


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


class AppMetadataFactory(ModelFactory[BiocommonsAppMetadata]): ...
