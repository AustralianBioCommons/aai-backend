import random

from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory

from schemas.biocommons import BiocommonsAppMetadata, BiocommonsAuth0User
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser


def random_auth0_id() -> str:
    return "auth0|" + ''.join(random.choices('0123456789abcdef', k=24))


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]):
    __allow_none_optionals__ = False


class SessionUserFactory(ModelFactory[SessionUser]): ...


class BiocommonsAuth0UserFactory(ModelFactory[BiocommonsAuth0User]):

    @classmethod
    def user_id(cls) -> str:
        return random_auth0_id()


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
