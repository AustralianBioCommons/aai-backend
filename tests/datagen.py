import random
from string import ascii_letters, digits

from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory

from schemas.biocommons import (
    Auth0UserData,
    BiocommonsAppMetadata,
    BiocommonsRegisterData,
)
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser


def random_auth0_id() -> str:
    return "auth0|" + "".join(random.choices("0123456789abcdef", k=24))


def random_auth0_role_id() -> str:
    return "rol_" + "".join(random.choices(ascii_letters + digits, k=16))


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]):
    __allow_none_optionals__ = False

    @classmethod
    def sub(cls) -> str:
        return random_auth0_id()


class BiocommonsRegisterDataFactory(ModelFactory[BiocommonsRegisterData]):

    @classmethod
    def connection(cls) -> str:
        return "Username-Password-Authentication"


class BiocommonsRegistrationRequestFactory(ModelFactory[BiocommonsRegistrationRequest]): ...


class SessionUserFactory(ModelFactory[SessionUser]): ...


class Auth0UserDataFactory(ModelFactory[Auth0UserData]):
    @classmethod
    def user_id(cls) -> str:
        return random_auth0_id()


class GalaxyRegistrationDataFactory(ModelFactory[GalaxyRegistrationData]):
    @post_generated
    @classmethod
    def confirmPassword(cls, password: str) -> str:
        """
        Use the same value as password for confirmPassword.
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


class BiocommonsRegistrationDataFactory(ModelFactory[BiocommonsRegistrationRequest]):
    """Factory for generating BioCommons registration test data."""

    @classmethod
    def bundle(cls) -> str:
        return "bpa-galaxy"
