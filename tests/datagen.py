import random
from string import ascii_letters, digits

from faker import Faker
from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory

from schemas.biocommons import (
    ALLOWED_SPECIAL_CHARS,
    Auth0UserData,
    BiocommonsAppMetadata,
    BiocommonsRegisterData,
)
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.tokens import AccessTokenPayload
from schemas.user import SessionUser

fake = Faker()


class BiocommonsProviders:
    @staticmethod
    def biocommons_username() -> str:
        # Must pass regex ^[-_a-z0-9]+$ and length 3–128
        return fake.slug()

    @staticmethod
    def biocommons_password() -> str:
        pw = fake.password(
            length=20,
            special_chars=True,
            digits=True,
            upper_case=True,
            lower_case=True,
        )
        pw = "".join(c for c in pw if c.isalnum() or c in ALLOWED_SPECIAL_CHARS)
        return pw


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

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class BiocommonsRegistrationRequestFactory(ModelFactory[BiocommonsRegistrationRequest]):
    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class SessionUserFactory(ModelFactory[SessionUser]): ...


class Auth0UserDataFactory(ModelFactory[Auth0UserData]):
    @classmethod
    def user_id(cls) -> str:
        return random_auth0_id()

    username = BiocommonsProviders.biocommons_username


class GalaxyRegistrationDataFactory(ModelFactory[GalaxyRegistrationData]):
    @post_generated
    @classmethod
    def confirmPassword(cls, password: str) -> str:
        """
        Use the same value as password for confirmPassword.
        """
        return password

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username

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

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class AppMetadataFactory(ModelFactory[BiocommonsAppMetadata]): ...


class BiocommonsRegistrationDataFactory(ModelFactory[BiocommonsRegistrationRequest]):
    """Factory for generating BioCommons registration test data."""

    @classmethod
    def bundle(cls) -> str:
        return "bpa-galaxy"

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username
