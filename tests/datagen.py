import random
import string
from string import ascii_letters, digits

from faker import Faker
from polyfactory.decorators import post_generated
from polyfactory.factories.pydantic_factory import ModelFactory
from pydantic import TypeAdapter, ValidationError

from auth0.client import (
    EmailVerificationResponse,
    RoleUserData,
    RoleUsersWithTotals,
    UsersWithTotals,
)
from auth0.user_info import UserInfo
from schemas.biocommons import (
    ALLOWED_SPECIAL_CHARS,
    Auth0UserData,
    BiocommonsAppMetadata,
    BiocommonsPassword,
    BiocommonsRegisterData,
)
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.sbp import SBPRegistrationRequest
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
        """
        Generate a password compatible with our requirements.

        Since the requirements are a bit complex and might not be satisfied
        by a random choice, generate multiple times until we get a compatible one
        """
        chars = string.ascii_letters + string.digits + ALLOWED_SPECIAL_CHARS
        password_adapter = TypeAdapter(BiocommonsPassword)
        for i in range(20):
            try:
                password = ''.join(random.choices(chars, k=20))
                password_adapter.validate_python(password)
                break
            except ValidationError:
                continue
        else:
            raise ValueError("Failed to generate password")
        return password


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


class UserInfoFactory(ModelFactory[UserInfo]): ...


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

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class SBPRegistrationDataFactory(ModelFactory[SBPRegistrationRequest]):
    """Factory for generating SBP registration test data."""

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class AppMetadataFactory(ModelFactory[BiocommonsAppMetadata]): ...


class BiocommonsRegistrationDataFactory(ModelFactory[BiocommonsRegistrationRequest]):
    """Factory for generating BioCommons registration test data."""

    @classmethod
    def bundle(cls) -> str:
        return "bpa_galaxy"

    password = BiocommonsProviders.biocommons_password
    username = BiocommonsProviders.biocommons_username


class EmailVerificationResponseFactory(ModelFactory[EmailVerificationResponse]): ...


class UsersWithTotalsFactory(ModelFactory[UsersWithTotals]):
    """
    Factory for generating Auth0 users API response.
    It's tricky to define this factory so total/start/limit always match, best
    to define them manually in each test.
    """
    total = 20
    limit = 10
    start = 0

    @post_generated
    @classmethod
    def users(cls, limit: int) -> list[Auth0UserData]:
        return Auth0UserDataFactory.batch(size=limit)


class RoleUserDataFactory(ModelFactory[RoleUserData]):
    @classmethod
    def user_id(cls) -> str:
        return random_auth0_id()


class RoleUsersWithTotalsFactory(ModelFactory[RoleUsersWithTotals]):
    total = 20
    limit = 10
    start = 0

    @post_generated
    @classmethod
    def users(cls, limit: int) -> list[RoleUserData]:
        return RoleUserDataFactory.batch(size=limit)
