from polyfactory.factories.pydantic_factory import ModelFactory

from schemas.service import Auth0User
from schemas.tokens import AccessTokenPayload
from schemas.user import User


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]): ...


class UserFactory(ModelFactory[User]): ...


class Auth0UserFactory(ModelFactory[Auth0User]): ...
