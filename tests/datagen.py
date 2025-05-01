from polyfactory.factories.pydantic_factory import ModelFactory

from schemas.tokens import AccessTokenPayload
from schemas.user import User


class AccessTokenPayloadFactory(ModelFactory[AccessTokenPayload]):
    ...


class UserFactory(ModelFactory[User]):
    ...