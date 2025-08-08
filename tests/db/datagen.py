from polyfactory.factories.sqlalchemy_factory import SQLAlchemyFactory

from db.models import Auth0Role, BiocommonsGroup, BiocommonsUser, GroupMembership
from tests.datagen import random_auth0_id


class BiocommonsUserFactory(SQLAlchemyFactory[BiocommonsUser]):
    __set_relationships__ = False

    @classmethod
    def id(cls) -> str:
        return random_auth0_id()


class Auth0RoleFactory(SQLAlchemyFactory[Auth0Role]):
    __set_relationships__ = True


class BiocommonsGroupFactory(SQLAlchemyFactory[BiocommonsGroup]):
    __set_relationships__ = True


class GroupMembershipFactory(SQLAlchemyFactory[GroupMembership]):
    __set_relationships__ = True
