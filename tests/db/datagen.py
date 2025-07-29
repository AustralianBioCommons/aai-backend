from polyfactory.factories.sqlalchemy_factory import SQLAlchemyFactory

from db.models import Auth0Role, BiocommonsGroup, GroupMembership


class Auth0RoleFactory(SQLAlchemyFactory[Auth0Role]):
    __set_relationships__ = True


class BiocommonsGroupFactory(SQLAlchemyFactory[BiocommonsGroup]):
    __set_relationships__ = True


class GroupMembershipFactory(SQLAlchemyFactory[GroupMembership]):
    __set_relationships__ = True
