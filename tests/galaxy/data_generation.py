from polyfactory.factories.pydantic_factory import ModelFactory

from galaxy.schemas import GalaxyUserModel


class GalaxyUserFactory(ModelFactory[GalaxyUserModel]): ...
