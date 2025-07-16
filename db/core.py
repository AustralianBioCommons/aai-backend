from typing import ClassVar

from sqlalchemy import MetaData
from sqlmodel import SQLModel

naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=naming_convention)


class BaseModel(SQLModel):
    """
    Base SQLModel that all our models should inherit from.

    We need to set the naming conventions for database
    constraints in order for our models to work well
    with alembic's automatic migrations, so we're
    setting these in the model metadata
    """
    __abstract__ = True
    metadata: ClassVar[MetaData] = metadata


__all__ = ["BaseModel"]
