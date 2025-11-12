from __future__ import annotations

from typing import Any, ClassVar

from sqlalchemy import MetaData, event, select, true
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SASession
from sqlalchemy.orm import class_mapper, with_loader_criteria
from sqlalchemy.sql import expression
from sqlmodel import Field, Session, SQLModel

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


class SoftDeleteModel(BaseModel):
    """
    Base for ORM models that should support soft deletion.
    """
    __abstract__ = True

    is_deleted: bool = Field(
        default=False,
        nullable=False,
        index=True,
        sa_column_kwargs={"server_default": expression.false()},
        description="Soft-delete flag. True means the row is hidden from default queries.",
    )

    def delete(self, session: Session, commit: bool = False) -> "SoftDeleteModel":
        """
        Soft delete this record (mark as deleted without removing from DB).
        """
        self.is_deleted = True
        session.add(self)
        if commit:
            session.commit()
            session.expunge(self)
        return self

    def restore(self, session: Session, commit: bool = False) -> "SoftDeleteModel":
        """
        Restore a previously deleted record.
        """
        self.is_deleted = False
        session.add(self)
        if commit:
            session.commit()
        return self

    @classmethod
    def get_deleted_by_id(cls, session: Session, identity: Any) -> "SoftDeleteModel | None":
        """
        Retrieve a soft-deleted record by primary key.
        """
        identity_dict = cls._coerce_primary_key_map(identity)
        stmt = (
            select(cls)
            .execution_options(include_deleted=True)
            .filter_by(**identity_dict)
            .where(cls.is_deleted.is_(True))
        )
        return session.exec(stmt).scalars().one_or_none()

    @classmethod
    def _coerce_primary_key_map(cls, identity: Any) -> dict[str, Any]:
        """
        Coerce arbitrary primary key identifiers into a ``{column: value}`` mapping.

        ``identity`` may be provided as:
        * a dict where keys match the primary key columns,
        * a single scalar value when the model uses a single-column primary key,
        * a tuple/list containing values for each primary key column in order.

        Any mismatch between the provided structure and the model's primary key
        definition raises ``ValueError`` so downstream queries remain predictable.
        """
        mapper = sa_inspect(cls)
        pk_cols = mapper.primary_key
        if not pk_cols:
            raise ValueError(f"{cls.__name__} does not have a primary key defined.")

        if isinstance(identity, dict):
            return identity

        if len(pk_cols) == 1 and not isinstance(identity, (tuple, list)):
            return {pk_cols[0].key: identity}

        if isinstance(identity, (tuple, list)):
            if len(identity) != len(pk_cols):
                raise ValueError(
                    f"Identity length {len(identity)} does not match primary key length {len(pk_cols)}"
                )
            return {col.key: value for col, value in zip(pk_cols, identity)}

        raise ValueError("Identity must be scalar, tuple/list, or dict matching the primary key.")


def _copy_column_state(source: SoftDeleteModel, target: SoftDeleteModel) -> None:
    mapper = sa_inspect(source.__class__)
    for attr in mapper.column_attrs:
        key = attr.key
        if key == "is_deleted":
            continue
        setattr(target, key, getattr(source, key))


def _identity_dict_from_instance(instance: SoftDeleteModel) -> dict[str, Any] | None:
    mapper = sa_inspect(instance.__class__)
    identity: dict[str, Any] = {}
    for column in mapper.primary_key:
        value = getattr(instance, column.key, None)
        if value is None:
            return None
        identity[column.key] = value
    return identity


def _soft_delete_filter(entity_cls) -> Any:
    try:
        # ensure this is a mapped class and has the column
        class_mapper(entity_cls)
        col = getattr(entity_cls, "is_deleted", None)
        if col is not None:
            return col.is_(False)
    except Exception:
        pass
    return true()


@event.listens_for(SASession, "before_flush")
def _revive_soft_deleted(session: SASession, flush_context, instances) -> None:
    for obj in list(session.new):
        if not isinstance(obj, SoftDeleteModel):
            continue
        identity_dict = _identity_dict_from_instance(obj)
        if identity_dict is None:
            continue
        stmt = (
            select(obj.__class__)
            .execution_options(include_deleted=True)
            .filter_by(**identity_dict)
        )
        existing = session.exec(stmt).scalars().one_or_none()
        if existing is None:
            continue
        if not existing.is_deleted:
            raise IntegrityError(
                "Duplicate primary key for active record",
                params=None,
                orig=None,
            )
        _copy_column_state(obj, existing)
        existing.is_deleted = False
        session.expunge(obj)


@event.listens_for(SASession, "do_orm_execute")
def _filter_soft_deleted(execute_state) -> None:
    if execute_state.is_select and not execute_state.execution_options.get("include_deleted", False):
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                SoftDeleteModel,
                _soft_delete_filter,
                include_aliases=True,
            )
        )


__all__ = ["BaseModel", "SoftDeleteModel"]
