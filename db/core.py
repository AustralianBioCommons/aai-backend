from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, ClassVar

import sqlalchemy as sa
from sqlalchemy import MetaData, event, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SASession
from sqlalchemy.orm import with_loader_criteria
from sqlalchemy.sql import expression
from sqlmodel import DateTime, Field, Session, SQLModel
from sqlmodel import Enum as DbEnum

from db.types import AuditActionEnum

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


class AuditLogModel(BaseModel):
    """
    Base for tables that store audit log entries.
    """
    __abstract__ = True

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    action: AuditActionEnum = Field(
        sa_type=DbEnum(AuditActionEnum, name="AuditActionEnum"),
        description="Type of change that produced this audit record.",
    )
    acted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_type=DateTime(timezone=True),
        description="Timestamp when the audit record was produced.",
    )


class AuditedModel(BaseModel):
    """
    Base for ORM models that should write audit log entries on create/update/delete.
    """
    __abstract__ = True

    # Concrete subclasses must set this to the associated audit log SQLModel.
    __audit_model__: ClassVar[type[AuditLogModel] | None] = None
    # Map of attribute name on the subject model to the attribute name on the audit log.
    __audit_field_map__: ClassVar[dict[str, str]] = {}
    # Attributes to skip when copying state into the audit log.
    __audit_exclude_columns__: ClassVar[set[str]] = set()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.__abstract__:
            return
        audit_model = getattr(cls, "__audit_model__", None)
        if audit_model is None:
            raise TypeError(f"{cls.__name__} must define __audit_model__ to enable auditing.")
        try:
            mapper = sa.orm.class_mapper(cls)
        except sa.orm.exc.UnmappedClassError:
            mapper = None
        else:
            _configure_audited_model(mapper, cls)
        sa.orm.configure_mappers()

    @classmethod
    def _audit_after_insert(cls, mapper, connection, target) -> None:
        cls._emit_audit(connection, target, AuditActionEnum.CREATED)

    @classmethod
    def _audit_after_update(cls, mapper, connection, target) -> None:
        state = sa_inspect(target)
        has_changes = any(
            state.attrs[column.key].history.has_changes()
            for column in mapper.column_attrs
            if column.key in state.attrs
        )
        if has_changes:
            cls._emit_audit(connection, target, AuditActionEnum.UPDATED)

    @classmethod
    def _audit_before_delete(cls, mapper, connection, target) -> None:
        cls._emit_audit(connection, target, AuditActionEnum.DELETED)

    @classmethod
    def _emit_audit(cls, connection, target, action: AuditActionEnum) -> None:
        audit_model = cls.__audit_model__
        if audit_model is None:
            return
        payload = cls._collect_audit_payload(target, audit_model)
        if payload is None:
            return
        payload["action"] = action
        payload.setdefault("acted_at", datetime.now(timezone.utc))
        insert_stmt = audit_model.__table__.insert().values(**payload)
        connection.execute(insert_stmt)

    @classmethod
    def _collect_audit_payload(
        cls,
        target: "AuditedModel",
        audit_model: type[AuditLogModel],
    ) -> dict[str, Any]:
        mapper = sa_inspect(target.__class__)
        field_map = cls.__audit_field_map__
        exclude = cls.__audit_exclude_columns__
        audit_columns = set(audit_model.__table__.columns.keys())
        payload: dict[str, Any] = {}
        for column in mapper.columns:
            key = column.key
            if key in exclude:
                continue
            dest_key = field_map.get(key, key)
            if dest_key is None or dest_key not in audit_columns:
                continue
            payload[dest_key] = getattr(target, key)
        return payload or None


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


def _soft_delete_filter(cls) -> Any:
    mapper = sa_inspect(cls, raiseerr=False)
    if mapper is None:
        return expression.true()
    column = mapper.c.is_deleted
    return column.is_(False)


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
                lambda cls: _soft_delete_filter(cls),
                include_aliases=True,
            )
        )


__all__ = ["BaseModel", "SoftDeleteModel", "AuditLogModel", "AuditedModel"]


def _get_bind_connection(session: SASession, obj: AuditedModel):
    return session.connection()


@event.listens_for(SASession, "before_flush")
def _audit_deleted(session: SASession, flush_context, instances) -> None:
    for obj in list(session.deleted):
        if not isinstance(obj, AuditedModel):
            continue
        connection = _get_bind_connection(session, obj)
        obj.__class__._emit_audit(connection, obj, AuditActionEnum.DELETED)


@event.listens_for(SASession, "after_flush")
def _audit_new_and_dirty(session: SASession, flush_context) -> None:
    new_objs = [obj for obj in session.new if isinstance(obj, AuditedModel)]
    new_ids = {id(obj) for obj in new_objs}
    dirty_objs = [
        obj for obj in session.dirty
        if isinstance(obj, AuditedModel) and id(obj) not in new_ids
    ]

    for obj in new_objs:
        connection = _get_bind_connection(session, obj)
        obj.__class__._emit_audit(connection, obj, AuditActionEnum.CREATED)

    for obj in dirty_objs:
        state = sa_inspect(obj)
        has_changes = any(
            attr.history.has_changes() for attr in state.attrs
        )
        if not has_changes:
            continue
        connection = _get_bind_connection(session, obj)
        obj.__class__._emit_audit(connection, obj, AuditActionEnum.UPDATED)


@event.listens_for(sa.orm.Mapper, "mapper_configured")
def _configure_audited_model(mapper, cls) -> None:
    if not isinstance(cls, type) or not issubclass(cls, AuditedModel):
        return
    if cls.__abstract__:
        return
    audit_model = getattr(cls, "__audit_model__", None)
    if audit_model is None:
        return
