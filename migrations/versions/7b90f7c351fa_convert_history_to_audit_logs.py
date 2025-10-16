"""convert history tables to audit logs

Revision ID: 7b90f7c351fa
Revises: 6c9d1e8540be
Create Date: 2025-10-21 10:00:00.000000

"""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7b90f7c351fa"
down_revision: Union[str, None] = "6c9d1e8540be"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _normalize_enum(value: str | None) -> str | None:
    if value is None:
        return None
    return value


def upgrade() -> None:
    bind = op.get_bind()

    audit_action_enum = sa.Enum(
        "created",
        "updated",
        "deleted",
        name="AuditActionEnum",
    )
    audit_action_enum.create(bind, checkfirst=True)

    op.create_table(
        "platform_membership_audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("membership_id", sa.Uuid(), nullable=True),
        sa.Column(
            "platform_id",
            sa.Enum(name="PlatformEnum", create_type=False),
            nullable=False,
        ),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column(
            "approval_status",
            sa.Enum(name="ApprovalStatusEnum", create_type=False),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("acted_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by_id", sa.String(), nullable=True),
        sa.Column("revocation_reason", sa.String(length=1024), nullable=True),
        sa.Column(
            "action",
            sa.Enum("created", "updated", "deleted", name="AuditActionEnum"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["membership_id"],
            ["platformmembership.id"],
            ondelete="SET NULL",
            name="fk_platform_membership_audit_log_membership_id_platformmembership",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_id"],
            ["biocommons_user.id"],
            name="fk_platform_membership_audit_log_updated_by_id_biocommons_user",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["biocommons_user.id"],
            name="fk_platform_membership_audit_log_user_id_biocommons_user",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_platform_membership_audit_log"),
    )
    op.create_index(
        op.f("ix_platform_membership_audit_log_membership_id"),
        "platform_membership_audit_log",
        ["membership_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_platform_membership_audit_log_platform_id"),
        "platform_membership_audit_log",
        ["platform_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_platform_membership_audit_log_user_id"),
        "platform_membership_audit_log",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "group_membership_audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("membership_id", sa.Uuid(), nullable=True),
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column(
            "approval_status",
            sa.Enum(name="ApprovalStatusEnum", create_type=False),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("acted_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by_id", sa.String(), nullable=True),
        sa.Column("revocation_reason", sa.String(length=1024), nullable=True),
        sa.Column(
            "action",
            sa.Enum("created", "updated", "deleted", name="AuditActionEnum"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["biocommonsgroup.group_id"],
            name="fk_group_membership_audit_log_group_id_biocommonsgroup",
        ),
        sa.ForeignKeyConstraint(
            ["membership_id"],
            ["groupmembership.id"],
            ondelete="SET NULL",
            name="fk_group_membership_audit_log_membership_id_groupmembership",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_id"],
            ["biocommons_user.id"],
            name="fk_group_membership_audit_log_updated_by_id_biocommons_user",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["biocommons_user.id"],
            name="fk_group_membership_audit_log_user_id_biocommons_user",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_group_membership_audit_log"),
    )
    op.create_index(
        op.f("ix_group_membership_audit_log_membership_id"),
        "group_membership_audit_log",
        ["membership_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_group_membership_audit_log_group_id"),
        "group_membership_audit_log",
        ["group_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_group_membership_audit_log_user_id"),
        "group_membership_audit_log",
        ["user_id"],
        unique=False,
    )

    platform_audit_table = sa.table(
        "platform_membership_audit_log",
        sa.column("id", sa.Uuid()),
        sa.column("membership_id", sa.Uuid()),
        sa.column("platform_id", sa.String()),
        sa.column("user_id", sa.String()),
        sa.column("approval_status", sa.String()),
        sa.column("acted_at", sa.DateTime()),
        sa.column("updated_by_id", sa.String()),
        sa.column("revocation_reason", sa.String()),
        sa.column("action", sa.String()),
    )

    group_audit_table = sa.table(
        "group_membership_audit_log",
        sa.column("id", sa.Uuid()),
        sa.column("membership_id", sa.Uuid()),
        sa.column("group_id", sa.String()),
        sa.column("user_id", sa.String()),
        sa.column("approval_status", sa.String()),
        sa.column("acted_at", sa.DateTime()),
        sa.column("updated_by_id", sa.String()),
        sa.column("revocation_reason", sa.String()),
        sa.column("action", sa.String()),
    )

    _migrate_platform_history(bind, platform_audit_table)
    _migrate_group_history(bind, group_audit_table)

    op.drop_index(op.f("ix_platformmembership_is_deleted"), table_name="platformmembership")
    op.drop_column("platformmembership", "is_deleted")
    op.drop_index(op.f("ix_groupmembership_is_deleted"), table_name="groupmembership")
    op.drop_column("groupmembership", "is_deleted")

    op.drop_table("platformmembershiphistory")
    op.drop_table("groupmembershiphistory")


def _migrate_platform_history(bind, audit_table) -> None:
    history_rows = bind.execute(
        sa.text(
            """
            SELECT
                h.id,
                h.platform_id,
                h.user_id,
                h.approval_status,
                h.updated_at,
                h.updated_by_id,
                h.reason,
                h.is_deleted AS history_is_deleted,
                pm.id AS membership_id
            FROM platformmembershiphistory h
            LEFT JOIN platformmembership pm
              ON pm.platform_id = h.platform_id
             AND pm.user_id = h.user_id
            """
        )
    ).mappings().all()

    grouped: dict[object, list[dict]] = defaultdict(list)
    for row in history_rows:
        key = row["membership_id"] or (row["platform_id"], row["user_id"])
        grouped[key].append(row)

    inserts: list[dict[str, object]] = []
    seen_memberships: set[uuid.UUID] = set()

    for key, rows in grouped.items():
        rows.sort(key=lambda r: r["updated_at"] or datetime.now(timezone.utc))
        for index, row in enumerate(rows):
            membership_id = row["membership_id"]
            action = (
                "deleted"
                if row["history_is_deleted"]
                else ("created" if index == 0 else "updated")
            )
            inserts.append(
                {
                    "id": row["id"],
                    "membership_id": membership_id,
                    "platform_id": _normalize_enum(row["platform_id"]),
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["reason"],
                    "action": action,
                }
            )
            if membership_id:
                seen_memberships.add(membership_id)

    membership_rows = bind.execute(
        sa.text(
            """
            SELECT
                id,
                platform_id,
                user_id,
                approval_status,
                updated_at,
                updated_by_id,
                revocation_reason,
                is_deleted
            FROM platformmembership
            """
        )
    ).mappings().all()

    memberships_to_delete: list[uuid.UUID] = []
    for row in membership_rows:
        membership_id = row["id"]
        if membership_id not in seen_memberships:
            inserts.append(
                {
                    "id": uuid.uuid4(),
                    "membership_id": membership_id,
                    "platform_id": _normalize_enum(row["platform_id"]),
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["revocation_reason"],
                    "action": "created",
                }
            )
            seen_memberships.add(membership_id)

        if row["is_deleted"]:
            inserts.append(
                {
                    "id": uuid.uuid4(),
                    "membership_id": membership_id,
                    "platform_id": _normalize_enum(row["platform_id"]),
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["revocation_reason"],
                    "action": "deleted",
                }
            )
            memberships_to_delete.append(membership_id)

    if inserts:
        op.bulk_insert(audit_table, inserts)

    if memberships_to_delete:
        for membership_id in memberships_to_delete:
            bind.execute(
                sa.text("DELETE FROM platformmembership WHERE id = :id"),
                {"id": membership_id},
            )


def _migrate_group_history(bind, audit_table) -> None:
    history_rows = bind.execute(
        sa.text(
            """
            SELECT
                h.id,
                h.group_id,
                h.user_id,
                h.approval_status,
                h.updated_at,
                h.updated_by_id,
                h.reason,
                h.is_deleted AS history_is_deleted,
                gm.id AS membership_id
            FROM groupmembershiphistory h
            LEFT JOIN groupmembership gm
              ON gm.group_id = h.group_id
             AND gm.user_id = h.user_id
            """
        )
    ).mappings().all()

    grouped: dict[object, list[dict]] = defaultdict(list)
    for row in history_rows:
        key = row["membership_id"] or (row["group_id"], row["user_id"])
        grouped[key].append(row)

    inserts: list[dict[str, object]] = []
    seen_memberships: set[uuid.UUID] = set()

    for key, rows in grouped.items():
        rows.sort(key=lambda r: r["updated_at"] or datetime.now(timezone.utc))
        for index, row in enumerate(rows):
            membership_id = row["membership_id"]
            action = (
                "deleted"
                if row["history_is_deleted"]
                else ("created" if index == 0 else "updated")
            )
            inserts.append(
                {
                    "id": row["id"],
                    "membership_id": membership_id,
                    "group_id": row["group_id"],
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["reason"],
                    "action": action,
                }
            )
            if membership_id:
                seen_memberships.add(membership_id)

    membership_rows = bind.execute(
        sa.text(
            """
            SELECT
                id,
                group_id,
                user_id,
                approval_status,
                updated_at,
                updated_by_id,
                revocation_reason,
                is_deleted
            FROM groupmembership
            """
        )
    ).mappings().all()

    memberships_to_delete: list[uuid.UUID] = []
    for row in membership_rows:
        membership_id = row["id"]
        if membership_id not in seen_memberships:
            inserts.append(
                {
                    "id": uuid.uuid4(),
                    "membership_id": membership_id,
                    "group_id": row["group_id"],
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["revocation_reason"],
                    "action": "created",
                }
            )
            seen_memberships.add(membership_id)

        if row["is_deleted"]:
            inserts.append(
                {
                    "id": uuid.uuid4(),
                    "membership_id": membership_id,
                    "group_id": row["group_id"],
                    "user_id": row["user_id"],
                    "approval_status": _normalize_enum(row["approval_status"]),
                    "updated_at": row["updated_at"] or datetime.now(timezone.utc),
                    "acted_at": row["updated_at"] or datetime.now(timezone.utc),
                    "updated_by_id": row["updated_by_id"],
                    "revocation_reason": row["revocation_reason"],
                    "action": "deleted",
                }
            )
            memberships_to_delete.append(membership_id)

    if inserts:
        op.bulk_insert(audit_table, inserts)

    if memberships_to_delete:
        for membership_id in memberships_to_delete:
            bind.execute(
                sa.text("DELETE FROM groupmembership WHERE id = :id"),
                {"id": membership_id},
            )


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade is not supported for converting history tables into audit logs."
    )
