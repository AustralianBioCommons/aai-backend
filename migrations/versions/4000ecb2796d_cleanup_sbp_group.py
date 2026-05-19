"""cleanup_sbp_group

Revision ID: 4000ecb2796d
Revises: 274454823044
Create Date: 2026-05-19 09:04:35.271199

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '4000ecb2796d'
down_revision: Union[str, None] = '274454823044'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD_SBP_GROUP_ID = "biocommons/group/sbp_bundle"
SBP_GROUP_ID = "biocommons/group/sbp_workflow_execution"
SBP_NAME = "Structural Biology Platform Bundle"
SBP_SHORT_NAME = "SBP"

def _delete_legacy_sbp_group() -> None:
    bind = op.get_bind()

    for table in ("grouprolelink", "groupmembershiphistory", "groupmembership"):
        bind.execute(
            sa.text(f"DELETE FROM {table} WHERE group_id = :group_id"),
            {"group_id": OLD_SBP_GROUP_ID},
        )

    bind.execute(
        sa.text("DELETE FROM biocommonsgroup WHERE group_id = :group_id"),
        {"group_id": OLD_SBP_GROUP_ID},
    )


def _upsert_sbp_workflow_execution_group() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        bind.execute(
            sa.text(
                """
                INSERT INTO biocommonsgroup (group_id, name, short_name, is_deleted)
                VALUES (:group_id, :name, :short_name, FALSE)
                    ON CONFLICT (group_id) DO UPDATE
                                                  SET name = EXCLUDED.name,
                                                  short_name = EXCLUDED.short_name,
                                                  is_deleted = FALSE
                """
            ),
            {
                "group_id": SBP_GROUP_ID,
                "name": SBP_NAME,
                "short_name": SBP_SHORT_NAME,
            },
        )
        return

    existing = bind.execute(
        sa.text("SELECT group_id FROM biocommonsgroup WHERE group_id = :group_id"),
        {"group_id": SBP_GROUP_ID},
    ).fetchone()

    if existing is None:
        bind.execute(
            sa.text(
                """
                INSERT INTO biocommonsgroup (group_id, name, short_name, is_deleted)
                VALUES (:group_id, :name, :short_name, FALSE)
                """
            ),
            {
                "group_id": SBP_GROUP_ID,
                "name": SBP_NAME,
                "short_name": SBP_SHORT_NAME,
            },
        )
    else:
        bind.execute(
            sa.text(
                """
                UPDATE biocommonsgroup
                SET name = :name,
                    short_name = :short_name,
                    is_deleted = FALSE
                WHERE group_id = :group_id
                """
            ),
            {
                "group_id": SBP_GROUP_ID,
                "name": SBP_NAME,
                "short_name": SBP_SHORT_NAME,
            },
        )

def upgrade() -> None:
    _delete_legacy_sbp_group()
    _upsert_sbp_workflow_execution_group()


def downgrade() -> None:
    pass
