"""sbp_group: ensure SBP group exists in the DB

Revision ID: 98e639b5731f
Revises: 038392d88518
Create Date: 2026-05-01 10:06:15.256398

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

SBP_GROUP_ID = "biocommons/group/sbp_bundle"
SBP_NAME = "Structural Biology Platform Bundle"
SBP_SHORT_NAME = "SBP"

revision: str = '98e639b5731f'
down_revision: Union[str, None] = '038392d88518'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
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
    else:
        existing = bind.execute(
            sa.text(
                "SELECT group_id FROM biocommonsgroup WHERE group_id = :group_id"
            ),
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
                    SET name       = :name,
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


def downgrade() -> None:
    bind = op.get_bind()
    # Soft-delete to avoid breaking memberships
    bind.execute(
        sa.text(
            """
            UPDATE biocommonsgroup
            SET is_deleted = TRUE
            WHERE group_id = :group_id
            """
        ),
        {"group_id": SBP_GROUP_ID},
    )

