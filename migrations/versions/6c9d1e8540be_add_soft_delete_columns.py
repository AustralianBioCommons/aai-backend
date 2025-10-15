"""add soft delete columns

Revision ID: 6c9d1e8540be
Revises: 30fd168b9c90
Create Date: 2025-10-20 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = "6c9d1e8540be"
down_revision: Union[str, None] = "30fd168b9c90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


INSERT_ORDER = [
    "biocommons_user",
    "auth0role",
    "biocommonsgroup",
    "platform",
    "platformrolelink",
    "grouprolelink",
    "platformmembership",
    "groupmembership",
    "platformmembershiphistory",
    "groupmembershiphistory",
]

# Dependency-aware order for deleting rows on downgrade (children before parents).
DELETE_ORDER = [
    "platformmembershiphistory",
    "groupmembershiphistory",
    "platformmembership",
    "groupmembership",
    "platformrolelink",
    "grouprolelink",
    "platform",
    "biocommonsgroup",
    "auth0role",
    "biocommons_user",
]


def upgrade() -> None:
    for table in INSERT_ORDER:
        op.add_column(
            table,
            sa.Column(
                "is_deleted",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
        op.create_index(
            op.f(f"ix_{table}_is_deleted"),
            table,
            ["is_deleted"],
        )


def downgrade() -> None:
    # Remove soft-deleted rows before dropping the column so data does not reappear.
    for table in DELETE_ORDER:
        op.execute(text(f'DELETE FROM "{table}" WHERE is_deleted = TRUE'))
        op.drop_index(op.f(f"ix_{table}_is_deleted"), table_name=table)
        op.drop_column(table, "is_deleted")
