"""group-membership-rejection

Revision ID: c4c7a8e9b2d3
Revises: d6a5578732bc
Create Date: 2025-12-02 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c4c7a8e9b2d3"
down_revision: Union[str, Sequence[str], None] = "d6a5578732bc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name != "sqlite":
        op.execute('ALTER TYPE "ApprovalStatusEnum" ADD VALUE \'REJECTED\'')

    op.add_column(
        "groupmembership",
        sa.Column("rejection_reason", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("groupmembership", "rejection_reason")
