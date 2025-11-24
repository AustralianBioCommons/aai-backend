"""email retry window

Revision ID: 1c9f2d7b11a4
Revises: ff6e32a9c164
Create Date: 2024-11-24 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "1c9f2d7b11a4"
down_revision: Union[str, None] = "ff6e32a9c164"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emailnotification",
        sa.Column("first_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("emailnotification", "first_attempt_at")

