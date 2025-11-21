"""add email change otp table

Revision ID: 9f2d8c1b5d4e
Revises: a8cb5fd2d258
Create Date: 2025-11-20 13:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9f2d8c1b5d4e"
down_revision: Union[str, Sequence[str], None] = "d64e9ebd0253"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "email_change_otps",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.String(length=255),
            sa.ForeignKey("biocommons_user.id"),
            nullable=False,
        ),
        sa.Column("target_email", sa.String(length=320), nullable=False),
        sa.Column("otp_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("total_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_email_change_otps'))
    )


def downgrade() -> None:
    op.drop_table("email_change_otps")
