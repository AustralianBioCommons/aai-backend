"""platform_constraints

Revision ID: 08a3d0593418
Revises: 575a146957f2
Create Date: 2025-09-24 10:38:24.506817

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '08a3d0593418'
down_revision: Union[str, None] = '575a146957f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        with op.batch_alter_table("platform") as batch_op:
            batch_op.create_unique_constraint(op.f("uq_platform_id"), ["id"])
    else:
        op.create_unique_constraint(op.f("uq_platform_id"), "platform", ["id"])


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        with op.batch_alter_table("platform") as batch_op:
            batch_op.drop_constraint(op.f("uq_platform_id"), type_="unique")
    else:
        op.drop_constraint(op.f("uq_platform_id"), "platform", type_="unique")
