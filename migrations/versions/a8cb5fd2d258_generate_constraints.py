"""generate_constraints

Revision ID: a8cb5fd2d258
Revises: 27eaccb12f9b
Create Date: 2025-08-11 11:07:35.961466

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'a8cb5fd2d258'
down_revision: Union[str, None] = '27eaccb12f9b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        # SQLite requires batch mode to alter constraints safely.
        with op.batch_alter_table("auth0role") as batch_op:
            batch_op.create_unique_constraint(op.f("uq_auth0role_id"), ["id"])
        with op.batch_alter_table("biocommonsgroup") as batch_op:
            batch_op.create_unique_constraint(op.f("uq_biocommonsgroup_group_id"), ["group_id"])
    else:
        op.create_unique_constraint(op.f("uq_auth0role_id"), "auth0role", ["id"])
        op.create_unique_constraint(op.f("uq_biocommonsgroup_group_id"), "biocommonsgroup", ["group_id"])


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        with op.batch_alter_table("biocommonsgroup") as batch_op:
            batch_op.drop_constraint(op.f("uq_biocommonsgroup_group_id"), type_="unique")
        with op.batch_alter_table("auth0role") as batch_op:
            batch_op.drop_constraint(op.f("uq_auth0role_id"), type_="unique")
    else:
        op.drop_constraint(op.f("uq_biocommonsgroup_group_id"), "biocommonsgroup", type_="unique")
        op.drop_constraint(op.f("uq_auth0role_id"), "auth0role", type_="unique")
