"""edna-explorer

Adds the EDNA_EXPLORER value to the Postgres ``PlatformEnum`` type.

We use ``ALTER TYPE ... ADD VALUE`` (in-place append) rather than recreating the
type: ``platform.id`` is a primary key referenced by foreign keys in
``platformrolelink``/``platformmembership``/``platformmembershiphistory``, so
recreating the type would fail with "foreign key constraint cannot be
implemented". This mirrors how SBP (575a146957f2) and REJECTED (c4c7a8e9b2d3)
were added. SQLite stores enums as plain strings, so no DDL is needed there.

Revision ID: 39caad32922e
Revises: 4000ecb2796d
Create Date: 2026-07-17 10:24:19.065484

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '39caad32922e'
down_revision: Union[str, None] = '4000ecb2796d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        # IF NOT EXISTS keeps this idempotent (the value cannot be dropped on
        # downgrade, so a re-upgrade must not error).
        op.execute("ALTER TYPE \"PlatformEnum\" ADD VALUE IF NOT EXISTS 'EDNA_EXPLORER'")


def downgrade() -> None:
    # Postgres cannot remove a value from an enum type, so there is nothing to
    # reverse (matches the other ADD VALUE migrations).
    pass
