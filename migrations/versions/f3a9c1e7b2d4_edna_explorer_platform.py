"""edna_explorer_platform: add EDNA_EXPLORER value to PlatformEnum

Adds the eDNA Explorer platform enum value. The `platform` row itself is
created at runtime by `populate_platforms_from_auth0` once the Auth0 roles
`biocommons/platform/edna_explorer` and `biocommons/role/edna_explorer/admin`
exist (same mechanism that maintains galaxy/bpa/sbp), so we only extend the
Postgres enum type here. We deliberately do NOT seed/use the new value in this
migration to avoid Postgres' "unsafe use of new enum value in the same
transaction" restriction (mirrors c4c7a8e9b2d3).

Revision ID: f3a9c1e7b2d4
Revises: 4000ecb2796d
Create Date: 2026-07-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f3a9c1e7b2d4"
down_revision: Union[str, Sequence[str], None] = "4000ecb2796d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    # NOTE: alembic doesn't automatically add new enum values to existing types.
    # SQLite stores enums as plain strings, so no DDL is needed there.
    if dialect_name != "sqlite":
        op.execute("ALTER TYPE \"PlatformEnum\" ADD VALUE IF NOT EXISTS 'EDNA_EXPLORER'")


def downgrade() -> None:
    # Postgres does not support removing a value from an enum type, so there is
    # nothing to reverse. (Matches the other ADD VALUE migrations.)
    pass
