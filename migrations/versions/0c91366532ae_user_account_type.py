"""user_account_type

Revision ID: 0c91366532ae
Revises: 39caad32922e
Create Date: 2026-08-06 14:12:14.614001

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '0c91366532ae'
down_revision: Union[str, None] = '39caad32922e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    account_type_enum = sa.Enum('auth0', 'aaf', name='biocommons_user_account_type')
    op.add_column(
        'biocommons_user',
        sa.Column(
            'account_type',
            account_type_enum,
            nullable=True,
            server_default='auth0',
        ),
    )
    op.execute("UPDATE biocommons_user SET account_type = 'auth0' WHERE account_type IS NULL")
    with op.batch_alter_table('biocommons_user') as batch_op:
        batch_op.alter_column(
            'account_type',
            existing_type=account_type_enum,
            nullable=False,
            server_default=None,
        )


def downgrade() -> None:
    op.drop_column('biocommons_user', 'account_type')
