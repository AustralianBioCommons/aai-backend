"""merge admin revoke heads

Revision ID: 9c2ebbf62acd
Revises: 08a3d0593418, 2a0012a7fb99
Create Date: 2025-09-28 19:01:32.548044

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '9c2ebbf62acd'
down_revision: Union[str, None] = ('08a3d0593418', '2a0012a7fb99')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
