"""email_notifications

Revision ID: 7b0e3b7f4d84
Revises: ff6e32a9c164
Create Date: 2025-10-29 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '7b0e3b7f4d84'
down_revision: Union[str, None] = 'ff6e32a9c164'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'emailnotification',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('to_address', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('subject', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('body_html', sa.Text(), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'SENDING', 'SENT', 'FAILED', name='EmailStatusEnum'), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.String(length=1024), nullable=True),
        sa.Column('send_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_emailnotification'))
    )
    op.create_index(op.f('ix_emailnotification_status'), 'emailnotification', ['status'], unique=False)
    op.create_index(op.f('ix_emailnotification_to_address'), 'emailnotification', ['to_address'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_emailnotification_to_address'), table_name='emailnotification')
    op.drop_index(op.f('ix_emailnotification_status'), table_name='emailnotification')
    op.drop_table('emailnotification')
