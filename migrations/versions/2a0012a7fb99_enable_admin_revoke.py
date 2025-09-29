"""enable_admin_revoke

Revision ID: 2a0012a7fb99
Revises: 1546c07b9d78
Create Date: 2025-09-26 12:37:37.374881

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '2a0012a7fb99'
down_revision: Union[str, None] = '1546c07b9d78'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Extend PlatformEnum for the SBP platform.
    op.execute('ALTER TYPE "PlatformEnum" ADD VALUE \'SBP\'')

    # Create platform lookup tables and wire existing membership FK.
    op.create_table(
        'platform',
        sa.Column('id', sa.Enum('GALAXY', 'BPA_DATA_PORTAL', 'SBP', name='PlatformEnum'), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_platform')),
        sa.UniqueConstraint('name', name=op.f('uq_platform_name')),
    )
    op.create_unique_constraint(op.f('uq_platform_id'), 'platform', ['id'])

    op.execute("INSERT INTO platform (id, name) VALUES ('GALAXY', 'Galaxy Australia')")
    op.execute("INSERT INTO platform (id, name) VALUES ('BPA_DATA_PORTAL', 'Bioplatforms Australia Data Portal')")
    op.execute("INSERT INTO platform (id, name) VALUES ('SBP', 'Structural Biology Platform')")

    op.create_table(
        'platformrolelink',
        sa.Column('platform_id', sa.Enum('GALAXY', 'BPA_DATA_PORTAL', 'SBP', name='PlatformEnum'), nullable=False),
        sa.Column('role_id', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.ForeignKeyConstraint(['platform_id'], ['platform.id'], name=op.f('fk_platformrolelink_platform_id_platform')),
        sa.ForeignKeyConstraint(['role_id'], ['auth0role.id'], name=op.f('fk_platformrolelink_role_id_auth0role')),
        sa.PrimaryKeyConstraint('platform_id', 'role_id', name=op.f('pk_platformrolelink')),
    )

    op.create_foreign_key(
        op.f('fk_platformmembership_platform_id_platform'),
        'platformmembership',
        'platform',
        ['platform_id'],
        ['id'],
    )

    # Capture admin-provided revoke reasons on memberships and history.
    op.add_column('groupmembership', sa.Column('revocation_reason', sa.String(length=1024), nullable=True))
    op.add_column('groupmembershiphistory', sa.Column('reason', sa.String(length=1024), nullable=True))
    op.add_column('platformmembership', sa.Column('revocation_reason', sa.String(length=1024), nullable=True))
    op.add_column('platformmembershiphistory', sa.Column('reason', sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column('platformmembershiphistory', 'reason')
    op.drop_column('platformmembership', 'revocation_reason')
    op.drop_column('groupmembershiphistory', 'reason')
    op.drop_column('groupmembership', 'revocation_reason')

    op.drop_constraint('fk_platformmembership_platform_id_platform', 'platformmembership', type_='foreignkey')
    op.drop_table('platformrolelink')
    op.drop_constraint('uq_platform_id', 'platform', type_='unique')
    op.drop_table('platform')
