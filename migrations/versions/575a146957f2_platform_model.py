"""platform_model

Revision ID: 575a146957f2
Revises: 1546c07b9d78
Create Date: 2025-09-24 10:07:01.958231

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = "575a146957f2"
down_revision: Union[str, None] = "1546c07b9d78"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    inspector = sa.inspect(bind)

    # NOTE: alembic doesn't automatically add new enum values to existing types
    if dialect_name != "sqlite":
        op.execute('ALTER TYPE "PlatformEnum" ADD VALUE \'SBP\'')

    if not inspector.has_table("platform"):
        op.create_table(
            "platform",
            sa.Column("id", sa.Enum("GALAXY", "BPA_DATA_PORTAL", "SBP", name="PlatformEnum"), nullable=False),
            sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_platform")),
            sa.UniqueConstraint("id", name=op.f("uq_platform_id")),
            sa.UniqueConstraint("name", name=op.f("uq_platform_name")),
        )

    if not inspector.has_table("platformrolelink"):
        op.create_table(
            "platformrolelink",
            sa.Column("platform_id", sa.Enum("GALAXY", "BPA_DATA_PORTAL", "SBP", name="PlatformEnum"), nullable=False),
            sa.Column("role_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
            sa.ForeignKeyConstraint(
                ["platform_id"],
                ["platform.id"],
                name=op.f("fk_platformrolelink_platform_id_platform"),
            ),
            sa.ForeignKeyConstraint(
                ["role_id"],
                ["auth0role.id"],
                name=op.f("fk_platformrolelink_role_id_auth0role"),
            ),
            sa.PrimaryKeyConstraint("platform_id", "role_id", name=op.f("pk_platformrolelink")),
        )

    fk_names = {fk["name"] for fk in inspector.get_foreign_keys("platformmembership")}
    fk_name = op.f("fk_platformmembership_platform_id_platform")
    if fk_name not in fk_names:
        if dialect_name == "sqlite":
            with op.batch_alter_table("platformmembership", recreate="always") as batch_op:
                batch_op.create_foreign_key(
                    fk_name,
                    "platform",
                    ["platform_id"],
                    ["id"],
                )
        else:
            op.create_foreign_key(
                fk_name,
                "platformmembership",
                "platform",
                ["platform_id"],
                ["id"],
            )

    if dialect_name == "sqlite":
        op.execute("INSERT OR IGNORE INTO platform (id, name) VALUES ('GALAXY', 'Galaxy Australia')")
        op.execute("INSERT OR IGNORE INTO platform (id, name) VALUES ('BPA_DATA_PORTAL', 'Bioplatforms Australia Data Portal')")
        op.execute("INSERT OR IGNORE INTO platform (id, name) VALUES ('SBP', 'Structural Biology Platform')")
    else:
        op.execute("INSERT INTO platform (id, name) VALUES ('GALAXY', 'Galaxy Australia') ON CONFLICT (id) DO NOTHING")
        op.execute("INSERT INTO platform (id, name) VALUES ('BPA_DATA_PORTAL', 'Bioplatforms Australia Data Portal') ON CONFLICT (id) DO NOTHING")
        op.execute("INSERT INTO platform (id, name) VALUES ('SBP', 'Structural Biology Platform') ON CONFLICT (id) DO NOTHING")


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "sqlite":
        # SQLite needs batch mode to drop FKs.
        with op.batch_alter_table("platformmembership", recreate="always") as batch_op:
            batch_op.drop_constraint(op.f("fk_platformmembership_platform_id_platform"), type_="foreignkey")
    else:
        op.drop_constraint(op.f("fk_platformmembership_platform_id_platform"), "platformmembership", type_="foreignkey")
    op.drop_table("platformrolelink")
    op.drop_table("platform")
