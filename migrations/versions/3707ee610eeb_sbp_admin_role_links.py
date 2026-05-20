"""sbp_admin_role_links

Link biocommons/role/sbp/admin to both the SBP platform (platformrolelink) and
the SBP bundle group (grouprolelink), so a single Auth0 role covers both
platform and bundle admin actions.

Both inserts are conditional: if the auth0role row doesn't exist yet (i.e. no
SBP admin has logged in and triggered a sync) the insert is skipped — the
scheduled link_admin_roles task will pick it up automatically once the role is
present.

Revision ID: 3707ee610eeb
Revises: 4000ecb2796d
Create Date: 2026-05-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3707ee610eeb'
down_revision: Union[str, None] = '4000ecb2796d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SBP_ADMIN_ROLE_NAME = "biocommons/role/sbp/admin"
SBP_PLATFORM_ID = "sbp"
SBP_GROUP_ID = "biocommons/group/sbp_workflow_execution"


def _get_role_id(bind, role_name: str) -> str | None:
    row = bind.execute(
        sa.text("SELECT id FROM auth0role WHERE name = :name AND is_deleted = FALSE"),
        {"name": role_name},
    ).fetchone()
    return row[0] if row else None


def _upsert_platformrolelink(bind, platform_id: str, role_id: str) -> None:
    existing = bind.execute(
        sa.text(
            "SELECT is_deleted FROM platformrolelink"
            " WHERE platform_id = :platform_id AND role_id = :role_id"
        ),
        {"platform_id": platform_id, "role_id": role_id},
    ).fetchone()

    if existing is None:
        bind.execute(
            sa.text(
                "INSERT INTO platformrolelink (platform_id, role_id, is_deleted)"
                " VALUES (:platform_id, :role_id, FALSE)"
            ),
            {"platform_id": platform_id, "role_id": role_id},
        )
    elif existing[0]:
        bind.execute(
            sa.text(
                "UPDATE platformrolelink SET is_deleted = FALSE"
                " WHERE platform_id = :platform_id AND role_id = :role_id"
            ),
            {"platform_id": platform_id, "role_id": role_id},
        )


def _upsert_grouprolelink(bind, group_id: str, role_id: str) -> None:
    existing = bind.execute(
        sa.text(
            "SELECT is_deleted FROM grouprolelink"
            " WHERE group_id = :group_id AND role_id = :role_id"
        ),
        {"group_id": group_id, "role_id": role_id},
    ).fetchone()

    if existing is None:
        bind.execute(
            sa.text(
                "INSERT INTO grouprolelink (group_id, role_id, is_deleted)"
                " VALUES (:group_id, :role_id, FALSE)"
            ),
            {"group_id": group_id, "role_id": role_id},
        )
    elif existing[0]:
        bind.execute(
            sa.text(
                "UPDATE grouprolelink SET is_deleted = FALSE"
                " WHERE group_id = :group_id AND role_id = :role_id"
            ),
            {"group_id": group_id, "role_id": role_id},
        )


def upgrade() -> None:
    bind = op.get_bind()
    role_id = _get_role_id(bind, SBP_ADMIN_ROLE_NAME)
    if role_id is None:
        return
    _upsert_platformrolelink(bind, SBP_PLATFORM_ID, role_id)
    _upsert_grouprolelink(bind, SBP_GROUP_ID, role_id)


def downgrade() -> None:
    bind = op.get_bind()
    role_id = _get_role_id(bind, SBP_ADMIN_ROLE_NAME)
    if role_id is None:
        return
    bind.execute(
        sa.text("DELETE FROM grouprolelink WHERE group_id = :gid AND role_id = :rid"),
        {"gid": SBP_GROUP_ID, "rid": role_id},
    )
    bind.execute(
        sa.text("DELETE FROM platformrolelink WHERE platform_id = :pid AND role_id = :rid"),
        {"pid": SBP_PLATFORM_ID, "rid": role_id},
    )
