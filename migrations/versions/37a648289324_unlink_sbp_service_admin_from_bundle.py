"""unlink_sbp_service_admin_from_bundle

Remove the stale admin-role link between the SBP service admin role
(``biocommons/role/sbp/admin``) and the SBP bundle group
(``biocommons/group/sbp_workflow_execution``).

That link was created by the earlier combined "SBP admin" behavior
(``PLATFORM_BUNDLE_GROUP_MAP``), where a single role granted admin over both the
SBP platform and the SBP bundle group. Now that the roles are split, the service
admin role must gate the platform only; the bundle is gated by the separate
``biocommons/role/sbp_workflow_execution/admin`` role. ``link_admin_roles`` is
append-only (it never removes links), so this pre-existing row has to be deleted
by a data migration -- otherwise ``/me/groups/admin-roles`` keeps returning the
bundle for service admins and the portal classifies them as biocommons admins.

Revision ID: 37a648289324
Revises: 4000ecb2796d
Create Date: 2026-07-06 14:10:56.063620

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '37a648289324'
down_revision: Union[str, None] = '4000ecb2796d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SBP_BUNDLE_GROUP_ID = "biocommons/group/sbp_workflow_execution"
SBP_SERVICE_ADMIN_ROLE = "biocommons/role/sbp/admin"


def upgrade() -> None:
    # Hard delete (matches the 4000ecb2796d cleanup precedent). Idempotent: does
    # nothing on environments that never ran the combined-admin code. Raw SQL is
    # not subject to the ORM soft-delete filter, so the role is matched by name
    # even if the Auth0Role row is itself soft-deleted.
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            DELETE FROM grouprolelink
            WHERE group_id = :group_id
              AND role_id IN (
                  SELECT id FROM auth0role WHERE name = :role_name
              )
            """
        ),
        {"group_id": SBP_BUNDLE_GROUP_ID, "role_name": SBP_SERVICE_ADMIN_ROLE},
    )


def downgrade() -> None:
    # No-op: re-creating the link would reintroduce the combined-admin behavior.
    pass
