from logging import getLogger
from typing import Literal

from pydantic import BaseModel
from sqlmodel import Session

from auth0.client import Auth0Client
from db.models import BiocommonsGroup, BiocommonsUser
from db.types import GroupEnum, PlatformEnum

logger = getLogger(__name__)

# All new bundles should be added here
BundleType = Literal["tsi"]


class BiocommonsBundle(BaseModel):
    id: BundleType
    group_id: GroupEnum
    group_auto_approve: bool
    # Non-default extra_platforms that are included as part of the bundle
    extra_platforms: list[PlatformEnum]

    def _add_group_membership(self, user: BiocommonsUser, session: Session):
        # Verify group exists
        BiocommonsGroup.get_by_id_or_404(group_id=self.group_id.value, session=session)
        group_membership = user.add_group_membership(
            group_id=self.group_id.value, db_session=session, auto_approve=self.group_auto_approve
        )
        session.add(group_membership)

    def _add_platform_memberships(self, user: BiocommonsUser, session: Session, auth0_client: Auth0Client):
        for platform in self.extra_platforms:
            logger.info(f"Adding platform membership for {platform.value} to user {user.id}")
            platform_membership = user.add_platform_membership(
                platform=platform, db_session=session, auth0_client=auth0_client, auto_approve=True
            )
            session.add(platform_membership)

    def create_memberships(
        self,
        user: BiocommonsUser,
        auth0_client: Auth0Client,
        db_session: Session,
        commit: bool = False,
    ):
        """
        Create group and platform memberships for the bundle user
        """
        # Create group membership
        self._add_group_membership(user=user, session=db_session)
        # Add extra platform memberships based on bundle configuration
        self._add_platform_memberships(user=user, session=db_session, auth0_client=auth0_client)
        db_session.flush()
        if commit:
            db_session.commit()
        return user


BUNDLES: dict[BundleType, BiocommonsBundle] = {
    "tsi": BiocommonsBundle(
        id="tsi",
        group_id=GroupEnum.TSI,
        group_auto_approve=False,
        extra_platforms=[],
    ),
}
