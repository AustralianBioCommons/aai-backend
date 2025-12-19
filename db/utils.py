import logging
from datetime import UTC, datetime, timedelta
from typing import Sequence

from sqlmodel import Session, select

from auth0.client import Auth0Client
from db.models import BiocommonsUser

logger = logging.getLogger("uvicorn.error")


UNVERIFIED_REFRESH_INTERVAL = 60 * 5
LAST_UNVERIFIED_REFRESH_TIME: datetime | None = None


def refresh_unverified_users(session: Session, auth0_client: Auth0Client):
    """
    Update all unverified users with their latest email_verified status from Auth0.
    Run as a background task, triggered when an admin looks at unverified users.

    Uses a simple time-based throttle to avoid excessive API calls.
    """
    global LAST_UNVERIFIED_REFRESH_TIME
    if LAST_UNVERIFIED_REFRESH_TIME is not None:
        since_last_refresh = datetime.now(UTC) - LAST_UNVERIFIED_REFRESH_TIME
        if since_last_refresh < timedelta(seconds=UNVERIFIED_REFRESH_INTERVAL):
            logger.info(f"Skipping refresh of unverified users: last refresh was {LAST_UNVERIFIED_REFRESH_TIME}")
            return
    LAST_UNVERIFIED_REFRESH_TIME = datetime.now(UTC)
    unverified_users: Sequence[BiocommonsUser] = session.exec(select(BiocommonsUser).where(BiocommonsUser.email_verified.is_(False))).all()
    try:
        for user in unverified_users:
            auth0_data = auth0_client.get_user(user.id)
            if auth0_data.email_verified != user.email_verified:
                logger.info(f"Updating email_verified status for user {user.id}: {auth0_data.email_verified}")
                user.email_verified = auth0_data.email_verified
                session.add(user)
        session.commit()
    finally:
        session.close()
