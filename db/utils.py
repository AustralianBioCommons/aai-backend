import logging
from datetime import UTC, datetime, timedelta
from typing import Sequence

from sqlmodel import Session

from auth0.client import Auth0Client
from db.models import BiocommonsUser
from db.setup import get_engine

logger = logging.getLogger("uvicorn.error")


UNVERIFIED_REFRESH_INTERVAL_SECONDS = 60 * 5
LAST_UNVERIFIED_REFRESH_TIME: datetime | None = None


def refresh_unverified_users(session: Session, auth0_client: Auth0Client):
    """
    Update all unverified users with their latest email_verified status from Auth0.
    """
    unverified_users: Sequence[BiocommonsUser] = BiocommonsUser.list_unverified(session)
    for user in unverified_users:
        auth0_data = auth0_client.get_user(user.id)
        if auth0_data.email_verified != user.email_verified:
            logger.info(f"Updating email_verified status for user {user.id}: {auth0_data.email_verified}")
            user.email_verified = auth0_data.email_verified
            session.add(user)
    session.commit()


def refresh_unverified_users_task(auth0_client: Auth0Client, session: Session | None = None):
    """
    Background task wrapper for refreshing unverified users.

    Uses a dedicated session by default so it does not outlive the request-scoped session.
    """
    global LAST_UNVERIFIED_REFRESH_TIME
    if LAST_UNVERIFIED_REFRESH_TIME is not None:
        since_last_refresh = datetime.now(UTC) - LAST_UNVERIFIED_REFRESH_TIME
        if since_last_refresh < timedelta(seconds=UNVERIFIED_REFRESH_INTERVAL_SECONDS):
            logger.info(f"Skipping refresh of unverified users: last refresh was {LAST_UNVERIFIED_REFRESH_TIME}")
            return
    LAST_UNVERIFIED_REFRESH_TIME = datetime.now(UTC)

    owns_session = session is None
    if session is None:
        session = Session(get_engine())

    try:
        refresh_unverified_users(session, auth0_client)
    finally:
        if owns_session:
            session.close()
