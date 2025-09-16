from loguru import logger

from auth.management import get_management_token
from auth0.client import Auth0Client
from config import get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from scheduled_tasks.scheduler import SCHEDULER
from schemas.biocommons import Auth0UserData


async def sync_auth0_users():
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    current_page = 1
    logger.info("Fetching users")
    users = auth0_client.get_users(page=current_page, per_page=50, include_totals=True)
    while True:
        for user in users.users:
            SCHEDULER.add_job(update_auth0_user, args=[user], id=f"update_user_{user.user_id}", replace_existing=True)
        current_fetched = (users.start * users.limit) + len(users.users)
        if current_fetched >= users.total:
            break
        current_page += 1
        logger.info(f"Fetching page {current_page}")
        users = auth0_client.get_users(page=current_page, per_page=50, include_totals=True)


async def update_auth0_user(user_data: Auth0UserData):
    logger.info(f"Checking user {user_data.user_id}")
    session = next(get_db_session())
    db_user = session.get(BiocommonsUser, user_data.user_id)
    if db_user is None:
        logger.info("  User not found in DB")
        return False
    db_user.update_from_auth0_data(user_data)
    if session.is_modified(db_user):
        logger.info("  User data changed, updating in DB")
    else:
        logger.info("  User data unchanged")
    # Should be OK to commit as SQLAlchemy will only update modified fields
    session.commit()
    return True
