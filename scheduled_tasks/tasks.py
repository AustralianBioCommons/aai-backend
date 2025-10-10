from loguru import logger

from auth.management import get_management_token
from auth0.client import Auth0Client
from config import get_settings
from db.models import Auth0Role, BiocommonsGroup, BiocommonsUser
from db.setup import get_db_session
from db.types import GROUP_NAMES, GroupEnum
from scheduled_tasks.scheduler import SCHEDULER
from schemas.biocommons import Auth0UserData


async def sync_auth0_users():
    logger.info("Syncing Auth0 users")
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
        current_fetched = users.start + len(users.users)
        if current_fetched >= users.total:
            break
        current_page += 1
        logger.info(f"Fetching page {current_page}")
        users = auth0_client.get_users(page=current_page, per_page=50, include_totals=True)


async def update_auth0_user(user_data: Auth0UserData):
    logger.info(f"Checking user {user_data.user_id}")
    session = next(get_db_session())
    db_user = BiocommonsUser.get_by_id(user_data.user_id, session)
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


async def sync_auth0_roles():
    logger.info("Syncing Auth0 roles")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = auth0_client.get_all_roles()
    logger.info(f"Found {len(roles)} roles")

    db_session = next(get_db_session())
    with db_session.begin():
        for role in roles:
            logger.info(f"  Role: {role.name}")
            db_role = db_session.get(Auth0Role, role.id)
            if db_role is not None:
                logger.info("    Role already exists in DB")
                continue
            else:
                logger.info("    Role does not exist in DB, creating")
                db_role = Auth0Role(
                    id=role.id,
                    name=role.name,
                    description=role.description
                )
                db_session.add(db_role)


async def populate_db_groups():
    logger.info("Populating DB groups")
    db_session = next(get_db_session())
    with db_session.begin():
        for group in GroupEnum:
            logger.info(f"  Group: {group.value}")
            db_group = BiocommonsGroup.get_by_id(group.value, db_session)
            if db_group is not None:
                logger.info("    Group already exists in DB")
                continue
            else:
                logger.info("    Group does not exist in DB, creating")
                name = GROUP_NAMES.get(group, group.value)
                db_group = BiocommonsGroup(group_id=group.value, name=name)
                db_session.add(db_group)
        db_session.commit()
