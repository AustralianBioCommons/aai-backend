import re
from datetime import datetime, timezone

from loguru import logger
from sqlmodel import Session, select

from auth.management import get_management_token
from auth0.client import Auth0Client
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
)
from db.setup import get_db_session
from db.types import GROUP_NAMES, ApprovalStatusEnum, GroupEnum
from scheduled_tasks.scheduler import SCHEDULER
from schemas.auth0 import PLATFORM_ROLE_PATTERN, get_platform_id_from_role_name
from schemas.biocommons import Auth0UserData


def _ensure_user_from_auth0(session: Session, user_data: Auth0UserData) -> tuple[BiocommonsUser, bool, bool]:
    """
    Ensure the Auth0 user exists in the database, creating or restoring if required.

    Returns a tuple of (user, created, restored).
    """
    created = False
    restored = False
    user = BiocommonsUser.get_by_id(user_data.user_id, session)
    if user is None:
        user = BiocommonsUser.get_deleted_by_id(session, user_data.user_id)
        if user is not None:
            restored = True
            user.restore(session, commit=False)
        else:
            created = True
            user = BiocommonsUser.from_auth0_data(user_data)
    session.add(user)
    user.email = user_data.email
    if user_data.username is not None:
        user.username = user_data.username
    user.email_verified = user_data.email_verified
    return user, created, restored


def _get_membership_including_deleted(session: Session, user_id: str, group_id: str) -> GroupMembership | None:
    stmt = (
        select(GroupMembership)
        .execution_options(include_deleted=True)
        .where(GroupMembership.user_id == user_id, GroupMembership.group_id == group_id)
    )
    return session.exec(stmt).one_or_none()


async def sync_auth0_users():
    logger.info("Syncing Auth0 users")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    current_page = 1
    logger.info("Fetching users")
    users = auth0_client.get_users(page=current_page, per_page=50, include_totals=True)
    db_session = next(get_db_session())
    auth0_user_ids: set[str] = set()
    try:
        while True:
            for user in users.users:
                auth0_user_ids.add(user.user_id)
                _ensure_user_from_auth0(db_session, user)
                SCHEDULER.add_job(
                    update_auth0_user,
                    args=[user],
                    id=f"update_user_{user.user_id}",
                    replace_existing=True,
                )
            current_fetched = users.start + len(users.users)
            if current_fetched >= users.total:
                break
            current_page += 1
            logger.info(f"Fetching page {current_page}")
            users = auth0_client.get_users(page=current_page, per_page=50, include_totals=True)
        # Soft delete any users no longer present in Auth0
        db_session.flush()
        existing_users = db_session.exec(select(BiocommonsUser)).all()
        for db_user in existing_users:
            if db_user.id not in auth0_user_ids:
                logger.info(f"Soft deleting user {db_user.id} absent from Auth0")
                db_user.delete(db_session, commit=False)
        db_session.commit()
    finally:
        db_session.close()


async def update_auth0_user(user_data: Auth0UserData):
    logger.info(f"Checking user {user_data.user_id}")
    session = next(get_db_session())
    try:
        db_user, created, restored = _ensure_user_from_auth0(session, user_data)
        if created:
            logger.info("  User created in DB")
        elif restored:
            logger.info("  User restored from soft delete")
        else:
            logger.info("  User exists in DB, updating fields")
        if session.is_modified(db_user):
            logger.info("  User data changed, updating in DB")
        else:
            logger.info("  User data unchanged")
        # Should be OK to commit as SQLAlchemy will only update modified fields
        session.commit()
        return True
    finally:
        session.close()


async def sync_auth0_roles():
    logger.info("Syncing Auth0 roles")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = auth0_client.get_all_roles()
    logger.info(f"Found {len(roles)} roles")

    db_session = next(get_db_session())
    auth0_role_ids: set[str] = set()
    try:
        for role in roles:
            logger.info(f"  Role: {role.name}")
            auth0_role_ids.add(role.id)
            db_role = db_session.get(Auth0Role, role.id)
            created = False
            restored = False
            if db_role is None:
                db_role = Auth0Role.get_deleted_by_id(db_session, role.id)
                if db_role is not None:
                    restored = True
                    db_role.restore(db_session, commit=False)
                else:
                    created = True
                    db_role = Auth0Role(
                        id=role.id,
                        name=role.name,
                        description=role.description,
                    )
            db_session.add(db_role)
            if created:
                logger.info("    Role created in DB")
            elif restored:
                logger.info("    Role restored from soft delete")
            else:
                logger.info("    Role exists in DB, updating fields if necessary")
            if db_role.name != role.name or db_role.description != role.description:
                db_role.name = role.name
                db_role.description = role.description
        # Soft delete roles missing from Auth0
        db_session.flush()
        existing_roles = db_session.exec(select(Auth0Role)).all()
        for db_role in existing_roles:
            if db_role.id not in auth0_role_ids:
                logger.info(f"    Soft deleting role {db_role.name} ({db_role.id}) absent from Auth0")
                db_role.delete(db_session, commit=False)
        db_session.commit()
    finally:
        db_session.close()


async def sync_auth0_user_roles():
    logger.info("Syncing Auth0 user-role assignments")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = auth0_client.get_all_roles()
    db_session = next(get_db_session())
    managed_groups = {
        group.group_id: group for group in db_session.exec(select(BiocommonsGroup))
    }
    existing_memberships = {
        (membership.user_id, membership.group_id): membership
        for membership in db_session.exec(
            select(GroupMembership).execution_options(include_deleted=True)
        )
    }
    assignments_in_auth0: set[tuple[str, str]] = set()
    try:
        for role in roles:
            group = managed_groups.get(role.name)
            if group is None:
                continue
            logger.info(f"  Processing assignments for role {role.name}")
            role_users = auth0_client.get_all_role_users(role_id=role.id)
            for role_user in role_users:
                assignments_in_auth0.add((role_user.user_id, group.group_id))
                auth0_user = auth0_client.get_user(role_user.user_id)
                db_user, _, _ = _ensure_user_from_auth0(db_session, auth0_user)
                key = (db_user.id, group.group_id)
                membership = existing_memberships.get(key)
                created = False
                restored = False
                if membership is None:
                    membership = _get_membership_including_deleted(db_session, db_user.id, group.group_id)
                    if membership is None:
                        created = True
                        membership = GroupMembership(
                            group_id=group.group_id,
                            user_id=db_user.id,
                            approval_status=ApprovalStatusEnum.APPROVED,
                            updated_by_id=None,
                        )
                        db_session.add(membership)
                        db_session.flush()
                    existing_memberships[key] = membership
                if membership.is_deleted:
                    restored = True
                    membership.restore(db_session, commit=False)
                status_changed = False
                if membership.approval_status != ApprovalStatusEnum.APPROVED:
                    membership.approval_status = ApprovalStatusEnum.APPROVED
                    status_changed = True
                membership.updated_at = datetime.now(timezone.utc)
                db_session.add(membership)
                if created or restored or status_changed:
                    membership.save_history(db_session, commit=False)
                existing_memberships[key] = membership
                if created:
                    logger.info(f"    Created membership for {db_user.id} -> {group.group_id}")
                elif restored:
                    logger.info(f"    Restored membership for {db_user.id} -> {group.group_id}")
        # Soft delete memberships that are approved but no longer present
        db_session.flush()
        for key, membership in list(existing_memberships.items()):
            if membership.is_deleted:
                continue
            if membership.group_id not in managed_groups:
                continue
            if membership.approval_status != ApprovalStatusEnum.APPROVED:
                continue
            if key not in assignments_in_auth0:
                logger.info(
                    f"    Soft deleting membership {membership.user_id} -> {membership.group_id} absent from Auth0"
                )
                membership.delete(db_session, commit=False)
        db_session.commit()
    finally:
        db_session.close()


async def populate_db_groups():
    logger.info("Populating DB groups")
    db_session = next(get_db_session())
    try:
        with db_session.begin():
            for group in GroupEnum:
                logger.info(f"  Group: {group.value}")
                db_group = BiocommonsGroup.get_by_id(group.value, db_session)
                if db_group is not None:
                    logger.info("    Group already exists in DB")
                    continue
                logger.info("    Group does not exist in DB, creating")
                name_tuple = GROUP_NAMES.get(group, (group.value, group.value))
                name, short_name = (
                    name_tuple if isinstance(name_tuple, tuple) else (name_tuple, group.value)
                )
                db_group = BiocommonsGroup(group_id=group.value, name=name, short_name=short_name)
                db_session.add(db_group)
        db_session.commit()
    finally:
        db_session.close()


async def populate_platforms_from_auth0():
    """
    Create platforms in the database based on Auth0 roles - any roles
    matching the PLATFORM_ROLE_PATTERN will be considered platforms.
    """
    logger.info("Syncing Auth0 user-role assignments")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = auth0_client.get_all_roles()
    db_session = next(get_db_session())
    platform_roles = [role for role in roles if re.match(PLATFORM_ROLE_PATTERN, role.name) is not None]
    try:
        with db_session.begin():
            for role in platform_roles:
                db_role = Auth0Role.get_by_id(role.id, db_session)
                platform_id = get_platform_id_from_role_name(role.name)
                platform = Platform.get_by_id(platform_id=platform_id, session=db_session)
                if platform is None:
                    logger.info(f"  Creating platform {platform_id}")
                    platform = Platform.create_from_auth0_role(db_role, db_session, commit=False)
                else:
                    logger.info(f"  Updating platform {platform_id} (if needed)")
                    platform.update_from_auth0_role(db_role, db_session, commit=False)
        db_session.commit()
    finally:
        db_session.close()
