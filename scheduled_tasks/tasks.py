import re
from datetime import datetime, timezone
from uuid import UUID

from loguru import logger
from pydantic import BaseModel
from sqlalchemy import or_
from sqlmodel import Session, select

from auth.management import get_management_token
from auth.ses import get_email_service
from auth0.client import Auth0Client, RoleData
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    EmailNotification,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import GROUP_NAMES, ApprovalStatusEnum, EmailStatusEnum, GroupEnum
from scheduled_tasks.scheduler import SCHEDULER
from schemas.auth0 import (
    GROUP_ROLE_PATTERN,
    PLATFORM_ROLE_PATTERN,
    get_platform_id_from_role_name,
)
from schemas.biocommons import Auth0UserData

EMAIL_QUEUE_BATCH_SIZE = 25
EMAIL_RETRY_DELAY_SECONDS = 300
EMAIL_JOB_ID_PREFIX = "email_notification_"


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


def _get_group_membership_including_deleted(session: Session, user_id: str, group_id: str) -> GroupMembership | None:
    stmt = (
        select(GroupMembership)
        .execution_options(include_deleted=True)
        .where(GroupMembership.user_id == user_id, GroupMembership.group_id == group_id)
    )
    return session.exec(stmt).one_or_none()


async def process_email_queue(
    batch_size: int = EMAIL_QUEUE_BATCH_SIZE,
    retry_delay_seconds: int = EMAIL_RETRY_DELAY_SECONDS,
) -> int:
    """
    Schedule pending email notifications for delivery.
    """
    logger.info("Processing email notification queue")
    session = next(get_db_session())
    try:
        now = datetime.now(timezone.utc)
        stmt = (
            select(EmailNotification)
            .where(
                EmailNotification.status.in_(
                    [EmailStatusEnum.PENDING, EmailStatusEnum.FAILED]
                ),
                or_(
                    EmailNotification.send_after.is_(None),
                    EmailNotification.send_after <= now,
                ),
            )
            .order_by(EmailNotification.created_at)
            .limit(batch_size)
        )
        notifications = session.exec(stmt).all()
        if not notifications:
            logger.info("No email notifications ready for delivery")
            return 0
        scheduled = 0
        for notification in notifications:
            notification.mark_sending()
            session.add(notification)
            session.flush()
            job_id = f"{EMAIL_JOB_ID_PREFIX}{notification.id}"
            SCHEDULER.add_job(
                send_email_notification,
                args=[notification.id],
                id=job_id,
                replace_existing=True,
                kwargs={"retry_delay_seconds": retry_delay_seconds},
            )
            scheduled += 1
        session.commit()
        logger.info("Queued %d email notifications for delivery", scheduled)
        return scheduled
    finally:
        session.close()


async def send_email_notification(
    notification_id: UUID,
    retry_delay_seconds: int = EMAIL_RETRY_DELAY_SECONDS,
) -> bool:
    """
    Deliver a single queued email notification.
    """
    session = next(get_db_session())
    try:
        notification = session.get(EmailNotification, notification_id)
        if notification is None:
            logger.warning("Email notification %s not found", notification_id)
            return False
        email_service = get_email_service()
        try:
            email_service.send(
                notification.to_address,
                notification.subject,
                notification.body_html,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to send email %s: %s", notification.id, exc
            )
            notification.mark_failed(str(exc), retry_delay_seconds)
            session.add(notification)
            session.commit()
            return False
        else:
            notification.mark_sent()
            session.add(notification)
            session.commit()
            return True
    finally:
        session.close()


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


class MembershipSyncStatus(BaseModel):
    created: bool
    restored: bool
    status_changed: bool

    def is_changed(self) -> bool:
        return self.created or self.restored or self.status_changed


async def sync_group_memberships_for_role(role: RoleData, auth0_client: Auth0Client, session: Session):
    """
    Sync memberships and membership status for a role
    """
    logger.info(f"Syncing Auth0 role {role.name} memberships")
    group = BiocommonsGroup.get_by_id(role.name, session)
    if group is None:
        logger.info(f"  Group {role.name} not found in DB, skipping")
        return
    role_users = auth0_client.get_all_role_users(role_id=role.id)
    # Add or restore memberships that are in Auth0 but not in DB
    for role_user in role_users:
        sync_status = MembershipSyncStatus(created=False, restored=False, status_changed=False)
        auth0_user = auth0_client.get_user(role_user.user_id)
        db_user, _, _ = _ensure_user_from_auth0(session, auth0_user)
        group_membership = _get_group_membership_including_deleted(session, db_user.id, role.name)
        # No membership found in DB
        if group_membership is None:
            sync_status.created = True
            group_membership = GroupMembership(
                group_id=group.group_id,
                user_id=db_user.id,
                approval_status=ApprovalStatusEnum.APPROVED,
                updated_by_id=None,
            )
            session.add(group_membership)
            session.flush()
        # Deleted membership that needs to be restored
        elif group_membership.is_deleted:
            sync_status.restored = True
            group_membership.restore(session, commit=False)
        # Status in DB doesn't reflect Auth0
        if group_membership.approval_status != ApprovalStatusEnum.APPROVED:
            sync_status.status_changed = True
            group_membership.approval_status = ApprovalStatusEnum.APPROVED
            group_membership.updated_at = datetime.now(timezone.utc)
        session.add(group_membership)
        if sync_status.is_changed():
            group_membership.save_history(session, commit=False)
            if sync_status.created:
                logger.info(f"    Created membership for {db_user.id} -> {group.group_id}")
            elif sync_status.restored:
                logger.info(f"    Restored membership for {db_user.id} -> {group.group_id}")
    # Soft delete memberships that are approved but no longer present
    session.flush()
    all_memberships = session.exec(select(GroupMembership).execution_options(include_deleted=True).where(GroupMembership.group_id == group.group_id)).all()
    all_in_auth0 = {user.user_id for user in role_users}
    for membership in all_memberships:
        if membership.is_deleted:
            continue
        if membership.group_id != role.name:
            continue
        if membership.approval_status != ApprovalStatusEnum.APPROVED:
            continue
        if membership.user_id not in all_in_auth0:
            logger.info(
                f"    Soft deleting membership {membership.user_id} -> {membership.group_id} absent from Auth0"
            )
            membership.delete(session, commit=False)
    session.commit()


async def sync_group_user_roles():
    """
    Sync group memberships for all roles matching the GROUP_ROLE_PATTERN.
    """
    logger.info("Syncing Auth0 user-role assignments for groups")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = [role for role in auth0_client.get_all_roles()
             if re.match(GROUP_ROLE_PATTERN, role.name)]
    for role in roles:
        db_session = next(get_db_session())
        try:
            await sync_group_memberships_for_role(role, auth0_client, db_session)
        finally:
            db_session.close()


def _get_platform_membership_including_deleted(session: Session, user_id: str, platform_id: str) -> PlatformMembership | None:
    stmt = (
        select(PlatformMembership)
        .execution_options(include_deleted=True)
        .where(PlatformMembership.user_id == user_id, PlatformMembership.platform_id == platform_id)
    )
    return session.exec(stmt).one_or_none()


async def sync_platform_memberships_for_role(role: RoleData, auth0_client: Auth0Client, session: Session):
    """
    Sync memberships and membership status for a given platform role
    """
    logger.info(f"Syncing Auth0 role {role.name} platform memberships")
    platform_id = get_platform_id_from_role_name(role.name)
    platform = Platform.get_by_id(platform_id=platform_id, session=session)
    if platform is None:
        logger.warning(f"  Platform {platform_id} for {role.name} not found in DB, skipping")
        return
    role_users = auth0_client.get_all_role_users(role_id=role.id)
    # Add or restore memberships that are in Auth0 but not in DB
    for role_user in role_users:
        sync_status = MembershipSyncStatus(created=False, restored=False, status_changed=False)
        auth0_user = auth0_client.get_user(role_user.user_id)
        db_user, _, _ = _ensure_user_from_auth0(session, auth0_user)
        platform_membership = _get_platform_membership_including_deleted(session, db_user.id, platform_id)
        # No membership found in DB
        if platform_membership is None:
            sync_status.created = True
            platform_membership = PlatformMembership(
                platform_id=platform_id,
                user_id=db_user.id,
                approval_status=ApprovalStatusEnum.APPROVED,
                updated_by_id=None,
            )
            session.add(platform_membership)
            session.flush()
        # Deleted membership that needs to be restored
        elif platform_membership.is_deleted:
            sync_status.restored = True
            platform_membership.restore(session, commit=False)
        # Status in DB doesn't reflect Auth0
        if platform_membership.approval_status != ApprovalStatusEnum.APPROVED:
            sync_status.status_changed = True
            platform_membership.approval_status = ApprovalStatusEnum.APPROVED
            platform_membership.updated_at = datetime.now(timezone.utc)
        session.add(platform_membership)
        if sync_status.is_changed():
            platform_membership.save_history(session, commit=False)
            if sync_status.created:
                logger.info(f"    Created membership for {db_user.id} -> {platform_id}")
            elif sync_status.restored:
                logger.info(f"    Restored membership for {db_user.id} -> {platform_id}")
    # Soft delete memberships that are approved but no longer present
    session.flush()
    all_memberships = session.exec(select(PlatformMembership).execution_options(include_deleted=True).where(PlatformMembership.platform_id == platform_id)).all()
    all_in_auth0 = {user.user_id for user in role_users}
    for membership in all_memberships:
        if membership.is_deleted:
            continue
        if membership.approval_status != ApprovalStatusEnum.APPROVED:
            continue
        if membership.user_id not in all_in_auth0:
            logger.info(
                f"    Soft deleting membership {membership.user_id} -> {membership.platform_id} absent from Auth0"
            )
            membership.delete(session, commit=False)
    session.commit()


async def sync_platform_user_roles():
    logger.info("Syncing Auth0 user-role assignments for platforms")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    roles = [role for role in auth0_client.get_all_roles()
             if re.match(PLATFORM_ROLE_PATTERN, role.name)]
    for role in roles:
        db_session = next(get_db_session())
        try:
            await sync_platform_memberships_for_role(role, auth0_client, db_session)
        finally:
            db_session.close()


# Allow changing the groups argument for easy testing
async def populate_db_groups(groups=GroupEnum):
    logger.info("Populating DB groups")
    db_session = next(get_db_session())
    try:
        with db_session.begin():
            for group in groups:
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
    logger.info("Populating platforms from Auth0 roles")
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
                    Platform.create_from_auth0_role(db_role, db_session, commit=False)
                else:
                    logger.info(f"  Updating platform {platform_id} (if needed)")
                    platform.update_from_auth0_role(db_role, db_session, commit=False)
        db_session.commit()
    finally:
        db_session.close()
