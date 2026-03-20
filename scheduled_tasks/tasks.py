import csv
import math
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from httpx import HTTPStatusError
from loguru import logger
from pydantic import BaseModel, field_validator
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from auth.management import get_management_token
from auth.ses import get_email_service
from auth0.client import Auth0Client, RoleData
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    EmailChangeOtp,
    EmailNotification,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import (
    GROUP_NAMES,
    ApprovalStatusEnum,
    EmailStatusEnum,
    GroupEnum,
    PlatformEnum,
)
from scheduled_tasks.email_retry import (
    EMAIL_JOB_ID_PREFIX,
    EMAIL_MAX_ATTEMPTS,
    EMAIL_QUEUE_BATCH_SIZE,
    EMAIL_RETRY_WINDOW_SECONDS,
    can_schedule_notification,
    is_retryable_email_error,
    next_retry_delay_seconds,
    retry_deadline,
)
from scheduled_tasks.scheduler import SCHEDULER
from schemas.auth0 import (
    GROUP_ROLE_PATTERN,
    PLATFORM_ROLE_PATTERN,
    get_platform_id_from_role_name,
)
from schemas.biocommons import Auth0UserData


def chunked[T](items: list[T], size: int) -> list[list[T]]:
    """
    Split a list into chunks of a given size.
    """
    return [items[i:i + size] for i in range(0, len(items), size)]


class ExportedUser(BaseModel):
    user_id: str
    email: str
    email_verified: bool
    username: str | None
    blocked: bool
    updated_at: datetime

    @field_validator("email_verified", "blocked", mode="before")
    @classmethod
    def _empty_to_false(cls, value: Any) -> Any:
        if isinstance(value, str):
            if value == "":
                return False
        return value


class UserSyncConflictError(ValueError):
    """Raised when Auth0 user data conflicts with an existing DB user."""


def _find_conflicting_user_by_username(
    session: Session, user_id: str, username: str
) -> BiocommonsUser | None:
    for pending in session.new:
        if (
            isinstance(pending, BiocommonsUser)
            and pending.id != user_id
            and pending.username == username
        ):
            return pending
    with session.no_autoflush:
        return BiocommonsUser.get_by_username(
            username=username,
            session=session,
            include_deleted=True,
            exclude_user_id=user_id,
        )


def _find_conflicting_user_by_email(
    session: Session, user_id: str, email: str
) -> BiocommonsUser | None:
    for pending in session.new:
        if (
            isinstance(pending, BiocommonsUser)
            and pending.id != user_id
            and pending.email == email
        ):
            return pending
    with session.no_autoflush:
        return BiocommonsUser.get_by_email(
            email=email,
            session=session,
            include_deleted=True,
            exclude_user_id=user_id,
        )


def _ensure_user_from_auth0(
        session: Session,
        user_data: Auth0UserData | ExportedUser
) -> tuple[BiocommonsUser | None, bool, bool]:
    """
    Ensure the Auth0 user exists in the database, creating or restoring if required.

    Returns a tuple of (user, created, restored).
    """
    username = user_data.username
    if username is not None:
        username_conflict = _find_conflicting_user_by_username(
            session=session,
            user_id=user_data.user_id,
            username=username,
        )
        if username_conflict is not None:
            raise UserSyncConflictError(
                "Auth0 username conflict for user "
                f"{user_data.user_id}: username '{username}' is already used by {username_conflict.id}."
            )

    email_conflict = _find_conflicting_user_by_email(
        session=session,
        user_id=user_data.user_id,
        email=user_data.email,
    )
    if email_conflict is not None:
        raise UserSyncConflictError(
            "Auth0 email conflict for user "
            f"{user_data.user_id}: email '{user_data.email}' is already used by {email_conflict.id}."
        )

    created = False
    restored = False
    user = BiocommonsUser.get_by_id(user_data.user_id, session)
    # Blocked users are soft deleted and should stay soft deleted
    if user_data.blocked:
        deleted_user = BiocommonsUser.get_deleted_by_id(session, user_data.user_id)
        if deleted_user is not None:
            user = deleted_user
        # Blocked user not in the DB
        elif user is None:
            return None, False, False
    elif user is None:
        user = BiocommonsUser.get_deleted_by_id(session, user_data.user_id)
        if user is not None:
            restored = True
            user.restore(session, commit=False)

            user.save_history(
                session,
                change="restored_from_auth0",
                reason="User restored during Auth0 sync",
                updated_by=None
            )
        else:
            created = True
            user = BiocommonsUser.from_auth0_data(user_data)
    session.add(user)

    # Save history entry if updating from Auth0 sync
    if not created:
        has_changes = user.email != user_data.email
        if user_data.username is not None and user.username != user_data.username:
            has_changes = True

        if has_changes:
            user.save_history(
                session,
                change="auth0_sync",
                reason="User data updated from Auth0",
                updated_by=None
            )

    user.email = user_data.email
    if username is not None:
        user.username = username
    user.email_verified = user_data.email_verified
    return user, created, restored


def _get_group_membership_including_deleted(session: Session, user_id: str, group_id: str) -> GroupMembership | None:
    return GroupMembership.get_by_user_id_and_group_id(
        user_id,
        group_id,
        session,
        include_deleted=True,
    )


async def process_email_queue(
    batch_size: int = EMAIL_QUEUE_BATCH_SIZE,
) -> int:
    """
    Schedule pending email notifications for delivery.
    """
    logger.info("Processing email notification queue")
    session = next(get_db_session())
    try:
        now = datetime.now(timezone.utc)
        notifications = EmailNotification.get_ready_for_delivery(
            session,
            now=now,
            batch_size=batch_size,
        )
        if not notifications:
            logger.info("No email notifications ready for delivery")
            return 0
        scheduled = 0
        for notification in notifications:
            if not can_schedule_notification(notification, now):
                logger.info(
                    "Skipping email %s: retry window exhausted or max attempts reached",
                    notification.id,
                )
                notification.status = EmailStatusEnum.FAILED
                notification.send_after = None
                session.add(notification)
                continue
            notification.mark_sending()
            session.add(notification)
            session.flush()
            job_id = f"{EMAIL_JOB_ID_PREFIX}{notification.id}"
            SCHEDULER.add_job(
                send_email_notification,
                args=[notification.id],
                id=job_id,
                replace_existing=True,
            )
            scheduled += 1
        session.commit()
        logger.info("Queued %d email notifications for delivery", scheduled)
        return scheduled
    finally:
        session.close()


async def send_email_notification(
    notification_id: UUID,
) -> bool:
    """
    Deliver a single queued email notification.
    """
    session = next(get_db_session())
    settings = get_settings()
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
                settings=settings,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to send email %s: %s", notification.id, exc)
            now = datetime.now(timezone.utc)
            should_retry = is_retryable_email_error(exc)
            deadline = retry_deadline(notification)
            if deadline is None:
                deadline = now + timedelta(seconds=EMAIL_RETRY_WINDOW_SECONDS)
            attempts_remaining = notification.attempts < EMAIL_MAX_ATTEMPTS
            if (
                should_retry
                and attempts_remaining
                and now < deadline
            ):
                delay_seconds = next_retry_delay_seconds()
                retry_time = now + timedelta(seconds=delay_seconds)
                if retry_time <= deadline:
                    notification.schedule_retry(str(exc), retry_time)
                    session.add(notification)
                    session.commit()
                    return False
            notification.mark_failed(str(exc))
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


def parse_auth0_export(path: Path) -> list[ExportedUser]:
    """
    Parse Auth0 export csv into a list of ExportedUser objects.

    Auth0 export prepends string fields with ' so these need to be stripped
    """
    parsed = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed.append(ExportedUser(
                user_id=row["user_id"].lstrip("'"),
                email=row["email"].lstrip("'"),
                email_verified=row["email_verified"],
                username=row["username"].lstrip("'") or None,
                blocked=row["blocked"],
                updated_at=row["updated_at"],
            ))
    return parsed


async def export_auth0_users(auth0_client: Auth0Client) -> list[ExportedUser]:
    """
    Export all users to CSV and return a list
    """
    fields = [
        {"name": "user_id"},
        {"name": "email"},
        {"name": "email_verified"},
        {"name": "username"},
        {"name": "blocked"},
        {"name": "updated_at"}
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "auth0_users.csv"

        logger.info(f"Exporting Auth0 users to {temp_path}")
        try:
            auth0_client.export_and_download_users(download_path=temp_path, fields=fields)
        except HTTPStatusError as exc:
            logger.error(f"Failed to export Auth0 users: {exc}")
            logger.error(f"Response: {exc.response.content}")
            raise exc
        users = parse_auth0_export(temp_path)
        # Delete export
        temp_path.unlink()
    return users


async def sync_auth0_users():
    logger.info("Syncing Auth0 users")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    users = await export_auth0_users(auth0_client)
    db_session = next(get_db_session())
    auth0_user_ids: set[str] = set()
    try:
        batch_size = 500
        total_batches = math.ceil(len(users) / batch_size)
        for batch_index, user_batch in enumerate(chunked(users, batch_size)):
            logger.info(f"Syncing Auth0 user batch {batch_index + 1}/{total_batches}")
            for user in user_batch:
                auth0_user_ids.add(user.user_id)
            await update_auth0_users_batch(user_batch)
        # Soft delete any users no longer present in Auth0
        existing_users = BiocommonsUser.list_all(db_session)
        for db_user in existing_users:
            if db_user.id not in auth0_user_ids:
                # Double check if in Auth0 before deleting (something could have changed since export)
                try:
                    auth0_client.get_user(db_user.id)
                    time.sleep(0.5)
                except HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        logger.info(f"Soft deleting user {db_user.id} not found in Auth0")
                        db_user.delete(db_session, reason="auth0_sync", commit=False)
                    else:
                        logger.warning(f"Failed to check if user {db_user.id} exists in Auth0: {exc}")
        db_session.commit()
    finally:
        db_session.close()


async def update_auth0_users_batch(users: list[Auth0UserData | ExportedUser]) -> dict[str, int]:
    updated = 0
    skipped = 0

    session = next(get_db_session())
    try:
        for user_data in users:
            try:
                with session.begin_nested():
                    success = update_auth0_user(user_data, session=session)
            except (UserSyncConflictError, IntegrityError) as exc:
                # Roll back this user's changes and continue with the next user
                logger.warning(
                    "Error while updating Auth0 user %r: %s",
                    getattr(user_data, "user_id", None),
                    exc,
                )
                success = False
            if success:
                updated += 1
            else:
                skipped += 1
        session.commit()
    finally:
        session.close()

    logger.info(
        f"Processed Auth0 user batch: {updated} updated, {skipped} skipped, total={len(users)}"
    )
    return {"updated": updated, "skipped": skipped}


def update_auth0_user(user_data: Auth0UserData | ExportedUser, session: Session):
    """
    Update a single user from Auth0. Called by update_auth0_users_batch, which handles session
    creation/committing
    """
    db_user, created, restored = _ensure_user_from_auth0(session, user_data)
    if db_user is None:
        if user_data.blocked:
            logger.warning(f"Blocked {user_data.user_id} not found in DB, skipping")
        else:
            logger.warning(f"User {user_data.user_id} not found in DB, skipping")
        return False
    if created:
        logger.debug(f"User {user_data.user_id} created in DB")
    elif restored:
        logger.debug(f"User {user_data.user_id} restored from soft delete")
    else:
        logger.debug(f"User {user_data.user_id} exists in DB, updating fields")
    if session.is_modified(db_user):
        logger.debug(f"User data changed for {user_data.user_id}, updating in DB")
    else:
        logger.debug(f"User data unchanged for {user_data.user_id}")
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
    auth0_role_ids: set[str] = set()
    db_roles_by_name: dict[str, Auth0Role] = {}
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
            db_roles_by_name[db_role.name] = db_role
        # Soft delete roles missing from Auth0
        db_session.flush()
        existing_roles = Auth0Role.get_all(db_session)
        for db_role in existing_roles:
            if db_role.id not in auth0_role_ids:
                logger.info(f"    Soft deleting role {db_role.name} ({db_role.id}) absent from Auth0")
                db_role.delete(db_session, commit=False)
        link_admin_roles(db_session, db_roles_by_name)
        db_session.commit()
    finally:
        db_session.close()


def link_admin_roles(session: Session, db_roles_by_name: dict[str, Auth0Role]) -> None:
    """
    Link admin roles to platforms/groups based on naming conventions:
      - Platform admin roles: biocommons/role/{platform_id}/admin
      - Group admin roles:    biocommons/role/{group_short_id}/admin where group_id is biocommons/group/{group_short_id}
    """
    platform_admin_pattern = re.compile(
        r"^biocommons/role/(?P<platform_id>[a-z0-9_]+)/admin$", re.IGNORECASE
    )
    group_admin_pattern = re.compile(
        r"^biocommons/role/(?P<group_short_id>[a-z0-9_]+)/admin$", re.IGNORECASE
    )

    for role_name, role in db_roles_by_name.items():
        platform_match = platform_admin_pattern.match(role_name)
        if platform_match:
            pid = platform_match.group("platform_id").lower()
            try:
                platform_enum = PlatformEnum(pid)
            except ValueError:
                platform = None
            else:
                platform = Platform.get_by_id(platform_enum, session)
            if platform:
                if role not in platform.admin_roles:
                    platform.admin_roles.append(role)
                    session.add(platform)
                continue

        group_match = group_admin_pattern.match(role_name)
        if group_match:
            gid_short = group_match.group("group_short_id").lower()
            full_group_id = f"biocommons/group/{gid_short}"
            group = BiocommonsGroup.get_by_id(full_group_id, session)
            if group and role not in group.admin_roles:
                group.admin_roles.append(role)
                session.add(group)


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
        if auth0_user.blocked:
            logger.info(f"    User {auth0_user.user_id} blocked, skipping")
            continue
        try:
            with session.begin_nested():
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
        except UserSyncConflictError as exc:
            logger.warning(f"    Skipping user {auth0_user.user_id} for group {group.group_id}: {exc}")
            continue
    # Soft delete memberships that are approved but no longer present
    session.flush()
    all_memberships = GroupMembership.list_by_group_id(
        group.group_id,
        session,
        include_deleted=True,
    )
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
    return PlatformMembership.get_by_user_id_and_platform_id(
        user_id,
        platform_id,
        session,
        include_deleted=True,
    )


async def sync_platform_memberships_for_role(
        role: RoleData,
        auth0_client: Auth0Client,
        session: Session,
        exported_users_by_id: dict[str, ExportedUser],
):
    """
    Sync memberships and membership status for a given platform role
    """
    logger.info(f"Syncing Auth0 role {role.name} platform memberships")
    platform_id = get_platform_id_from_role_name(role.name)
    platform = Platform.get_by_id(platform_id=platform_id, session=session)
    if platform is None:
        logger.warning(f"  Platform {platform_id} for {role.name} not found in DB, skipping")
        return
    # Add or restore memberships that are in Auth0 but not in DB
    created = 0
    restored = 0
    role_users = []
    for user_batch in auth0_client.get_all_role_users_generator(role_id=role.id):
        for role_user in user_batch:
            role_users.append(role_user)
            sync_status = MembershipSyncStatus(created=False, restored=False, status_changed=False)
            auth0_user = exported_users_by_id.get(role_user.user_id)
            if auth0_user is None:
                logger.warning(f"    User {role_user.user_id} not found in exported users, skipping")
                continue
            if auth0_user.blocked:
                logger.info(f"    User {auth0_user.user_id} blocked, skipping")
                continue
            try:
                with session.begin_nested():
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
                            created += 1
                            logger.debug(f"    Created membership for {db_user.id} -> {platform_id}")
                        elif sync_status.restored:
                            restored += 1
                            logger.debug(f"    Restored membership for {db_user.id} -> {platform_id}")
            except (UserSyncConflictError, IntegrityError) as exc:
                logger.warning(f"    Skipping user {role_user.user_id} for platform {platform_id}: {exc}")
                continue
        session.commit()
    logger.info(f"  Created {created} new memberships, restored {restored} memberships")
    # Soft delete memberships that are approved but no longer present
    all_in_auth0 = {user.user_id for user in role_users}
    with session.begin():
        all_memberships = PlatformMembership.list_by_platform_id(
            platform_id,
            session,
            include_deleted=True,
        )
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


async def sync_platform_user_roles():
    logger.info("Syncing Auth0 user-role assignments for platforms")
    settings = get_settings()
    token = get_management_token(settings=settings)
    auth0_client = Auth0Client(domain=settings.auth0_domain, management_token=token)
    exported_users = await export_auth0_users(auth0_client)
    exported_users_by_id = {user.user_id: user for user in exported_users}
    roles = [role for role in auth0_client.get_all_roles()
             if re.match(PLATFORM_ROLE_PATTERN, role.name)]
    for role in roles:
        db_session = next(get_db_session())
        try:
            await sync_platform_memberships_for_role(
                role,
                auth0_client,
                db_session,
                exported_users_by_id=exported_users_by_id
            )
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
        # Ensure admin roles are linked now that groups exist (sync_auth0_roles may have run earlier)
        roles_by_name = {role.name: role for role in Auth0Role.get_all(db_session)}
        link_admin_roles(db_session, roles_by_name)
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
                if db_role is None:
                    db_role = Auth0Role.get_or_create_by_id(role.id, db_session, auth0_client)
                platform_id = get_platform_id_from_role_name(role.name)
                platform = Platform.get_by_id(platform_id=platform_id, session=db_session)
                if platform is None:
                    logger.info(f"  Creating platform {platform_id}")
                    Platform.create_from_auth0_role(db_role, db_session, commit=False)
                else:
                    logger.info(f"  Updating platform {platform_id} (if needed)")
                    platform.update_from_auth0_role(db_role, db_session, commit=False)
        db_session.commit()
        roles_by_name = {role.name: role for role in Auth0Role.get_all(db_session)}
        link_admin_roles(db_session, roles_by_name)
        db_session.commit()
    finally:
        db_session.close()


async def cleanup_email_otps():
    """Purge expired or used email change OTPs."""
    logger.info("Cleaning up expired email change OTPs")
    db_session = next(get_db_session())
    try:
        now = datetime.now(timezone.utc)
        expired = EmailChangeOtp.get_expired_or_inactive(db_session, now=now)
        if not expired:
            return
        for otp in expired:
            db_session.delete(otp)
        db_session.commit()
    finally:
        db_session.close()
