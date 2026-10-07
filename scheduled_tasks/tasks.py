import asyncio
import json
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from httpx2 import HTTPStatusError
from loguru import logger
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlmodel import Session

from auth.management import get_management_token
from auth.ses import get_email_service
from auth0.client import Auth0Client
from config import get_settings
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    EmailChangeOtp,
    EmailNotification,
    Platform,
)
from db.setup import get_db_session
from db.types import (
    GROUP_NAMES,
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
from scheduled_tasks.scheduler import EMAIL_QUEUE_EXECUTOR, SCHEDULER
from scheduled_tasks.sync.memberships import (
    sync_group_memberships_for_role,
    sync_platform_memberships_for_role,
)
from scheduled_tasks.sync.users import (
    Auth0ExportIdentityIndex,
    soft_delete_users_missing_from_auth0,
    sync_exported_users,
)
from schemas.auth0 import (
    GROUP_ROLE_PATTERN,
    PLATFORM_ROLE_PATTERN,
    get_platform_id_from_role_name,
)
from schemas.biocommons import Auth0Identity, BiocommonsUserAccountType


class ExportedUser(BaseModel):
    user_id: str
    email: str
    email_verified: bool | None = None
    username: str | None = None
    metadata_username: str | None = None
    blocked: bool = False
    updated_at: datetime
    account_type: BiocommonsUserAccountType = BiocommonsUserAccountType.AUTH0
    aaf_only: bool | None = None
    aaf_registration_complete: bool | None = None
    linking_completed: bool | None = None
    linking_completed_at: datetime | None = None
    identities: list[Auth0Identity] = Field(default_factory=list)

    @field_validator("email_verified", "blocked", mode="before")
    @classmethod
    def _empty_to_false(cls, value: Any) -> Any:
        if isinstance(value, str):
            if value == "":
                return False
        return value

    @field_validator(
        "aaf_only",
        "aaf_registration_complete",
        "linking_completed",
        "linking_completed_at",
        "metadata_username",
        mode="before",
    )
    @classmethod
    def _empty_to_none(cls, value: Any) -> Any:
        if isinstance(value, str) and value == "":
            return None
        return value

    @model_validator(mode="after")
    def _infer_aaf_account_type(self) -> "ExportedUser":
        if (
            self.account_type == BiocommonsUserAccountType.AUTH0
            and (self.aaf_only is True or self.aaf_registration_complete is True)
        ):
            self.account_type = BiocommonsUserAccountType.AAF
        return self


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
                send_email_notification_job,
                args=[notification.id],
                id=job_id,
                executor=EMAIL_QUEUE_EXECUTOR,
                jobstore="email",
                max_instances=1,
                replace_existing=True,
            )
            scheduled += 1
        session.commit()
        logger.info("Queued %d email notifications for delivery", scheduled)
        return scheduled
    finally:
        session.close()


def process_email_queue_job(batch_size: int = EMAIL_QUEUE_BATCH_SIZE) -> int:
    """
    Run the email queue poller in a worker thread so it does not block the main scheduler loop.
    """
    return asyncio.run(process_email_queue(batch_size=batch_size))


def sync_auth0_roles_job() -> None:
    asyncio.run(sync_auth0_roles())


def sync_auth0_users_job(batch_size: int = 500) -> None:
    asyncio.run(sync_auth0_users(batch_size=batch_size))


def sync_group_user_roles_job(batch_size: int = 500) -> None:
    asyncio.run(sync_group_user_roles(batch_size=batch_size))


def sync_platform_user_roles_job(batch_size: int = 500) -> None:
    asyncio.run(sync_platform_user_roles(batch_size=batch_size))


def populate_db_groups_job() -> None:
    asyncio.run(populate_db_groups())


def populate_platforms_from_auth0_job() -> None:
    asyncio.run(populate_platforms_from_auth0())


def cleanup_email_otps_job() -> None:
    asyncio.run(cleanup_email_otps())


def send_email_notification_job(notification_id: UUID) -> bool:
    return asyncio.run(send_email_notification(notification_id))


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


def parse_auth0_json_export(path: Path) -> list[ExportedUser]:
    """
    Parse Auth0 JSON-compatible export data.

    Auth0 JSON-compatible exports are NDJSON: one JSON object per line.
    """
    parsed = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parsed.append(ExportedUser(**json.loads(line)))
    return parsed


async def export_auth0_users(
    auth0_client: Auth0Client,
    connection_id: str | None = None,
    filename: str | None = None,
) -> list[ExportedUser]:
    """
    Export all users and return a parsed list.

    Normally saves to a temp file that is immediately deleted. Specify
    filename to save instead.
    """
    fields =  [
        {"name": "user_id"},
        {"name": "email"},
        {"name": "email_verified"},
        {"name": "username"},
        {"name": "app_metadata.username", "export_as": "metadata_username"},
        {"name": "blocked"},
        {"name": "updated_at"},
        {"name": "app_metadata.account_type", "export_as": "account_type"},
        {"name": "app_metadata.aaf_only", "export_as": "aaf_only"},
        {
            "name": "app_metadata.aaf_registration_complete",
            "export_as": "aaf_registration_complete",
        },
        {"name": "app_metadata.linking_completed", "export_as": "linking_completed"},
        {
            "name": "app_metadata.linking_completed_at",
            "export_as": "linking_completed_at",
        },
        {"name": "identities"},
    ]
    if filename is not None:
        path = Path(filename)
        try:
            auth0_client.export_and_download_users(
                download_path=path,
                fields=fields,
                format="json",
                connection_id=connection_id,
            )
        except HTTPStatusError as exc:
            logger.error(f"Failed to export Auth0 users: {exc}")
            logger.error(f"Response: {exc.response.content}")
            raise exc
        users = parse_auth0_json_export(path)
    else:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "auth0_users.json"

            logger.info(f"Exporting Auth0 users to {temp_path}")
            try:
                auth0_client.export_and_download_users(
                    download_path=temp_path,
                    fields=fields,
                    format="json",
                    connection_id=connection_id,
                )
            except HTTPStatusError as exc:
                logger.error(f"Failed to export Auth0 users: {exc}")
                logger.error(f"Response: {exc.response.content}")
                raise exc
            users = parse_auth0_json_export(temp_path)
            # Delete export
            temp_path.unlink()
    return users


async def sync_auth0_users(batch_size: int = 500):
    logger.info("Syncing Auth0 users")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    with Auth0Client(domain=settings.auth0_domain, management_token=token) as auth0_client:
        # Not specifying connection ID: export both AAF and Auth0 connections
        users = await export_auth0_users(auth0_client)
        db_session = next(get_db_session())
        try:
            summary = sync_exported_users(
                db_session,
                users,
                batch_size=batch_size,
                commit=True,
            )
            summary.soft_deleted += soft_delete_users_missing_from_auth0(
                db_session,
                Auth0ExportIdentityIndex.from_user_list(users),
                auth0_client=auth0_client,
                batch_size=batch_size,
                commit=True,
            )
            logger.info("Auth0 user sync summary: {}", summary.model_dump())
            return summary
        finally:
            db_session.close()


async def sync_auth0_roles():
    logger.info("Syncing Auth0 roles")
    logger.info("Setting up Auth0 client")
    settings = get_settings()
    token = get_management_token(settings=settings)
    with Auth0Client(domain=settings.auth0_domain, management_token=token) as auth0_client:
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

    Each admin role is linked to a single resource. SBP is split into a service
    admin role (biocommons/role/sbp/admin -> SBP platform) and a bundle admin role
    (biocommons/role/sbp_workflow_execution/admin -> SBP bundle group).
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


async def sync_group_user_roles(batch_size: int = 500):
    """
    Sync group memberships for all roles matching the GROUP_ROLE_PATTERN.
    """
    logger.info("Syncing Auth0 user-role assignments for groups")
    settings = get_settings()
    token = get_management_token(settings=settings)
    with Auth0Client(domain=settings.auth0_domain, management_token=token) as auth0_client:
        roles = [role for role in auth0_client.get_all_roles()
                 if re.match(GROUP_ROLE_PATTERN, role.name)]
        if not settings.sbp_enabled:
            roles = [role for role in roles if role.name != GroupEnum.SBP.value]
        for role in roles:
            db_session = next(get_db_session())
            try:
                summary = await sync_group_memberships_for_role(
                    role,
                    auth0_client,
                    db_session,
                    batch_size=batch_size,
                )
                logger.info(
                    "Group membership sync summary for {}: {}",
                    role.name,
                    summary.model_dump(),
                )
            finally:
                db_session.close()


async def sync_platform_user_roles(batch_size: int = 500):
    logger.info("Syncing Auth0 user-role assignments for platforms")
    settings = get_settings()
    token = get_management_token(settings=settings)
    with Auth0Client(domain=settings.auth0_domain, management_token=token) as auth0_client:
        roles = [role for role in auth0_client.get_all_roles()
                 if re.match(PLATFORM_ROLE_PATTERN, role.name)]
        if not settings.sbp_enabled:
            roles = [
                role for role in roles
                if get_platform_id_from_role_name(role.name) != PlatformEnum.SBP.value
            ]
        for role in roles:
            db_session = next(get_db_session())
            try:
                summary = await sync_platform_memberships_for_role(
                    role,
                    auth0_client,
                    db_session,
                    batch_size=batch_size,
                )
                logger.info(
                    "Platform membership sync summary for {}: {}",
                    role.name,
                    summary.model_dump(),
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
    with Auth0Client(domain=settings.auth0_domain, management_token=token) as auth0_client:
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
