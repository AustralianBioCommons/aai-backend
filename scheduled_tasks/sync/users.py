from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, Self

from httpx2 import HTTPStatusError
from loguru import logger
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from auth0.client import Auth0Client
from db.models import BiocommonsUser, BiocommonsUserHistory
from scheduled_tasks.sync.summaries import SyncSummary
from schemas.biocommons import Auth0Identity, Auth0UserData, BiocommonsUserAccountType


class UserSyncConflictError(ValueError):
    """Raised when synced user data conflicts with another user."""


class UserSyncValidationError(ValueError):
    """Raised when synced user data is incomplete for its account type."""


class ExportedUserLike(Protocol):
    """Minimum shape expected from an Auth0 export row."""

    user_id: str
    email: str
    email_verified: bool | None
    username: str | None
    metadata_username: str | None
    blocked: bool | None
    updated_at: datetime | None
    account_type: BiocommonsUserAccountType | str | None
    aaf_only: bool | None
    aaf_registration_complete: bool | None
    linking_completed: bool | None
    linking_completed_at: datetime | None
    identities: list[Auth0Identity]


class Auth0ExportIdentityIndex(BaseModel):
    """Lookup data derived from an Auth0 user export."""

    exported_user_ids: set[str]
    exported_identity_ids: set[str]
    exported_emails: set[str]

    @classmethod
    def from_user_list(cls, users: Iterable[ExportedUserLike]) -> Self:
        exported_user_ids: set[str] = set()
        exported_identity_ids: set[str] = set()
        exported_emails: set[str] = set()

        for user in users:
            exported_user_ids.add(user.user_id)
            exported_emails.add(user.email.lower())
            for identity in user.identities:
                exported_identity_ids.add(format_auth0_identity_id(identity))

        return cls(
            exported_user_ids=exported_user_ids,
            exported_identity_ids=exported_identity_ids,
            exported_emails=exported_emails,
        )


class UserSyncType(StrEnum):
    AUTH0 = "auth0"
    AAF_ONLY = "aaf_only"
    AAF_LINKED = "aaf_linked"
    AAF_UNKNOWN = "aaf_unknown"


class UserSyncRecord(BaseModel):
    """Normalized Auth0 user data used by the user sync service."""

    user_id: str
    email: str
    username: str | None = None
    metadata_username: str | None = None
    email_verified: bool = False
    blocked: bool = False
    account_type: BiocommonsUserAccountType = BiocommonsUserAccountType.AUTH0
    updated_at: datetime | None = None
    aaf_only: bool | None = None
    aaf_registration_complete: bool | None = None
    linking_completed: bool | None = None
    linking_completed_at: datetime | None = None

    model_config = ConfigDict(use_enum_values=False)

    @property
    def sync_type(self) -> UserSyncType:
        if self.account_type == BiocommonsUserAccountType.AUTH0:
            return UserSyncType.AUTH0
        if self.aaf_only is True:
            return UserSyncType.AAF_ONLY
        if self.linking_completed is True:
            return UserSyncType.AAF_LINKED
        return UserSyncType.AAF_UNKNOWN


@dataclass(frozen=True)
class UserSyncPolicy:
    """Account-type-specific user sync behavior."""
    email_verified_source: Literal["auth0", "always_true"]


USER_SYNC_POLICIES: dict[BiocommonsUserAccountType, UserSyncPolicy] = {
    BiocommonsUserAccountType.AUTH0: UserSyncPolicy(
        email_verified_source="auth0",
    ),
    BiocommonsUserAccountType.AAF: UserSyncPolicy(
        email_verified_source="always_true",
    ),
}


class UserSyncAction(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    RESTORED = "restored"
    SOFT_DELETED = "soft_deleted"
    SKIPPED_UNCHANGED = "skipped_unchanged"
    SKIPPED_BLOCKED_MISSING = "skipped_blocked_missing"


class UserSyncResult(BaseModel):
    action: UserSyncAction
    user: BiocommonsUser | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class UserSyncSummary(SyncSummary):
    total: int = 0
    created: int = 0
    updated: int = 0
    restored: int = 0
    soft_deleted: int = 0
    skipped_unchanged: int = 0
    skipped_blocked_missing: int = 0
    skipped_invalid: int = 0
    conflicted: int = 0

    def add_result(self, result: UserSyncResult) -> None:
        self.total += 1
        match result.action:
            case UserSyncAction.CREATED:
                self.created += 1
            case UserSyncAction.UPDATED:
                self.updated += 1
            case UserSyncAction.RESTORED:
                self.restored += 1
            case UserSyncAction.SOFT_DELETED:
                self.soft_deleted += 1
            case UserSyncAction.SKIPPED_UNCHANGED:
                self.skipped_unchanged += 1
            case UserSyncAction.SKIPPED_BLOCKED_MISSING:
                self.skipped_blocked_missing += 1

    def add_invalid(self) -> None:
        self.total += 1
        self.skipped_invalid += 1

    def add_conflict(self) -> None:
        self.total += 1
        self.conflicted += 1


def chunked[T](items: Iterable[T], size: int) -> Iterable[list[T]]:
    """Yield items in batches of ``size``."""
    if size < 1:
        raise ValueError("batch_size must be at least 1")

    batch: list[T] = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def get_user_sync_policy(
    account_type: BiocommonsUserAccountType,
) -> UserSyncPolicy:
    try:
        return USER_SYNC_POLICIES[account_type]
    except KeyError as exc:
        raise UserSyncValidationError(
            f"No user sync policy defined for account type {account_type!r}"
        ) from exc


def normalize_auth0_user(user: Auth0UserData) -> UserSyncRecord:
    """
    Normalize live Auth0 user data into the shape used by the sync service.

    AAF users store the application username in app_metadata during registration,
    while Auth0 database users may expose it as the top-level username.
    """
    account_type = _coerce_auth0_account_type(user)
    username = _select_username(
        account_type=account_type,
        auth0_username=user.username,
        metadata_username=user.app_metadata.username,
    )
    return UserSyncRecord(
        user_id=user.user_id,
        email=str(user.email),
        username=username,
        metadata_username=user.app_metadata.username,
        email_verified=bool(user.email_verified),
        blocked=bool(user.blocked),
        account_type=account_type,
        updated_at=user.updated_at,
        aaf_only=user.app_metadata.aaf_only,
        aaf_registration_complete=user.app_metadata.aaf_registration_complete,
        linking_completed=user.app_metadata.linking_completed,
        linking_completed_at=user.app_metadata.linking_completed_at,
    )


def normalize_exported_user(user: ExportedUserLike) -> UserSyncRecord:
    """Normalize an Auth0 export row into the shape used by the sync service."""
    account_type = _coerce_export_account_type(user)
    username = _select_username(
        account_type=account_type,
        auth0_username=user.username,
        metadata_username=user.metadata_username,
    )
    return UserSyncRecord(
        user_id=user.user_id,
        email=str(user.email),
        username=username,
        metadata_username=user.metadata_username,
        email_verified=bool(user.email_verified),
        blocked=bool(user.blocked),
        account_type=account_type,
        updated_at=user.updated_at,
        aaf_only=user.aaf_only,
        aaf_registration_complete=user.aaf_registration_complete,
        linking_completed=user.linking_completed,
        linking_completed_at=user.linking_completed_at,
    )


def sync_one_user(session: Session, record: UserSyncRecord) -> UserSyncResult:
    """
    Create, update, restore, or soft-delete one DB user from normalized Auth0 data.

    This function owns only ``BiocommonsUser`` rows. It deliberately does not sync
    platform or group memberships.
    """
    policy = get_user_sync_policy(record.account_type)

    if record.blocked:
        return _sync_blocked_user(session, record, policy)

    if record.username is None:
        raise UserSyncValidationError(f"No username found for user {record.user_id!r}")
    _check_user_conflicts(session, record)

    user = BiocommonsUser.get_by_id(
        record.user_id,
        session,
        include_deleted=True,
    )

    if user is None:
        user = _create_user(session, record, policy)
        return UserSyncResult(action=UserSyncAction.CREATED, user=user)

    if user.is_deleted:
        user.restore(session, commit=False)
        user.save_history(
            session,
            change="restored_from_auth0",
            reason="User restored during Auth0 sync",
            updated_by=None,
            commit=False,
        )
        _apply_record_to_user(user, record, policy)
        session.add(user)
        return UserSyncResult(action=UserSyncAction.RESTORED, user=user)

    if not _user_needs_update(user, record, policy):
        return UserSyncResult(action=UserSyncAction.SKIPPED_UNCHANGED, user=user)

    user.save_history(
        session,
        change="auth0_sync",
        reason="User data updated from Auth0",
        updated_by=None,
        commit=False,
    )
    _apply_record_to_user(user, record, policy)
    session.add(user)
    return UserSyncResult(action=UserSyncAction.UPDATED, user=user)


def sync_user_batch(
    session: Session,
    records: Iterable[UserSyncRecord],
) -> UserSyncSummary:
    """
    Sync a batch of users.

    Each user is wrapped in a nested transaction so one conflict does not discard
    the rest of the batch.
    """
    summary = UserSyncSummary()
    for record in records:
        try:
            with session.begin_nested():
                result = sync_one_user(session, record)
        except UserSyncValidationError as exc:
            logger.warning("Skipping invalid synced user {}: {}", record.user_id, exc)
            summary.add_invalid()
        except (UserSyncConflictError, IntegrityError) as exc:
            logger.warning("Skipping conflicted synced user {}: {}", record.user_id, exc)
            summary.add_conflict()
        else:
            summary.add_result(result)
    return summary


def sync_users_from_records(
    session: Session,
    records: Iterable[UserSyncRecord],
    *,
    batch_size: int = 500,
    commit: bool = True,
) -> UserSyncSummary:
    """Sync normalized user records, committing after each batch by default."""
    summary = UserSyncSummary()
    for batch in chunked(records, batch_size):
        summary.merge(sync_user_batch(session, batch))
        if commit:
            session.commit()
    return summary


def sync_exported_users(
    session: Session,
    users: Iterable[ExportedUserLike],
    *,
    batch_size: int = 500,
    commit: bool = True,
) -> UserSyncSummary:
    """Normalize and sync users from an Auth0 export."""
    records = (normalize_exported_user(user) for user in users)
    return sync_users_from_records(
        session,
        records,
        batch_size=batch_size,
        commit=commit,
    )


def soft_delete_users_missing_from_auth0(
    session: Session,
    export_index: Auth0ExportIdentityIndex,
    *,
    auth0_client: Auth0Client | None = None,
    batch_size: int = 500,
    commit: bool = True,
    live_lookup_delay_seconds: float = 0.5,
) -> int:
    """
    Soft-delete active DB users whose IDs were absent from an Auth0 export.

    This stays in the user sync module because missing-user deletion is still a
    ``BiocommonsUser`` concern, not a membership concern.
    """
    deleted = 0
    for batch in chunked(BiocommonsUser.list_all(session), batch_size):
        for user in batch:
            if not should_soft_delete_missing_user(user, export_index):
                continue
            if auth0_client is not None:
                try:
                    if user_exists_in_auth0(
                        auth0_client,
                        user,
                        delay_seconds=live_lookup_delay_seconds,
                    ):
                        continue
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to check if user {} exists in Auth0: {}",
                        user.id,
                        exc,
                    )
                    continue
            logger.info("Soft deleting user {} absent from Auth0", user.id)
            user.delete(session, reason="auth0_sync", commit=False)
            deleted += 1
        if commit:
            session.commit()
    return deleted


def format_auth0_identity_id(identity: Auth0Identity) -> str:
    """
    Reconstruct the full Auth0 user ID for an identity object.

    Auth0 identity objects usually store the provider separately from the
    provider-local user_id. Top-level user IDs include both.
    """
    if identity.user_id.startswith(f"{identity.provider}|"):
        return identity.user_id
    if identity.provider == "auth0":
        return f"auth0|{identity.user_id}"
    if identity.connection:
        return f"{identity.provider}|{identity.connection}|{identity.user_id}"
    return f"{identity.provider}|{identity.user_id}"


def user_seen_in_auth0_export(
    user: BiocommonsUser,
    export_index: Auth0ExportIdentityIndex,
) -> bool:
    user_ids = {
        user.id,
        user.other_user_id,
    }
    return any(
        user_id is not None
        and (
            user_id in export_index.exported_user_ids
            or user_id in export_index.exported_identity_ids
        )
        for user_id in user_ids
    )


def user_exists_in_auth0(
    auth0_client: Auth0Client,
    user: BiocommonsUser,
    *,
    delay_seconds: float = 0.5,
) -> bool:
    """
    Check live Auth0 before soft-deleting a user that was missing from export.

    A user may appear after the export was generated. Linked AAF users may also
    have either the primary DB ID or linked identity ID in Auth0.
    """
    for user_id in _user_auth0_lookup_ids(user):
        try:
            auth0_client.get_user(user_id)
        except HTTPStatusError as exc:
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            if exc.response.status_code == 404:
                continue
            raise exc
        else:
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            return True
    return False


def should_soft_delete_missing_user(
    user: BiocommonsUser,
    export_index: Auth0ExportIdentityIndex,
) -> bool:
    if user_seen_in_auth0_export(user, export_index):
        return False

    if user.account_type == BiocommonsUserAccountType.AUTH0:
        return True

    if user.account_type == BiocommonsUserAccountType.AAF:
        if user.other_user_id is None:
            logger.warning(
                "Skipping missing-user soft delete for AAF user {} because no "
                "linked identity is recorded.",
                user.id,
            )
            return False
        return True

    logger.warning(
        "Skipping missing-user soft delete for user {} with unexpected account "
        "type {}.",
        user.id,
        user.account_type,
    )
    return False


def _user_auth0_lookup_ids(user: BiocommonsUser) -> list[str]:
    user_ids = set()
    for user_id in (user.id, user.other_user_id):
        if user_id is not None:
            user_ids.add(user_id)
    return sorted(user_ids)


def _sync_blocked_user(
    session: Session,
    record: UserSyncRecord,
    policy: UserSyncPolicy,
) -> UserSyncResult:
    user = BiocommonsUser.get_by_id(
        record.user_id,
        session,
        include_deleted=True,
    )
    if user is None:
        return UserSyncResult(action=UserSyncAction.SKIPPED_BLOCKED_MISSING)

    _check_user_conflicts(session, record)
    if _user_needs_update(user, record, policy):
        user.save_history(
            session,
            change="auth0_sync",
            reason="Blocked user data updated from Auth0",
            updated_by=None,
            commit=False,
        )
        _apply_record_to_user(user, record, policy)

    if user.is_deleted:
        session.add(user)
        return UserSyncResult(action=UserSyncAction.SKIPPED_UNCHANGED, user=user)

    user.delete(session, reason="auth0_sync", commit=False)
    return UserSyncResult(action=UserSyncAction.SOFT_DELETED, user=user)


def _create_user(
    session: Session,
    record: UserSyncRecord,
    policy: UserSyncPolicy,
) -> BiocommonsUser:
    username = record.username
    if username is None:
        raise UserSyncValidationError(
            f"User {record.user_id} requires a username"
        )

    user = BiocommonsUser(
        id=record.user_id,
        email=record.email,
        username=username,
        email_verified=_effective_email_verified(record, policy),
        account_type=record.account_type,
    )
    session.add(user)
    return user


def _check_user_conflicts(session: Session, record: UserSyncRecord) -> None:
    email_conflict = _find_conflicting_user_by_email(
        session=session,
        user_id=record.user_id,
        email=record.email,
    )
    if email_conflict is not None:
        raise UserSyncConflictError(
            "Auth0 email conflict for user "
            f"{record.user_id}: email {record.email!r} is already used by "
            f"{email_conflict.id}."
        )

    if record.username is None:
        return

    username_conflict = _find_conflicting_user_by_username(
        session=session,
        user_id=record.user_id,
        username=record.username,
    )
    if username_conflict is not None:
        raise UserSyncConflictError(
            "Auth0 username conflict for user "
            f"{record.user_id}: username {record.username!r} is already used by "
            f"{username_conflict.id}."
        )

    history_conflict = _find_conflicting_username_history(
        session=session,
        user_id=record.user_id,
        username=record.username,
    )
    if history_conflict is not None:
        raise UserSyncConflictError(
            "Auth0 username history conflict for user "
            f"{record.user_id}: username {record.username!r} was already used by "
            f"{history_conflict.user_id}."
        )


def _find_conflicting_user_by_username(
    session: Session,
    user_id: str,
    username: str,
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
    session: Session,
    user_id: str,
    email: str,
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


def _find_conflicting_username_history(
    session: Session,
    user_id: str,
    username: str,
) -> BiocommonsUserHistory | None:
    statement = (
        select(BiocommonsUserHistory)
        .where(BiocommonsUserHistory.username == username)
        .where(BiocommonsUserHistory.user_id != user_id)
        .execution_options(include_deleted=True)
    )
    with session.no_autoflush:
        return session.exec(statement).first()


def _user_needs_update(
    user: BiocommonsUser,
    record: UserSyncRecord,
    policy: UserSyncPolicy,
) -> bool:
    return any(
        [
            user.email != record.email,
            record.username is not None and user.username != record.username,
            user.email_verified != _effective_email_verified(record, policy),
            user.account_type != record.account_type,
        ]
    )


def _apply_record_to_user(
    user: BiocommonsUser,
    record: UserSyncRecord,
    policy: UserSyncPolicy,
) -> None:
    if user.account_type != record.account_type:
        logger.warning(
            "User sync changing account type for {} from {} to {}. "
            "Account type changes should normally be handled by API endpoints.",
            user.id,
            user.account_type,
            record.account_type,
        )

    user.email = record.email
    if record.username is not None:
        user.username = record.username
    user.email_verified = _effective_email_verified(record, policy)
    user.account_type = record.account_type


def _effective_email_verified(
    record: UserSyncRecord,
    policy: UserSyncPolicy,
) -> bool:
    if policy.email_verified_source == "always_true":
        return True
    return record.email_verified


def _coerce_account_type(
    value: BiocommonsUserAccountType | str | None,
) -> BiocommonsUserAccountType:
    if isinstance(value, BiocommonsUserAccountType):
        return value
    if value in (None, ""):
        return BiocommonsUserAccountType.AUTH0
    return BiocommonsUserAccountType(value)


def _coerce_export_account_type(
    user: ExportedUserLike,
) -> BiocommonsUserAccountType:
    if user.account_type not in (None, ""):
        return _coerce_account_type(user.account_type)
    if user.aaf_only is True or user.aaf_registration_complete is True:
        return BiocommonsUserAccountType.AAF
    return BiocommonsUserAccountType.AUTH0


def _coerce_auth0_account_type(
    user: Auth0UserData,
) -> BiocommonsUserAccountType:
    if (
        user.app_metadata.account_type == BiocommonsUserAccountType.AUTH0
        and (
            user.app_metadata.aaf_only is True
            or user.app_metadata.aaf_registration_complete is True
        )
    ):
        return BiocommonsUserAccountType.AAF
    return user.app_metadata.account_type


def _select_username(
    *,
    account_type: BiocommonsUserAccountType,
    auth0_username: str | None,
    metadata_username: str | None,
) -> str | None:
    if account_type == BiocommonsUserAccountType.AAF:
        return metadata_username or auth0_username
    return auth0_username or metadata_username
