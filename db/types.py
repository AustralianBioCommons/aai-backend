"""
Shared types/enums used by the database.

Useful to keep them here rather than in models.py to
avoid circular imports.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class ApprovalStatusEnum(str, Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REVOKED = "revoked"
    REJECTED = "rejected"


class EmailStatusEnum(str, Enum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


class PlatformEnum(str, Enum):
    GALAXY = "galaxy"
    BPA_DATA_PORTAL = "bpa_data_portal"
    SBP = "sbp"


class PlatformMembershipData(BaseModel):
    """Data model for platform membership, when returned from the API"""
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    platform_id: PlatformEnum
    platform_name: str
    user_id: str
    approval_status: ApprovalStatusEnum
    updated_by: str = Field(validation_alias="updated_by_email")
    updated_at: AwareDatetime
    revocation_reason: str | None = None
    request_reason: str | None = None

    @field_validator("updated_at", mode="before")
    @classmethod
    def _ensure_tz_updated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class GroupMembershipData(BaseModel):
    """Data model for group membership, when returned from the API"""
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    group_id: str
    group_name: str
    group_short_name: str
    approval_status: ApprovalStatusEnum
    updated_by: str = Field(validation_alias="updated_by_email")
    updated_at: AwareDatetime
    revocation_reason: str | None = None
    rejection_reason: str | None = None
    request_reason: str | None = None

    @field_validator("updated_at", mode="before")
    @classmethod
    def _ensure_tz_updated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class GroupEnum(str, Enum):
    TSI = "biocommons/group/tsi"


# Provide default group names so we can populate the DB easily
#   - should use the DB values when looking them up though
GROUP_NAMES: dict[GroupEnum, tuple[str, str]] = {
    GroupEnum.TSI: ("Threatened Species Initiative", "TSI"),
}
