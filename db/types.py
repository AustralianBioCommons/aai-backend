"""
Shared types/enums used by the database.

Useful to keep them here rather than in models.py to
avoid circular imports.
"""
import uuid
from enum import Enum

from pydantic import BaseModel


class ApprovalStatusEnum(str, Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REVOKED = "revoked"


class PlatformEnum(str, Enum):
    GALAXY = "galaxy"
    BPA_DATA_PORTAL = "bpa_data_portal"
    SBP = "sbp"


class PlatformMembershipData(BaseModel):
    """Data model for platform membership, when returned from the API"""
    id: uuid.UUID
    platform_id: PlatformEnum
    user_id: str
    approval_status: ApprovalStatusEnum
    updated_by: str
    revocation_reason: str | None = None


class GroupMembershipData(BaseModel):
    """Data model for group membership, when returned from the API"""
    id: uuid.UUID
    group_id: str
    group_name: str
    approval_status: ApprovalStatusEnum
    updated_by: str
    revocation_reason: str | None = None


class GroupEnum(str, Enum):
    TSI = "biocommons/group/tsi"
    BPA_GALAXY = "biocommons/group/bpa_galaxy"


# Provide default group names so we can populate the DB easily
#   - should use the DB values when looking them up though
GROUP_NAMES: dict[GroupEnum, str] = {
    GroupEnum.TSI: "Threatened Species Initiative",
    GroupEnum.BPA_GALAXY: "Bioplatforms Australia Data Portal & Galaxy Australia",
}
