import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime
from sqlmodel import AutoString, DateTime, Field, SQLModel

ApprovalStatus = Literal["approved", "pending", "revoked"]


class GroupMembership(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # TODO: May want to constrain the types of strings
    #   given they have a specific format
    # TODO: May want to make group and/or user_id indexes?
    group: str
    user_id: str
    user_email: str
    approval_status: ApprovalStatus = Field(sa_type=AutoString)
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_type=DateTime)
    updated_by_id: str
    updated_by_email: str
