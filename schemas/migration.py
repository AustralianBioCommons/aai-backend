from enum import StrEnum

from pydantic import BaseModel, EmailStr


class MigrationDirection(StrEnum):
    AUTH0_TO_AAF = "AUTH0_TO_AAF"
    AAF_TO_AUTH0 = "AAF_TO_AUTH0"


class MigrationStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"


class MigrateToAafRequest(BaseModel):
    new_email: EmailStr
