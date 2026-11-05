from enum import StrEnum

from pydantic import BaseModel, EmailStr, Field

from schemas.biocommons import BiocommonsPassword


class MigrationDirection(StrEnum):
    AUTH0_TO_AAF = "AUTH0_TO_AAF"
    AAF_TO_AUTH0 = "AAF_TO_AUTH0"


class MigrationStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"


class MigrateToAafRequest(BaseModel):
    new_email: EmailStr


class MigrateToAuth0Request(BaseModel):
    new_email: EmailStr
    password: BiocommonsPassword


class CompleteToAuth0Request(BaseModel):
    migration_id: str
    otp: str = Field(pattern=r"^[0-9]{6}$")
