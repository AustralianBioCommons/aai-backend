from enum import StrEnum


class MigrationDirection(StrEnum):
    AUTH0_TO_AAF = "AUTH0_TO_AAF"
    AAF_TO_AUTH0 = "AAF_TO_AUTH0"


class MigrationStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
