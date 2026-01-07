from pydantic import BaseModel, Field

from schemas.biocommons import Auth0UserData


class FieldError(BaseModel):
    field: str
    message: str


class FieldErrorResponse(BaseModel):
    """
    Generic error response that specifies errors for individual fields where possible
    """
    message: str = Field(description="Overall error message")
    field_errors: list[FieldError] = Field(default_factory=list)


class RegistrationErrorResponse(FieldErrorResponse):
    """
    Error response for registration requests that specifies
    errors for individual fields where possible
    """
    pass


class RegistrationResponse(BaseModel):
    message: str
    user: Auth0UserData
