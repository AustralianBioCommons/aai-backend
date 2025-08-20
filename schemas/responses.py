from pydantic import BaseModel, Field


class FieldError(BaseModel):
    field: str
    message: str


class RegistrationErrorResponse(BaseModel):
    """
    Error response for registration requests that specifies
    errors for individual fields where possible
    """
    message: str = Field(description="Overall error message")
    field_errors: list[FieldError] = []
