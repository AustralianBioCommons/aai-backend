from typing import Annotated, Self

from pydantic import BaseModel, EmailStr, StringConstraints, model_validator


class GalaxyRegistrationData(BaseModel):
    email: EmailStr
    password: str
    password_confirmation: str
    public_name: Annotated[str, StringConstraints(min_length=3, pattern=r"^[a-z0-9._-]+$")]

    @model_validator(mode='after')
    def check_passwords_match(self) -> Self:
        if self.password != self.password_confirmation:
            raise ValueError('Passwords do not match')
        return self
