from typing import Self

from pydantic import BaseModel, EmailStr, Field, model_validator

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class GalaxyRegistrationData(BaseModel):
    email: EmailStr
    # TODO: Update name of this field in frontend from
    username: BiocommonsUsername
    password: BiocommonsPassword
    confirm_password: str = Field(alias='confirmPassword')

    @model_validator(mode='after')
    def check_passwords_match(self) -> Self:
        if self.password != self.confirm_password:
            raise ValueError('Passwords do not match')
        return self
