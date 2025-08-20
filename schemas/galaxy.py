from typing import Self

from pydantic import BaseModel, EmailStr, model_validator

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class GalaxyRegistrationData(BaseModel):
    email: EmailStr
    # TODO: Update name of this field in frontend from
    username: BiocommonsUsername
    password: BiocommonsPassword
    confirmPassword: str

    @model_validator(mode='after')
    def check_passwords_match(self) -> Self:
        if self.password != self.confirmPassword:
            raise ValueError('Passwords do not match')
        return self
