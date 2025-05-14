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

    def to_auth0_create_user_data(self,
                                  email_verified: bool=False,
                                  connection: str = "Username-Password-Authentication") -> 'Auth0CreateUserData':
        """
        Convert to the format expected by Auth0's create user endpoint
        """
        return Auth0CreateUserData(
            email=self.email,
            user_metadata=Auth0UserMetadata(galaxy_username=self.public_name),
            password=self.password,
            email_verified=email_verified,
            connection=connection,
        )


class Auth0UserMetadata(BaseModel):
    galaxy_username: str


class Auth0CreateUserData(BaseModel):
    email: EmailStr
    user_metadata: Auth0UserMetadata
    email_verified: bool = False
    password: str
    connection: str = 'Username-Password-Authentication'
