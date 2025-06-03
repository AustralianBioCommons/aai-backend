from typing import Dict, List

from pydantic import BaseModel, EmailStr


class BPAUserMetadata(BaseModel):
    bpa: Dict[str, str] = {"registration_reason": "", "username": ""}


class BPAAppMetadata(BaseModel):
    groups: List[Dict] = []
    services: List[Dict] = []


class BPARegisterData(BaseModel):
    email: EmailStr
    password: str
    connection: str = "Username-Password-Authentication"
    username: str
    name: str
    email_verified: bool = False
    blocked: bool = False
    verify_email: bool = True
    user_metadata: BPAUserMetadata
    app_metadata: BPAAppMetadata

    @classmethod
    def from_registration(cls, registration, bpa_service):
        """Create BPARegisterData from registration request and BPA service."""
        return cls(
            email=registration.email,
            password=registration.password,
            username=registration.username,
            name=registration.fullname,
            user_metadata=BPAUserMetadata(
                bpa={"registration_reason": registration.reason,
                     "username": registration.username,},
            ),
            app_metadata=BPAAppMetadata(services=[bpa_service.model_dump(mode="json")]),
        )
