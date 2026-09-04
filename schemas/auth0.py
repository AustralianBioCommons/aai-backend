import re

from pydantic import BaseModel, EmailStr

PLATFORM_ROLE_PATTERN = re.compile(r"biocommons/platform/(?P<platform_id>[a-z0-9_-]+)")
GROUP_ROLE_PATTERN = re.compile(r"biocommons/group/(?P<group_id>[a-z0-9_-]+)")


def get_platform_id_from_role_name(role_name: str) -> str | None:
    match = PLATFORM_ROLE_PATTERN.match(role_name)
    if match:
        return match.group("platform_id")
    return None


def get_group_id_from_role_name(role_name: str) -> str | None:
    match = GROUP_ROLE_PATTERN.match(role_name)
    if match:
        return match.group("group_id")
    return None


class Auth0ActionToken(BaseModel):
    """
    Token payload that we use in Auth0 actions - signed with a shared secret.

    Any future actions we create should use this payload.
    """
    user_id: str
    email: EmailStr
    client_id: str
    purpose: str
    sub: str | None = None
    iss: str | None = None
