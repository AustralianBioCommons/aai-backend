import re
from typing import Annotated

from pydantic import StringConstraints
from sqlmodel import Session

from auth0.client import Auth0Client
from db.core import BaseModel
from db.models import Auth0Role, BiocommonsGroup

GroupIdPattern = re.compile(r"^biocommons/group/[a-z0-9_]+$")
GroupId = Annotated[str, StringConstraints(pattern=GroupIdPattern)]
RoleIdPattern = re.compile(r"^biocommons/role/[a-z0-9_]+/[a-z0-9_]+$")
RoleId = Annotated[str, StringConstraints(pattern=RoleIdPattern)]


def is_valid_group_id(group_id: str) -> bool:
    return GroupIdPattern.match(group_id) is not None


def is_valid_role_id(role_id: str) -> bool:
    return RoleIdPattern.match(role_id) is not None


# Note: not using table=True so this is just a data model,
#   not saved in the DB
class BiocommonsGroupCreate(BaseModel):
    """
    Data needed to create a new biocommons group
    """
    group_id: GroupId
    name: str
    short_name: str
    admin_roles: list[RoleId | Auth0Role]

    def save(self, session: Session, auth0_client: Auth0Client) -> BiocommonsGroup:
        db_roles = []
        for role in self.admin_roles:
            if isinstance(role, Auth0Role):
                db_roles.append(role)
            else:
                role = Auth0Role.get_or_create_by_name(
                    role,
                    session,
                    auth0_client=auth0_client
                )
                db_roles.append(role)
        group = BiocommonsGroup(
            group_id=self.group_id,
            name=self.name,
            short_name=self.short_name,
            admin_roles=db_roles
        )
        session.add(group)
        session.commit()
        return group


class BiocommonsGroupResponse(BaseModel):
    """
    Data to return in API responses for BiocommonsGroup
    """
    group_id: str
    name: str
    admin_roles: list[str]
