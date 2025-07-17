import re
from typing import Annotated

from pydantic import StringConstraints
from sqlmodel import Session, select

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
    admin_roles: list[RoleId | Auth0Role]

    # TODO: currently requires the roles to exist in the DB
    #   already, probably want to get_or_create them
    def save(self, session: Session):
        db_roles = []
        for role in self.admin_roles:
            if isinstance(role, Auth0Role):
                db_roles.append(role)
            else:
                query = select(Auth0Role).where(Auth0Role.name == role)
                auth0_role = session.exec(query).one()
                db_roles.append(auth0_role)
        group = BiocommonsGroup(
            group_id=self.group_id,
            name=self.name,
            admin_roles=db_roles
        )
        session.add(group)
        session.commit()
