import re

GroupIdPattern = re.compile(r"^biocommons/group/[a-z0-9_]+$")
RoleIdPattern = re.compile(r"^biocommons/role/[a-z0-9_]+/[a-z0-9_]+$")


def is_valid_group_id(group_id: str) -> bool:
    return GroupIdPattern.match(group_id) is not None


def is_valid_role_id(role_id: str) -> bool:
    return RoleIdPattern.match(role_id) is not None
