from schemas.auth0 import (
    get_group_id_from_role_name,
    get_platform_id_from_role_name,
)


def test_get_platform_id_from_role_name_success():
    assert get_platform_id_from_role_name("biocommons/platform/galaxy") == "galaxy"


def test_get_platform_id_from_role_name_no_match():
    assert get_platform_id_from_role_name("biocommons/role/galaxy/admin") is None


def test_get_group_id_from_role_name_success():
    assert get_group_id_from_role_name("biocommons/group/tsi") == "tsi"


def test_get_group_id_from_role_name_no_match():
    assert get_group_id_from_role_name("biocommons/platform/galaxy") is None
