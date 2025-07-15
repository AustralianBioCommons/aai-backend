import pytest

from biocommons.groups import is_valid_group_id, is_valid_role_id


@pytest.mark.parametrize("group_id", [
    "biocommons/group/tsi",
    "biocommons/group/bird_genomics",
    "biocommons/group/biology2",
])
def test_valid_group_ids(group_id):
    assert is_valid_group_id(group_id)


@pytest.mark.parametrize("group_id", [
    "BioCommons/Group/TSI",
    "biocommons/tsi",
    "biocommons/group/crab-data"
])
def test_invalid_group_ids(group_id):
    assert not is_valid_group_id(group_id)


@pytest.mark.parametrize("role_id", [
    "biocommons/role/tsi/admin",
    "biocommons/role/biocommons/sysadmin",
    "biocommons/role/tsi/data_manager",
])
def test_valid_role_ids(role_id):
    assert is_valid_role_id(role_id)
