import pytest

from schemas.group import Group


def test_group_requires_fields() -> None:
    data = {"name": "Test Group", "id": "biocommons/group/test"}
    group = Group(**data)

    assert group.name == data["name"]
    assert group.id == data["id"]


@pytest.mark.parametrize("payload", [{}, {"name": "Missing ID"}])
def test_group_validation_errors(payload: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Group(**payload)
