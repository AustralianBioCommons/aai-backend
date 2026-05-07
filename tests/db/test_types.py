from db.types import GroupEnum, PlatformEnum


def test_group_and_platform_ids_do_not_overlap():
    platform_ids = {platform.value for platform in PlatformEnum}
    group_ids = {
        group.value.removeprefix("biocommons/group/")
        for group in GroupEnum
    }

    assert platform_ids.isdisjoint(group_ids), (
        "Group IDs must not overlap platform IDs: "
        f"{sorted(platform_ids & group_ids)}"
    )
