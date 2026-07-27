from db.types import PlatformEnum

# Platforms that are automatically approved when
# users register for a biocommons account
DEFAULT_PLATFORMS: list[PlatformEnum] = [
    PlatformEnum.BPA_DATA_PORTAL,
    PlatformEnum.GALAXY,
    PlatformEnum.SBP,
]


def get_default_platforms(*, sbp_enabled: bool = True) -> list[PlatformEnum]:
    if sbp_enabled:
        return list(DEFAULT_PLATFORMS)
    return [platform for platform in DEFAULT_PLATFORMS if platform != PlatformEnum.SBP]
