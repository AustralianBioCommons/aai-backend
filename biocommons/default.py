from db.types import PlatformEnum

# Platforms that are automatically approved when
# users register for a biocommons account
DEFAULT_PLATFORMS: list[PlatformEnum] = [
    PlatformEnum.BPA_DATA_PORTAL,
    PlatformEnum.GALAXY,
]
