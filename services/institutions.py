from typing import Optional

import httpx

GALAXY_AU_VALIDATE_URL = "https://site.usegalaxy.org.au/institution/validate"


async def check_australian_research_institution_email(email: str) -> Optional[bool]:
    """Check email against Galaxy Australia's institution validation API.

    Returns True/False for a definitive answer from the upstream service, or
    None when the result could not be determined (network/parse error). Callers
    that must not act on an outage should treat None distinctly from False.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(GALAXY_AU_VALIDATE_URL, params={"email": email})
            response.raise_for_status()
            return bool(response.json().get("valid", False))
    except Exception:
        return None


async def is_australian_research_institution_email(email: str) -> bool:
    """Check email against Galaxy Australia's institution validation API.

    Returns False on any network or parse error so registration is never
    blocked by an upstream outage.
    """
    return await check_australian_research_institution_email(email) is True
