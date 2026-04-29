import httpx

GALAXY_AU_VALIDATE_URL = "https://site.usegalaxy.org.au/institution/validate"


async def is_australian_research_institution_email(email: str) -> bool:
    """Check email against Galaxy Australia's institution validation API.

    Returns False on any network or parse error so registration is never
    blocked by an upstream outage.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(GALAXY_AU_VALIDATE_URL, params={"email": email})
            response.raise_for_status()
            return response.json().get("valid", False)
    except Exception:
        return False
