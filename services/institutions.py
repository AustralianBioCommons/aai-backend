import httpx

GALAXY_AU_VALIDATE_URL = "https://site.usegalaxy.org.au/institution/validate"

# TODO: Remove this once Galaxy adds biocommons.org.au in their institions list
ALWAYS_VALID_DOMAINS = {"biocommons.org.au"}


async def is_australian_research_institution_email(email: str) -> bool:
    """Check email against Galaxy Australia's institution validation API.

    Returns False on any network or parse error so registration is never
    blocked by an upstream outage.
    """
    domain = email.split("@")[-1].lower() if "@" in email else ""
    if domain in ALWAYS_VALID_DOMAINS:
        return True

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(GALAXY_AU_VALIDATE_URL, params={"email": email})
            response.raise_for_status()
            return response.json().get("valid", False)
    except Exception:
        return False
