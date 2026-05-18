from datetime import datetime, timezone

from pydantic import AwareDatetime


def request_time() -> AwareDatetime:
    """
    Returns the current time in UTC timezone.
    """
    return datetime.now(timezone.utc)