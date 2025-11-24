import random
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from db.models import EmailNotification

EMAIL_QUEUE_BATCH_SIZE = 25
EMAIL_MAX_ATTEMPTS = 2
EMAIL_RETRY_DELAY_MIN_SECONDS = 15 * 60
EMAIL_RETRY_DELAY_MAX_SECONDS = 30 * 60
EMAIL_RETRY_WINDOW_SECONDS = 60 * 60
EMAIL_JOB_ID_PREFIX = "email_notification_"

TRANSIENT_CLIENT_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceUnavailable",
    "InternalFailure",
    "InternalError",
    "RequestThrottled",
}


def _ensure_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def retry_deadline(notification: EmailNotification) -> datetime | None:
    first_attempt = _ensure_aware(notification.last_attempt_at)
    if first_attempt is None:
        return None
    return first_attempt + timedelta(seconds=EMAIL_RETRY_WINDOW_SECONDS)


def can_schedule_notification(notification: EmailNotification, now: datetime) -> bool:
    if notification.attempts >= EMAIL_MAX_ATTEMPTS:
        return False
    deadline = retry_deadline(notification)
    return deadline is None or now < deadline


def is_retryable_email_error(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code")
        return code in TRANSIENT_CLIENT_ERROR_CODES
    if isinstance(exc, BotoCoreError):
        return True
    if isinstance(exc, OSError):
        return True
    return False


def next_retry_delay_seconds() -> int:
    return random.randint(EMAIL_RETRY_DELAY_MIN_SECONDS, EMAIL_RETRY_DELAY_MAX_SECONDS)
