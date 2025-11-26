from datetime import datetime, timezone

from sqlmodel import Session

from db.models import EmailNotification
from email_settings import DEFAULT_EMAIL_SENDER


def enqueue_email(
    session: Session,
    *,
    to_address: str,
    subject: str,
    body_html: str,
    send_after: datetime | None = None,
    from_address: str | None = None,
) -> EmailNotification:
    """
    Persist an outbound email so the scheduler can deliver it later.

    Note: the caller is responsible for committing the session after enqueueing.
    """
    notification = EmailNotification(
        to_address=to_address,
        from_address=from_address or DEFAULT_EMAIL_SENDER,
        subject=subject,
        body_html=body_html,
        send_after=send_after,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(notification)
    session.flush()
    return notification
