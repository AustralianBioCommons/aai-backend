from datetime import datetime, timezone

from sqlmodel import Session

from biocommons.emails import get_default_sender_email
from db.models import EmailNotification


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
        from_address=from_address or get_default_sender_email(),
        subject=subject,
        body_html=body_html,
        send_after=send_after,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(notification)
    session.flush()
    return notification
