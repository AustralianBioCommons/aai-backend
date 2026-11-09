from fastapi import HTTPException, status
from sqlmodel import Session

from db.models import BiocommonsUser


def is_email_available_for_change(
    email: str, *, current_user_id: str, session: Session,
) -> bool:
    """Check local accounts, including deleted ones, excluding the current user."""
    return BiocommonsUser.get_by_email(
        email=email,
        session=session,
        case_insensitive=True,
        include_deleted=True,
        exclude_user_id=current_user_id,
    ) is None


def check_email_conflict(*, current_user_id: str, new_email: str, session: Session) -> None:
    """Reject an email change or migration that conflicts with another account."""
    if not is_email_available_for_change(
        new_email, current_user_id=current_user_id, session=session,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user",
        )
