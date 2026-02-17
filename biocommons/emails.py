from pydantic import EmailStr

from config import Settings, get_settings
from db.models import GroupMembership


def get_default_sender_email(settings: Settings | None = None) -> str:
    if settings is None:
        settings = get_settings()
    email: EmailStr = settings.default_email_sender
    return str(email)


def compose_group_approval_email(request: GroupMembership, settings: Settings) -> tuple[str, str]:
    subject = f"New request to join {request.group.name}"
    body_html = f"""
        <p>A new user has requested access to the {request.group.name} group.</p>
        <p><strong>User:</strong> {request.user.email}</p>
        <p><strong>Reason for request:</strong> {request.request_reason}</p>
        <p>Please <a href='{settings.aai_portal_url}'>log into the BioCommons account dashboard</a> to review and approve access.</p>
    """
    return subject, body_html


def compose_group_membership_approved_email(
    group_name: str,
    group_short_name: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their group/bundle access was approved.
    """
    short_name = group_short_name or group_name
    portal_url = settings.aai_portal_url.rstrip("/")
    subject = f"Access approved for {short_name}"
    body_html = f"""
        <p>Hello,</p>
        <p>Your request to join <strong>{group_name}</strong> ({short_name} bundle) has been approved.</p>
        <p>You now have access to all services included with this bundle. Sign in to the <a href="{portal_url}"> BioCommons Access Portal</a> to review the bundle details and launch its platforms.</p>
        <p>If you have any questions, please reply to this email.</p>
    """
    return subject, body_html


def compose_email_change_notification(
    old_email: str,
    new_email: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their email address was updated.
    """
    portal_url = settings.aai_portal_url.rstrip("/")
    subject = "Your Biocommons Access email address was updated"
    body_html = f"""
        <p>Hello,</p>
        <p>The email address on your Biocommons Access account was updated.</p>
        <p><strong>Old email:</strong> {old_email}<br/>
        <strong>New email:</strong> {new_email}</p>
        <p>If you did not expect this change, please visit the
        <a href="{portal_url}">BioCommons Access Portal</a> or contact support.</p>
    """
    return subject, body_html


def compose_username_change_notification(
    old_username: str,
    new_username: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their username was updated.
    """
    portal_url = settings.aai_portal_url.rstrip("/")
    subject = "Your Biocommons Access username was updated"
    body_html = f"""
        <p>Hello,</p>
        <p>The username on your Biocommons Access account was updated by your service administrator.</p>
        <p><strong>Old username:</strong> {old_username}<br/>
        <strong>New username:</strong> {new_username}</p>
        <p>If you did not expect this change, please visit the
        <a href="{portal_url}">BioCommons Access Portal</a> or contact support.</p>
    """
    return subject, body_html


def compose_email_change_otp_email(
    code: str,
    target_email: str,
    expiration_minutes: int,
) -> tuple[str, str]:
    """
    Email OTP for confirming an email address change.
    """
    subject = "Confirm your new BioCommons Access email address"
    body_html = (
        "<p>Dear,</p>"
        "<p>We received a request to change the email address of your "
        f"BioCommons Access account to {target_email}.</p>"
        f"<p>Your verification code is <strong>{code}</strong>.</p>"
        f"<p>This code is valid for {expiration_minutes} minutes.</p>"
        "<p>Thank you,</p>"
        "<p>The BioCommons Access team.</p>"
        "<p>If you experience any issues, please refer to the FAQs or contact "
        "support via the BioCommons Access support page "
        "<a href=\"https://www.biocommons.org.au/access-support\">"
        "www.biocommons.org.au/access-support</a>.</p>"
    )
    return subject, body_html
