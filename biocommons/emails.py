from pydantic import EmailStr

from auth0.client import Auth0Client
from config import Settings, get_settings
from db.models import BiocommonsGroup


def get_default_sender_email(settings: Settings | None = None) -> str:
    if settings is None:
        settings = get_settings()
    email: EmailStr = settings.default_email_sender
    return str(email)


def format_first_name(
    *,
    full_name: str | None,
    given_name: str | None,
    fallback: str = "Admin",
) -> str:
    if given_name:
        cleaned = given_name.strip()
        if cleaned:
            return cleaned
    if full_name:
        cleaned = full_name.strip()
        if cleaned:
            return cleaned.split()[0]
    return fallback


def format_full_name(
    *,
    full_name: str | None,
    given_name: str | None,
    family_name: str | None,
    fallback: str,
) -> str:
    if full_name:
        cleaned = full_name.strip()
        if cleaned:
            return cleaned
    parts = [part.strip() for part in (given_name, family_name) if part and part.strip()]
    if parts:
        return " ".join(parts)
    return fallback


def get_group_admin_contacts(
    *,
    group: BiocommonsGroup,
    auth0_client: Auth0Client,
) -> list[tuple[str, str]]:
    """
    Return admin contact tuples of (email, first_name), deduped by email.
    """
    contacts: dict[str, str] = {}
    for role in group.admin_roles:
        role_admins = auth0_client.get_all_role_users(role_id=role.id)
        for admin in role_admins:
            email = admin.email
            full_name = admin.name
            given_name = None
            needs_profile = email is None or not (full_name and full_name.strip())
            if needs_profile:
                full_admin = auth0_client.get_user(admin.user_id)
                email = email or full_admin.email
                full_name = full_name or full_admin.name
                given_name = full_admin.given_name
            if not email:
                continue
            first_name = format_first_name(
                full_name=full_name,
                given_name=given_name,
            )
            if email not in contacts or contacts[email] == "Admin":
                contacts[email] = first_name
    return list(contacts.items())


def compose_group_approval_email(
    *,
    admin_first_name: str,
    bundle_name: str,
    requester_full_name: str,
    requester_email: str,
    request_reason: str | None,
    requester_user_id: str,
    settings: Settings,
) -> tuple[str, str]:
    subject = f"{bundle_name} Service Bundle request"
    portal_url = settings.aai_portal_url.rstrip("/")
    user_detail_url = f"{portal_url}/user/{requester_user_id}"
    reason = request_reason.strip() if request_reason else "Not provided"
    body_html = f"""
        <p>Dear {admin_first_name},</p>
        <p>You have received a new request for access to the {bundle_name} Service Bundle.</p>
        <p><strong>Name:</strong> {requester_full_name}</p>
        <p><strong>Email:</strong> {requester_email}</p>
        <p><strong>Reason:</strong> {reason}</p>
        <p>Please click <a href="{user_detail_url}">here</a> to approve or decline this request via the user detail page.</p>
        <p>Thank you,</p>
        <p>The BioCommons Access team.</p>
    """
    return subject, body_html


def compose_group_membership_approved_email(
    group_name: str,
    group_short_name: str,
    first_name: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their group/bundle access was approved.
    """
    short_name = group_short_name or group_name
    short_suffix = f" ({short_name})" if short_name and short_name != group_name else ""
    subject = f"{group_name} Service Bundle access approved"
    body_html = f"""
        <p>Dear {first_name},</p>
        <p>Your request to join the {group_name}{short_suffix} service bundle has been approved.</p>
        <p>If you are logged into either of the BioPlatforms Data Portal or Galaxy Australia, please log out and log back in again to ensure your access rights are updated.</p>
        <p>Thank you,</p>
        <p>The BioCommons Access team.</p>
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
