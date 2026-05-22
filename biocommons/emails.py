import logging

from pydantic import EmailStr

from auth0.client import Auth0Client
from config import Settings, get_settings
from db.models import BiocommonsGroup
from dependencies.templates import TEMPLATES
from schemas.biocommons import Auth0UserData

logger = logging.getLogger("uvicorn.error")

# Default styles to inject into templates
_LOGO_URL = "https://images.squarespace-cdn.com/content/v1/5d3a4213cf4f5b00014ea1db/1689141619044-F67XDPQLP4PG6KY862VA/Australian-Biocommons-Logo-Horizontal-RGB.png"
_ICON_MAIL = "https://cdn.auth0.com/website/emails/product/icon-mail.png"
_P = "margin: 0 0 12px; font-size: 16px; line-height: 24px; color: #171717; text-align: left;"
_P_CENTER = "margin: 0 0 12px; font-size: 16px; line-height: 24px; color: #171717; text-align: center;"
_LI = "font-size: 16px; line-height: 24px; color: #171717;"
_UL = "margin: 0 0 12px; padding-left: 24px; text-align: left;"
_P_SIGN_OFF = "margin: 24px 0 12px; font-size: 16px; line-height: 24px; color: #171717; text-align: left;"
_A = "color: #171717; text-decoration: underline;"


def render_default_email_html(
    title: str,
    preheader: str,
    body_html: str,
    portal_url: str,
    icon_url: str = _ICON_MAIL,
    logo_url: str = _LOGO_URL,
) -> str:
    email_template = TEMPLATES.get_template(name="emails/default_email.html")
    return email_template.render(
        title=title,
        preheader=preheader,
        body_html=body_html,
        portal_url=portal_url,
        icon_url=icon_url,
        logo_url=logo_url,
    )


def render_html_template(template_name: str, **kwargs) -> str:
    """Render an HTML template with default styles and provided kwargs."""
    template = TEMPLATES.get_template(name=template_name)
    style_defaults = {
        "p_style": _P,
        "p_center_style": _P_CENTER,
        "a_style": _A,
        "p_signoff": _P_SIGN_OFF,
        "li_style": _LI,
        "ul_style": _UL,
    }
    template_kwargs = {**style_defaults, **kwargs}
    return template.render(**template_kwargs)


def get_default_sender_email(settings: Settings | None = None) -> str:
    if settings is None:
        settings = get_settings()
    email: EmailStr = settings.no_reply_email_sender
    logger.info(f"Got default sender email: {email}")
    logger.info(f"Email settings: {settings.no_reply_email_sender=}")
    return str(email)


def get_user_first_name(user: Auth0UserData, fallback: str):
    return format_first_name(
        full_name=user.name,
        given_name=user.given_name,
        fallback=fallback,
    )


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


def get_requester_identity(
    *,
    auth0_client: Auth0Client,
    user_id: str,
    fallback_email: str | None,
) -> tuple[str | None, str]:
    auth0_user = auth0_client.get_user(user_id)
    requester_email = auth0_user.email or fallback_email
    requester_full_name = format_full_name(
        full_name=auth0_user.name,
        given_name=auth0_user.given_name,
        family_name=auth0_user.family_name,
        fallback=requester_email or fallback_email or "Unknown user",
    )
    return requester_email, requester_full_name


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
        settings: Settings,
) -> tuple[str, str]:
    subject = f"{bundle_name} Service Bundle request"
    reason = request_reason.strip() if request_reason else "Not provided"
    portal_url = settings.aai_portal_url
    body_html = render_html_template(
        "emails/group_approval.html",
        admin_first_name=admin_first_name,
        bundle_name=bundle_name,
        requester_full_name=requester_full_name,
        requester_email=requester_email,
        reason=reason,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_group_membership_approved_email(
        group_name: str,
        group_short_name: str,
        first_name: str,
        settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their group/bundle access was approved.
    """
    portal_url = settings.aai_portal_url
    short_name = group_short_name or group_name
    short_suffix = (
        f" ({short_name})" if short_name and short_name != group_name else ""
    )
    subject = f"{group_name} Service Bundle access approved"
    body_html = render_html_template(
        "emails/group_approved.html",
        group_name=group_name,
        short_suffix=short_suffix,
        short_name=short_name,
        first_name=first_name,
        portal_url=portal_url,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_email_change_notification(
        old_email: str,
        new_email: str,
        settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their email address was updated.
    """
    portal_url = settings.aai_portal_url
    subject = "Your Biocommons Access email address was updated"
    body_html = render_html_template(
        "emails/email_changed.html",
        old_email=old_email,
        new_email=new_email,
        portal_url=portal_url,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html



def compose_username_change_notification(
        old_username: str,
        new_username: str,
        settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their username was updated.
    """
    portal_url = settings.aai_portal_url
    subject = "Your Biocommons Access username was updated"
    body_html = render_html_template(
        "emails/username_changed.html",
        old_username=old_username,
        new_username=new_username,
        portal_url=portal_url,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_email_change_otp_email(
        code: str,
        target_email: str,
        expiration_minutes: int,
        portal_url: str = "",
) -> tuple[str, str]:
    """
    Email OTP for confirming an email address change.
    """
    subject = "Confirm your new BioCommons Access email address"
    body_html = render_html_template(
        "emails/email_change_otp.html",
        code=code,
        target_email=target_email,
        expiration_minutes=expiration_minutes,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_welcome_email(
        first_name: str,
        portal_url: str,
) -> tuple[str, str]:
    """
    Welcome email sent to new users after email verification
    and to users who have been successfully migrated.
    """
    subject = "Welcome to BioCommons Access"
    body_html = render_html_template("emails/welcome_email.html", first_name=first_name, portal_url=portal_url)
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html



def compose_group_membership_rejected_email(
        *,
        group_name: str,
        username: str,
        settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their group/bundle access request was rejected.
    For the TSI bundle, includes detailed information about open-access alternatives.
    """
    portal_url = settings.aai_portal_url
    subject = "Threatened Species Initiative service bundle request"
    body_html = render_html_template(
        "emails/group_membership_rejected.html",
        group_name=group_name,
        username=username,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_bundle_request_confirmation_email(
        *,
        first_name: str,
        bundle_name: str,
        request_reason: str | None,
        settings: Settings,
) -> tuple[str, str]:
    """
    Confirmation email sent to a user after they request access to a bundle/group.
    Informs them their request was received and explains next steps.
    """
    portal_url = settings.aai_portal_url
    reason = request_reason.strip() if request_reason else "Not provided"
    subject = f"Your {bundle_name} Service Bundle request has been received"
    body_html = render_html_template(
        "emails/bundle_request_confirmation.html",
        first_name=first_name,
        bundle_name=bundle_name,
        reason=reason,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html


def compose_incorrect_email_notification_email(
        *,
        first_name: str,
        incorrect_email: str,
        settings: Settings,
):
    subject = "Did you register for a BioCommons Access account?"
    portal_url = settings.aai_portal_url
    register_url = portal_url.rstrip("/") + "/register"
    body_html = render_html_template(
        "emails/incorrect_email.html",
        first_name=first_name,
        incorrect_email=incorrect_email,
        register_url=register_url,
    )
    email_html = render_default_email_html(
        title=subject,
        preheader=subject,
        body_html=body_html,
        portal_url=portal_url,
    )
    return subject, email_html
