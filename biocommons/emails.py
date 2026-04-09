import html
import logging

from pydantic import EmailStr

from auth0.client import Auth0Client
from config import Settings, get_settings
from db.models import BiocommonsGroup

logger = logging.getLogger("uvicorn.error")

_LOGO_URL = "https://images.squarespace-cdn.com/content/v1/5d3a4213cf4f5b00014ea1db/1689141619044-F67XDPQLP4PG6KY862VA/Australian-Biocommons-Logo-Horizontal-RGB.png"
_ICON_MAIL = "https://cdn.auth0.com/website/emails/product/icon-mail.png"
_P = "margin: 0 0 12px; font-size: 16px; line-height: 24px; color: #171717; text-align: left;"
_P_SIGN_OFF = "margin: 24px 0 12px; font-size: 16px; line-height: 24px; color: #171717; text-align: left;"
_A = "color: #171717; text-decoration: underline;"


def _wrap_email_html(
    title: str,
    preheader: str,
    body_html: str,
    portal_url: str,
    icon_url: str = _ICON_MAIL,
) -> str:
    safe_title = html.escape(title)
    safe_preheader = html.escape(preheader)
    safe_portal_url = html.escape(portal_url)
    safe_logo_url = html.escape(_LOGO_URL)
    safe_icon_url = html.escape(icon_url)
    return f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
  <head>
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
    <meta name="x-apple-disable-message-reformatting" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{safe_title}</title>
  </head>
  <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">
    <div style="display: none; overflow: hidden; line-height: 1px; opacity: 0; max-height: 0; max-width: 0;">{safe_preheader}</div>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f5f5f5; margin: 0; padding: 0">
      <tr>
        <td align="center" style="padding: 24px">
          <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="max-width: 660px; margin: 0 auto">
            <tr>
              <td style="background-color: #ffffff; border: 1px solid #e5e5e5; border-radius: 16px; padding: 32px; text-align: center;">
                <a href="{safe_portal_url}" target="_blank" style="display: block; margin-bottom: 16px; text-decoration: none;">
                  <img src="{safe_logo_url}" alt="BioCommons Logo" width="180" style="display: block; margin: 0 auto; width: 100%; max-width: 180px; height: auto; border: 0;" />
                </a>
                <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;" />
                <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="width: 64px; height: 64px; border-radius: 12px; background-color: #f5f5f5; margin: 0 auto;">
                  <tr>
                    <td align="center" valign="middle">
                      <img src="{safe_icon_url}" width="24" height="24" alt="" style="display: block; border: 0; margin: 0 auto" />
                    </td>
                  </tr>
                </table>
                <h1 style="text-align: center; font-size: 24px; line-height: 32px; font-weight: 600; color: #171717; margin: 24px 0;">{safe_title}</h1>
                <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;" />
                {body_html}
                <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;" />
                <p style="font-size: 14px; line-height: 20px; color: #737373; margin: 0; text-align: center;">
                  If you experience any issues, please refer to the
                  <a href="https://biocommonsaccess.freshdesk.com/support/home" style="color: #171717; text-decoration: underline" target="_blank" rel="noopener noreferrer">FAQs or contact support</a>
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""


def get_default_sender_email(settings: Settings | None = None) -> str:
    if settings is None:
        settings = get_settings()
    email: EmailStr = settings.no_reply_email_sender
    logger.info(f"Got default sender email: {email}")
    logger.info(f"Email settings: {settings.no_reply_email_sender=}")
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
    requester_user_id: str,
    settings: Settings,
) -> tuple[str, str]:
    subject = f"{bundle_name} Service Bundle request"
    reason = request_reason.strip() if request_reason else "Not provided"
    safe_admin_first_name = html.escape(admin_first_name)
    safe_bundle_name = html.escape(bundle_name)
    safe_requester_full_name = html.escape(requester_full_name)
    safe_requester_email = html.escape(requester_email)
    safe_reason = html.escape(reason)
    portal_url = settings.aai_portal_url or ""
    body_content = f"""
        <p style="{_P}">Dear {safe_admin_first_name},</p>
        <p style="{_P}">You have received a new request for access to the {safe_bundle_name} Service Bundle.</p>
        <p style="{_P}"><strong>Name:</strong> {safe_requester_full_name}<br/><strong>Email:</strong> {safe_requester_email}<br/><strong>Reason:</strong> {safe_reason}</p>
        <p style="{_P}">Please log into the BioCommons Access bundle dashboard to review and approve or decline this request.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


def compose_group_membership_approved_email(
    group_name: str,
    group_short_name: str,
    first_name: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their group/bundle access was approved.
    """
    portal_url = settings.aai_portal_url or ""
    short_name = group_short_name or group_name
    safe_group_name = html.escape(group_name or "")
    safe_short_name = html.escape(short_name or "")
    safe_first_name = html.escape(first_name or "")
    safe_portal_url = html.escape(portal_url)
    short_suffix = (
        f" ({safe_short_name})" if safe_short_name and safe_short_name != safe_group_name else ""
    )
    subject = f"{safe_group_name} Service Bundle access approved"
    body_content = f"""
        <p style="{_P}">Dear {safe_first_name},</p>
        <p style="{_P}">Your request to join the {safe_group_name}{short_suffix} service bundle has been approved.</p>
        <p style="{_P}">If you are logged into either of the BioPlatforms Data Portal or Galaxy Australia, please log out and log back in again to ensure your access rights are updated.</p>
        <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin: 24px auto;">
          <tr>
            <td align="center">
              <a href="{safe_portal_url}" target="_blank" rel="noopener noreferrer" style="display: inline-block; background-color: #171717; color: #ffffff; font-weight: 600; padding: 12px 18px; line-height: 20px; border-radius: 8px; text-decoration: none; font-size: 14px;">Go to BioCommons Access Portal</a>
            </td>
          </tr>
        </table>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


def compose_email_change_notification(
    old_email: str,
    new_email: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their email address was updated.
    """
    portal_url = settings.aai_portal_url or ""
    safe_portal_url = html.escape(portal_url)
    safe_old_email = html.escape(old_email)
    safe_new_email = html.escape(new_email)
    subject = "Your Biocommons Access email address was updated"
    body_content = f"""
        <p style="{_P}">Hello,</p>
        <p style="{_P}">The email address on your Biocommons Access account was updated.</p>
        <p style="{_P}"><strong>Old email:</strong> {safe_old_email}<br/><strong>New email:</strong> {safe_new_email}</p>
        <p style="{_P}">If you did not expect this change, please visit the <a href="{safe_portal_url}" style="{_A}" target="_blank" rel="noopener noreferrer">BioCommons Access Portal</a> or contact support.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


def compose_username_change_notification(
    old_username: str,
    new_username: str,
    settings: Settings,
) -> tuple[str, str]:
    """
    Notify a user that their username was updated.
    """
    portal_url = settings.aai_portal_url or ""
    safe_portal_url = html.escape(portal_url)
    safe_old_username = html.escape(old_username)
    safe_new_username = html.escape(new_username)
    subject = "Your Biocommons Access username was updated"
    body_content = f"""
        <p style="{_P}">Hello,</p>
        <p style="{_P}">The username on your Biocommons Access account was updated by your service administrator.</p>
        <p style="{_P}"><strong>Old username:</strong> {safe_old_username}<br/><strong>New username:</strong> {safe_new_username}</p>
        <p style="{_P}">If you did not expect this change, please visit the <a href="{safe_portal_url}" style="{_A}" target="_blank" rel="noopener noreferrer">BioCommons Access Portal</a> or contact support.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


def compose_email_change_otp_email(
    code: str,
    target_email: str,
    expiration_minutes: int,
    portal_url: str = "",
) -> tuple[str, str]:
    """
    Email OTP for confirming an email address change.
    """
    safe_target_email = html.escape(target_email)
    safe_code = html.escape(code)
    subject = "Confirm your new BioCommons Access email address"
    body_content = f"""
        <p style="{_P}">Hello,</p>
        <p style="{_P}">We received a request to change the email address of your BioCommons Access account to {safe_target_email}.</p>
        <p style="{_P}">Your verification code is <strong>{safe_code}</strong>.</p>
        <p style="{_P}">This code is valid for {expiration_minutes} minutes.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


def compose_welcome_email(
    first_name: str,
    portal_url: str,
) -> tuple[str, str]:
    """
    Welcome email sent to new users after email verification
    and to users who have been successfully migrated.
    """
    safe_first_name = html.escape(first_name)
    safe_portal_url = html.escape(portal_url)
    subject = "Welcome to BioCommons Access"
    body_content = f"""
        <p style="{_P}">Dear {safe_first_name},</p>
        <p style="{_P}">Welcome to your new BioCommons Access account!</p>
        <p style="{_P}"><strong><a href="https://www.biocommons.org.au/access" target="_blank" rel="noopener noreferrer" style="{_A}">BioCommons Access</a> is your key to unlocking analysis services and research data across the Australian BioCommons ecosystem. A single log in offers convenient and secure access to a growing number of services.</strong></p>
        <p style="{_P}">Consider bookmarking <a href="{safe_portal_url}" target="_blank" rel="noopener noreferrer" style="{_A}">{safe_portal_url}</a> for future logins. Use the BioCommons Access portal to access connected services, update your profile and apply for Service Bundles.</p>
        <table align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="margin: 24px auto;">
          <tr>
            <td align="center">
              <a href="{safe_portal_url}" target="_blank" rel="noopener noreferrer" style="display: inline-block; background-color: #171717; color: #ffffff; font-weight: 600; padding: 12px 18px; line-height: 20px; border-radius: 8px; text-decoration: none; font-size: 14px;">BioCommons Access Login</a>
            </td>
          </tr>
        </table>
        <p style="{_P}">The BioCommons Access portal contains links to services including Galaxy Australia and the Bioplatforms Australia Data Portal. You can also access these services directly with your BioCommons Access credentials.</p>
        <p style="{_P}">You can <a href="https://biocommonsaccess.freshdesk.com/support/home" target="_blank" rel="noopener noreferrer" style="{_A}">access support for your BioCommons Access account</a>, or find help related to <a href="https://www.biocommons.org.au/access-existing-users" target="_blank" rel="noopener noreferrer" style="{_A}">migrating existing Galaxy Australia or Bioplatforms Australia Data Portal accounts</a>.</p>
        <p style="{_P}">To hear when future services come online, as well as relevant training and other ways to connect, <a href="https://www.biocommons.org.au/subscribe" target="_blank" rel="noopener noreferrer" style="{_A}">subscribe to the Australian BioCommons monthly newsletter</a>.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">The Australian BioCommons<br/><a href="https://www.biocommons.org.au" target="_blank" rel="noopener noreferrer" style="{_A}">www.biocommons.org.au</a></p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)


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
    portal_url = settings.aai_portal_url or ""
    reason = request_reason.strip() if request_reason else "Not provided"
    safe_first_name = html.escape(first_name)
    safe_bundle_name = html.escape(bundle_name)
    safe_reason = html.escape(reason)
    subject = f"Your {bundle_name} Service Bundle request has been received"
    body_content = f"""
        <p style="{_P}">Dear {safe_first_name},</p>
        <p style="{_P}">Thank you for submitting a request to join the <strong>{safe_bundle_name}</strong> Service Bundle. Your request has been received and is currently under review.</p>
        <p style="{_P}"><strong>Bundle requested:</strong> {safe_bundle_name}<br/><strong>Reason provided:</strong> {safe_reason}</p>
        <p style="{_P}">A bundle administrator will review your request. If your request is approved, you will receive a confirmation email with further details.</p>
        <p style="{_P_SIGN_OFF}">Thank you,</p>
        <p style="{_P}">BioCommons Access team</p>
    """
    return subject, _wrap_email_html(subject, subject, body_content, portal_url)
