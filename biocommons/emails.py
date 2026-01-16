from config import Settings, get_settings
from db.models import GroupMembership


def get_default_sender_email(settings: Settings | None = None) -> str:
    if settings is None:
        settings = get_settings()
    return settings.default_email_sender or f"{settings.environment}@aai.test.biocommons.org.au"


def compose_group_approval_email(request: GroupMembership, settings: Settings) -> tuple[str, str]:
    subject = f"New request to join {request.group.name}"
    body_html = f"""
        <p>A new user has requested access to the {request.group.name} group.</p>
        <p><strong>User:</strong> {request.user.email}</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the BioCommons account dashboard</a> to review and approve access.</p>
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
        <p>You now have access to all services included with this bundle. Sign in to the <a href="{portal_url}">AAI Portal</a> to review the bundle details and launch its platforms.</p>
        <p>If you have any questions, please reply to this email.</p>
    """
    return subject, body_html
