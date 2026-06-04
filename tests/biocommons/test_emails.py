from types import SimpleNamespace

from biocommons.emails import (
    compose_bundle_request_confirmation_email,
    compose_email_change_notification,
    compose_email_change_otp_email,
    compose_group_approval_email,
    compose_group_membership_approved_email,
    compose_group_membership_rejected_email,
    compose_incorrect_email_notification_email,
    compose_username_change_notification,
    compose_welcome_email,
    format_first_name,
    format_full_name,
    get_default_sender_email,
    get_group_admin_contacts,
    render_default_email_html,
    render_html_template,
)
from db.models import Auth0Role, BiocommonsGroup
from tests.datagen import RoleUserDataFactory


def assert_email_contains(html: str, *expected: str) -> None:
    normalized_html = " ".join(html.split())
    for text in expected:
        assert " ".join(text.split()) in normalized_html


def test_get_default_sender(mock_settings):
    email = get_default_sender_email(mock_settings)
    assert email == mock_settings.no_reply_email_sender


def test_get_default_sender_email_fetches_settings(mock_settings, mocker):
    mocker.patch('biocommons.emails.get_settings', return_value=mock_settings)
    email = get_default_sender_email()
    assert email == mock_settings.no_reply_email_sender


def test_format_first_name_prefers_given_name():
    assert format_first_name(full_name="Ada Lovelace", given_name="  Ada  ") == "Ada"


def test_format_first_name_uses_full_name_first_token():
    assert format_first_name(full_name="  Grace Hopper  ", given_name=None) == "Grace"


def test_format_first_name_falls_back():
    assert format_first_name(full_name="  ", given_name="  ", fallback="Admin") == "Admin"


def test_format_full_name_prefers_full_name():
    assert format_full_name(
        full_name="  Ada Lovelace  ",
        given_name="Ada",
        family_name="Lovelace",
        fallback="Unknown",
    ) == "Ada Lovelace"


def test_format_full_name_joins_given_and_family():
    assert format_full_name(
        full_name=None,
        given_name="  Ada  ",
        family_name="  Lovelace  ",
        fallback="Unknown",
    ) == "Ada Lovelace"


def test_format_full_name_falls_back():
    assert format_full_name(
        full_name=None,
        given_name="  ",
        family_name=None,
        fallback="Unknown",
    ) == "Unknown"


def test_get_group_admin_contacts_dedupes_and_falls_back(mocker):
    role_one = Auth0Role(id="role-one", name="Role One")
    role_two = Auth0Role(id="role-two", name="Role Two")
    group = BiocommonsGroup(
        group_id="biocommons/group/tsi",
        name="Threatened Species Initiative",
        short_name="TSI",
        admin_roles=[role_one, role_two],
    )

    admin_1 = RoleUserDataFactory.build(user_id="auth0|1", email="a@example.com", name=None)
    admin_2 = RoleUserDataFactory.build(user_id="auth0|2", email=None, name=None)
    admin_3 = RoleUserDataFactory.build(user_id="auth0|3", email="a@example.com", name="Alice Smith")
    admin_4 = RoleUserDataFactory.build(user_id="auth0|4", email="b@example.com", name="  ")

    auth0_client = mocker.Mock()
    auth0_client.get_all_role_users.side_effect = lambda role_id: {
        "role-one": [admin_1, admin_2],
        "role-two": [admin_3, admin_4],
    }[role_id]
    auth0_client.get_user.side_effect = lambda user_id: {
        "auth0|1": SimpleNamespace(email="a@example.com", name=None, given_name=None),
        "auth0|2": SimpleNamespace(email="c@example.com", name="Charlie Brown", given_name=None),
        "auth0|4": SimpleNamespace(email="b@example.com", name="  ", given_name="Bea"),
    }[user_id]

    contacts = dict(get_group_admin_contacts(group=group, auth0_client=auth0_client))

    assert contacts == {
        "a@example.com": "Alice",
        "b@example.com": "Bea",
        "c@example.com": "Charlie",
    }


def test_render_default_email_html_renders_common_email_frame():
    html = render_default_email_html(
        title="Test & Email",
        preheader="Preview text",
        body_html="<p>Hello <strong>Ada</strong></p>",
        portal_url="https://portal.example.org",
        icon_url="https://example.org/icon.png",
        logo_url="https://example.org/logo.png",
    )

    assert_email_contains(
        html,
        "<title>Test &amp; Email</title>",
        "Preview text",
        '<a href="https://portal.example.org"',
        '<img src="https://example.org/logo.png" alt="BioCommons Logo"',
        '<img src="https://example.org/icon.png"',
        "<p>Hello <strong>Ada</strong></p>",
        "FAQs or contact support",
    )


def test_render_html_template_renders_template_with_default_styles():
    html = render_html_template(
        "emails/group_approval.html",
        admin_first_name="Ada <Admin>",
        bundle_name="Galaxy & Data",
        requester_full_name="Grace Hopper",
        requester_email="grace@example.org",
        reason="Research access",
    )

    assert_email_contains(
        html,
        "Dear Ada &lt;Admin&gt;",
        "Galaxy &amp; Data Service Bundle",
        "<strong>Name:</strong> Grace Hopper",
        "<strong>Email:</strong> grace@example.org",
        "<strong>Reason:</strong> Research access",
        "font-size: 16px",
    )


def test_compose_group_approval_email(mock_settings):
    subject, html = compose_group_approval_email(
        admin_first_name="Ada",
        bundle_name="Threatened Species",
        requester_full_name="Grace Hopper",
        requester_email="grace@example.org",
        request_reason="Genome analysis",
        settings=mock_settings,
    )

    assert subject == "Threatened Species Service Bundle request"
    assert_email_contains(
        html,
        "Dear Ada,",
        "new request for access to the Threatened Species Service Bundle",
        "<strong>Name:</strong> Grace Hopper",
        "<strong>Email:</strong> grace@example.org",
        "<strong>Reason:</strong> Genome analysis",
    )


def test_compose_group_approval_email_defaults_missing_reason(mock_settings):
    _, html = compose_group_approval_email(
        admin_first_name="Ada",
        bundle_name="Threatened Species",
        requester_full_name="Grace Hopper",
        requester_email="grace@example.org",
        request_reason=None,
        settings=mock_settings,
    )

    assert "<strong>Reason:</strong> Not provided" in html


def test_compose_group_membership_approved_email(mock_settings):
    subject, html = compose_group_membership_approved_email(
        group_name="Threatened Species",
        group_short_name="TSI",
        first_name="Grace",
        settings=mock_settings,
    )

    assert subject == "Threatened Species Service Bundle access approved"
    assert_email_contains(
        html,
        "Dear Grace,",
        "Your request to join the Threatened Species (TSI) service bundle has been approved.",
        "Go to BioCommons Access Portal",
        f'href="{mock_settings.aai_portal_url}"',
    )


def test_compose_group_membership_approved_email_omits_duplicate_short_name(mock_settings):
    _, html = compose_group_membership_approved_email(
        group_name="Galaxy",
        group_short_name="Galaxy",
        first_name="Grace",
        settings=mock_settings,
    )

    assert "Galaxy (Galaxy) service bundle" not in html
    assert "Galaxy service bundle has been approved" in html


def test_compose_email_change_notification(mock_settings):
    subject, html = compose_email_change_notification(
        old_email="old@example.org",
        new_email="new@example.org",
        settings=mock_settings,
    )

    assert subject == "Your Biocommons Access email address was updated"
    assert_email_contains(
        html,
        "The email address on your Biocommons Access account was updated.",
        "<strong>Old email:</strong> old@example.org",
        "<strong>New email:</strong> new@example.org",
        f'href="{mock_settings.aai_portal_url}"',
    )


def test_compose_username_change_notification(mock_settings):
    subject, html = compose_username_change_notification(
        old_username="old-user",
        new_username="new-user",
        settings=mock_settings,
    )

    assert subject == "Your Biocommons Access username was updated"
    assert_email_contains(
        html,
        "The username on your Biocommons Access account was updated by your service administrator.",
        "<strong>Old username:</strong> old-user",
        "<strong>New username:</strong> new-user",
        f'href="{mock_settings.aai_portal_url}"',
    )


def test_compose_email_change_otp_email():
    subject, html = compose_email_change_otp_email(
        code="123456",
        target_email="new@example.org",
        expiration_minutes=15,
        portal_url="https://portal.example.org",
    )

    assert subject == "Confirm your new BioCommons Access email address"
    assert_email_contains(
        html,
        "change the email address of your BioCommons Access account to new@example.org",
        "Your verification code is <strong>123456</strong>.",
        "This code is valid for 15 minutes.",
        'href="https://portal.example.org"',
    )


def test_compose_welcome_email():
    subject, html = compose_welcome_email(
        first_name="Grace",
        portal_url="https://portal.example.org",
    )

    assert subject == "Welcome to BioCommons Access"
    assert_email_contains(
        html,
        "Dear Grace,",
        "Welcome to your new BioCommons Access account!",
        "BioCommons Access Login",
        'href="https://portal.example.org"',
        "subscribe to the Australian BioCommons monthly newsletter",
    )


def test_compose_group_membership_rejected_email(mock_settings):
    subject, html = compose_group_membership_rejected_email(
        group_name="Threatened Species",
        username="Grace",
        settings=mock_settings,
    )

    assert subject == "Threatened Species Initiative service bundle request"
    assert_email_contains(
        html,
        "Dear Grace,",
        "Thank you for your interest in the Threatened Species Bundle.",
        "You have not been granted access.",
        "Threatened Species Initiative",
        "Request access to specialist tools",
        "help@bioplatforms.com",
        "BioCommons Access Team",
    )


def test_compose_bundle_request_confirmation_email(mock_settings):
    subject, html = compose_bundle_request_confirmation_email(
        first_name="Grace",
        bundle_name="Threatened Species",
        request_reason="Genome analysis",
        settings=mock_settings,
    )

    assert subject == "Your Threatened Species Service Bundle request has been received"
    assert_email_contains(
        html,
        "Dear Grace,",
        "Thank you for submitting a request to join the <strong>Threatened Species</strong> Service Bundle.",
        "<strong>Bundle requested:</strong> Threatened Species",
        "<strong>Reason provided:</strong> Genome analysis",
    )


def test_compose_bundle_request_confirmation_email_defaults_missing_reason(mock_settings):
    _, html = compose_bundle_request_confirmation_email(
        first_name="Grace",
        bundle_name="Threatened Species",
        request_reason=None,
        settings=mock_settings,
    )

    assert "<strong>Reason provided:</strong> Not provided" in html


def test_compose_incorrect_email_notification_email_trims_portal_url_trailing_slash(mock_settings):
    mock_settings.aai_portal_url = "https://portal.example.org/"

    subject, html = compose_incorrect_email_notification_email(
        first_name="Grace",
        incorrect_email="grace.typo@example.org",
        settings=mock_settings,
    )

    assert subject == "Did you register for a BioCommons Access account?"
    assert_email_contains(
        html,
        "Hi Grace",
        "grace.typo@example.org",
        'href="https://portal.example.org/register"',
        "https://portal.example.org/register",
        "BioCommons Access registration",
    )
    assert "https://portal.example.org//register" not in html
