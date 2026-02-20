from types import SimpleNamespace

from biocommons.emails import (
    format_first_name,
    format_full_name,
    get_default_sender_email,
    get_group_admin_contacts,
)
from db.models import Auth0Role, BiocommonsGroup
from tests.datagen import RoleUserDataFactory


def test_get_default_sender(mock_settings):
    email = get_default_sender_email(mock_settings)
    assert email == mock_settings.default_email_sender


def test_get_default_sender_email_fetches_settings(mock_settings, mocker):
    mocker.patch('biocommons.emails.get_settings', return_value=mock_settings)
    email = get_default_sender_email()
    assert email == mock_settings.default_email_sender


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
