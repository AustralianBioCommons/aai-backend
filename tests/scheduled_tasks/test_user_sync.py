from types import SimpleNamespace
from unittest.mock import MagicMock

from httpx2 import HTTPStatusError

from scheduled_tasks.sync.users import (
    Auth0ExportIdentityIndex,
    UserSyncType,
    format_auth0_identity_id,
    normalize_auth0_user,
    normalize_exported_user,
    soft_delete_users_missing_from_auth0,
    user_exists_in_auth0,
)
from scheduled_tasks.tasks import ExportedUser
from schemas.biocommons import (
    Auth0Identity,
    Auth0ReadAppMetadata,
    BiocommonsUserAccountType,
)
from tests.datagen import Auth0UserDataFactory
from tests.db.datagen import BiocommonsUserFactory


def test_normalize_exported_user_classifies_aaf_only_user():
    exported = ExportedUser(
        user_id="auth0|aaf-only",
        email="aaf-only@example.edu.au",
        email_verified=False,
        username=None,
        metadata_username="aaf_only",
        blocked=False,
        updated_at="2024-01-01T12:00:00+00:00",
        account_type=BiocommonsUserAccountType.AAF,
        aaf_only=True,
        aaf_registration_complete=True,
    )

    record = normalize_exported_user(exported)

    assert record.sync_type == UserSyncType.AAF_ONLY
    assert record.username == "aaf_only"
    assert record.metadata_username == "aaf_only"
    assert record.aaf_only is True
    assert record.aaf_registration_complete is True


def test_normalize_auth0_user_classifies_linked_aaf_user():
    auth0_user = Auth0UserDataFactory.build(
        user_id="auth0|linked",
        email="linked@example.com",
        username="linked_user",
        app_metadata=Auth0ReadAppMetadata(
            account_type=BiocommonsUserAccountType.AAF,
            linking_completed=True,
            aaf_only=False,
        ),
    )

    record = normalize_auth0_user(auth0_user)

    assert record.sync_type == UserSyncType.AAF_LINKED
    assert record.username == "linked_user"
    assert record.linking_completed is True
    assert record.aaf_only is False


def test_normalize_auth0_user_uses_metadata_username_for_aaf_only_user():
    auth0_user = Auth0UserDataFactory.build(
        user_id="oidc|AAF|aaf-only",
        email="aaf-only@example.edu.au",
        username=None,
        app_metadata=Auth0ReadAppMetadata(
            username="aaf_only",
            aaf_only=True,
            aaf_registration_complete=True,
        ),
    )

    record = normalize_auth0_user(auth0_user)

    assert record.account_type == BiocommonsUserAccountType.AAF
    assert record.sync_type == UserSyncType.AAF_ONLY
    assert record.username == "aaf_only"
    assert record.metadata_username == "aaf_only"


def test_normalize_exported_user_infers_aaf_type_from_aaf_only_metadata():
    exported = SimpleNamespace(
        user_id="oidc|AAF|aaf-only",
        email="aaf-only@example.edu.au",
        email_verified=False,
        username=None,
        metadata_username="aaf_only",
        blocked=False,
        updated_at=None,
        account_type=None,
        aaf_only=True,
        aaf_registration_complete=None,
        linking_completed=True,
        linking_completed_at=None,
    )

    record = normalize_exported_user(exported)

    assert record.account_type == BiocommonsUserAccountType.AAF
    assert record.sync_type == UserSyncType.AAF_ONLY
    assert record.username == "aaf_only"


def test_format_auth0_identity_id_reconstructs_provider_ids():
    assert format_auth0_identity_id(
        Auth0Identity(
            connection="Username-Password-Authentication",
            provider="auth0",
            user_id="abc123",
            isSocial=False,
        )
    ) == "auth0|abc123"
    assert format_auth0_identity_id(
        Auth0Identity(
            connection="AAF",
            provider="oidc",
            user_id="linked-aaf",
            isSocial=False,
        )
    ) == "oidc|AAF|linked-aaf"


def test_auth0_export_identity_index_from_user_list_includes_top_level_and_identity_ids():
    exported = _exported_user(
        user_id="auth0|primary",
        identities=[
            Auth0Identity(
                connection="AAF",
                provider="oidc",
                user_id="linked-aaf",
                isSocial=False,
            )
        ],
    )

    index = Auth0ExportIdentityIndex.from_user_list([exported])

    assert index.exported_user_ids == {"auth0|primary"}
    assert index.exported_identity_ids == {"oidc|AAF|linked-aaf"}
    assert index.exported_emails == {"primary@example.com"}


def test_soft_delete_users_missing_from_auth0_deletes_missing_auth0_user(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|missing",
        email="missing@example.com",
        username="missing_user",
        account_type=BiocommonsUserAccountType.AUTH0,
    )

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        commit=False,
    )

    assert deleted == 1
    assert user.is_deleted is True


def test_soft_delete_users_missing_from_auth0_keeps_user_found_by_live_lookup(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|late",
        email="late@example.com",
        username="late_user",
        account_type=BiocommonsUserAccountType.AUTH0,
        other_user_id=None,
    )
    auth0_client = MagicMock()
    auth0_client.get_user.return_value = object()

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=auth0_client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    auth0_client.get_user.assert_called_once_with(user.id)


def test_user_exists_in_auth0_sleeps_after_live_lookup(test_db_session, mocker):
    user = _db_user(
        test_db_session,
        id="auth0|live",
        email="live@example.com",
        username="live_user",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    auth0_client = MagicMock()
    sleep = mocker.patch("scheduled_tasks.sync.users.time.sleep")

    assert user_exists_in_auth0(auth0_client, user) is True
    sleep.assert_called_once_with(0.5)


def test_soft_delete_users_missing_from_auth0_keeps_linked_identity_found_by_live_lookup(
    test_db_session, mocker
):
    user = _db_user(
        test_db_session,
        id="auth0|primary",
        other_user_id="oidc|AAF|linked-aaf",
        email="linked-live@example.com",
        username="linked_live_user",
        account_type=BiocommonsUserAccountType.AAF,
    )
    auth0_client = MagicMock()
    auth0_client.get_user.side_effect = [
        _auth0_not_found(mocker),
        object(),
    ]

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=auth0_client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    assert auth0_client.get_user.call_args_list[0].args == ("auth0|primary",)
    assert auth0_client.get_user.call_args_list[1].args == ("oidc|AAF|linked-aaf",)


def test_soft_delete_users_missing_from_auth0_skips_delete_when_live_lookup_fails(
    test_db_session, mocker
):
    user = _db_user(
        test_db_session,
        id="auth0|lookup-error",
        email="lookup-error@example.com",
        username="lookup_error_user",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    auth0_client = MagicMock()
    auth0_client.get_user.side_effect = RuntimeError("lookup failed")
    warning = mocker.patch("scheduled_tasks.sync.users.logger.warning")

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=auth0_client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    warning.assert_called_once()
    assert warning.call_args.args[1] == user.id


def test_soft_delete_users_missing_from_auth0_keeps_linked_aaf_user_by_identity(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|primary",
        other_user_id="oidc|AAF|linked-aaf",
        email="linked@example.com",
        username="linked_user",
        account_type=BiocommonsUserAccountType.AAF,
    )
    exported = _exported_user(
        user_id="auth0|export-row",
        identities=[
            Auth0Identity(
                connection="AAF",
                provider="oidc",
                user_id="linked-aaf",
                isSocial=False,
            )
        ],
    )

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([exported]),
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False


def test_soft_delete_users_missing_from_auth0_deletes_linked_aaf_user_absent_by_both_ids(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|primary",
        other_user_id="oidc|AAF|linked-aaf",
        email="linked-missing@example.com",
        username="linked_missing_user",
        account_type=BiocommonsUserAccountType.AAF,
    )

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        commit=False,
    )

    assert deleted == 1
    assert user.is_deleted is True


def test_soft_delete_users_missing_from_auth0_skips_ambiguous_aaf_user(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|aaf-without-link",
        other_user_id=None,
        email="aaf-without-link@example.com",
        username="aaf_without_link",
        account_type=BiocommonsUserAccountType.AAF,
    )

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False


def _db_user(test_db_session, **kwargs):
    user = BiocommonsUserFactory.build(**kwargs)
    test_db_session.add(user)
    test_db_session.flush()
    return user


def _exported_user(
    *,
    user_id: str,
    identities: list[Auth0Identity] | None = None,
) -> ExportedUser:
    return ExportedUser(
        user_id=user_id,
        email="primary@example.com",
        email_verified=True,
        username="primary_user",
        blocked=False,
        updated_at="2024-01-01T12:00:00+00:00",
        identities=identities or [],
    )


def _auth0_not_found(mocker) -> HTTPStatusError:
    return HTTPStatusError(
        message="Not Found",
        request=mocker.Mock(),
        response=mocker.Mock(status_code=404),
    )
