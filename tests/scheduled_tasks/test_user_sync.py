from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx2 import HTTPStatusError

from scheduled_tasks.sync.users import (
    Auth0ExportIdentityIndex,
    UserSyncRecord,
    UserSyncType,
    format_auth0_identity_id,
    normalize_auth0_user,
    normalize_exported_user,
    soft_delete_users_missing_from_auth0,
    sync_exported_users,
    sync_users_from_records,
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


@pytest.mark.parametrize(
    ("user_id", "account_type", "aaf_only"),
    [
        ("auth0|database", BiocommonsUserAccountType.AUTH0, False),
        ("auth0|linked", BiocommonsUserAccountType.AAF, False),
        ("oidc|AAF|pure", BiocommonsUserAccountType.AAF, True),
    ],
)
def test_sync_exported_users_keeps_user_deleted_when_live_auth0_is_blocked(
    test_db_session, mocker, user_id, account_type, aaf_only
):
    user = _db_user(
        test_db_session,
        id=user_id,
        email="blocked@example.com",
        username="blocked_user",
        account_type=account_type,
    )
    user.delete(test_db_session, commit=False)
    test_db_session.flush()
    live_user = Auth0UserDataFactory.build(
        user_id=user.id,
        email=user.email,
        username=None if aaf_only else user.username,
        blocked=True,
        app_metadata=Auth0ReadAppMetadata(
            account_type=account_type,
            username=user.username if aaf_only else None,
            aaf_only=aaf_only,
        ),
    )
    exported = _exported_user(user_id=user.id).model_copy(
        update={
            "email": "stale@example.com",
            "username": "stale_username",
            "account_type": account_type,
        }
    )
    client = MagicMock()
    client.get_user.return_value = live_user
    sleep = mocker.patch("scheduled_tasks.sync.users.time.sleep")

    summary = sync_exported_users(
        test_db_session, [exported], auth0_client=client, commit=False
    )

    assert summary.restored == 0
    assert user.is_deleted is True
    assert user.email == "blocked@example.com"
    assert user.username == "blocked_user"
    client.get_user.assert_called_once_with(user.id)
    sleep.assert_called_once_with(0.5)


def test_sync_exported_users_restores_with_live_aaf_profile(test_db_session):
    user = _db_user(
        test_db_session,
        id="oidc|AAF|restored",
        email="old@example.edu.au",
        username="old_username",
        account_type=BiocommonsUserAccountType.AAF,
    )
    user.delete(test_db_session, commit=False)
    test_db_session.flush()
    client = MagicMock()
    client.get_user.return_value = Auth0UserDataFactory.build(
        user_id=user.id,
        email="current@example.edu.au",
        username=None,
        email_verified=False,
        blocked=False,
        app_metadata=Auth0ReadAppMetadata(
            account_type=BiocommonsUserAccountType.AAF,
            username="current_username",
            aaf_only=True,
            aaf_registration_complete=True,
        ),
    )

    summary = sync_exported_users(
        test_db_session,
        [_exported_user(user_id=user.id)],
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert summary.restored == 1
    assert user.is_deleted is False
    assert user.email == "current@example.edu.au"
    assert user.username == "current_username"
    assert user.account_type == BiocommonsUserAccountType.AAF
    assert user.email_verified is True
    client.get_user.assert_called_once_with(user.id)


@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize(
    ("db_type", "export_type", "live_type"),
    [
        ("auth0", "aaf", "auth0"),
        ("aaf", "auth0", "aaf"),
        ("auth0", "aaf", "aaf"),
        ("aaf", "auth0", "auth0"),
    ],
)
def test_sync_users_from_records_uses_live_account_type(
    test_db_session, mocker, db_type, export_type, live_type, blocked
):
    user = _db_user(
        test_db_session,
        id="auth0|type-change",
        email="type-change@example.com",
        username="type_change",
        email_verified=True,
        account_type=BiocommonsUserAccountType(db_type),
    )
    record = UserSyncRecord(
        user_id=user.id,
        email="stale@example.com",
        username="stale_username",
        account_type=BiocommonsUserAccountType(export_type),
        blocked=blocked,
    )
    client = MagicMock()
    client.get_user.return_value = Auth0UserDataFactory.build(
        user_id=user.id,
        email=user.email,
        username=user.username,
        email_verified=True,
        blocked=False,
        app_metadata=Auth0ReadAppMetadata(account_type=live_type),
    )
    warning = mocker.patch("scheduled_tasks.sync.users.logger.warning")

    summary = sync_users_from_records(
        test_db_session,
        [record],
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert user.account_type == live_type
    assert user.email == "type-change@example.com"
    assert user.username == "type_change"
    assert user.is_deleted is False
    assert summary.updated == int(db_type != live_type)
    assert summary.skipped_unchanged == int(db_type == live_type)
    client.get_user.assert_called_once_with(user.id)
    assert warning.call_count == int(db_type != live_type)


@pytest.mark.parametrize("restore", [False, True])
@pytest.mark.parametrize("failure", ["not_found", "api_error", "network_error"])
def test_sync_users_from_records_skips_sensitive_change_if_live_lookup_unavailable(
    test_db_session, mocker, restore, failure
):
    user = _db_user(
        test_db_session,
        id="auth0|lookup-failure",
        email="lookup-failure@example.com",
        username="lookup_failure",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    if restore:
        user.delete(test_db_session, commit=False)
    test_db_session.flush()
    record = UserSyncRecord(
        user_id=user.id,
        email="stale@example.com",
        username="stale_username",
        account_type=(
            BiocommonsUserAccountType.AUTH0 if restore else BiocommonsUserAccountType.AAF
        ),
    )
    next_record = UserSyncRecord(
        user_id="auth0|next-user", email="next@example.com", username="next_user"
    )
    client = MagicMock()
    if failure in ("not_found", "api_error"):
        client.get_user.side_effect = HTTPStatusError(
            "Lookup failed",
            request=mocker.Mock(),
            response=mocker.Mock(status_code=404 if failure == "not_found" else 429),
        )
    else:
        client.get_user.side_effect = RuntimeError("Network unavailable")
    sleep = mocker.patch("scheduled_tasks.sync.users.time.sleep")

    summary = sync_users_from_records(
        test_db_session,
        [record, next_record],
        auth0_client=client,
        commit=False,
    )

    assert summary.skipped_invalid == 1
    assert summary.created == 1
    test_db_session.refresh(user)
    assert user.is_deleted is restore
    assert user.account_type == BiocommonsUserAccountType.AUTH0
    assert user.email == "lookup-failure@example.com"
    assert user.username == "lookup_failure"
    client.get_user.assert_called_once_with(user.id)
    sleep.assert_called_once_with(0.5)


def test_sync_users_from_records_ordinary_changes_do_not_need_live_lookup(test_db_session):
    user = _db_user(
        test_db_session,
        id="auth0|ordinary",
        email="ordinary@example.com",
        username="ordinary",
        email_verified=True,
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    record = UserSyncRecord(
        user_id=user.id,
        email=user.email,
        username="updated_username",
        email_verified=True,
    )
    client = MagicMock()

    summary = sync_users_from_records(
        test_db_session,
        [
            record,
            record,
            UserSyncRecord(user_id="auth0|new", email="new@example.com", username="new_user"),
        ],
        auth0_client=client,
        commit=False,
    )

    assert summary.updated == 1
    assert summary.skipped_unchanged == 1
    assert summary.created == 1
    assert user.username == "updated_username"
    client.get_user.assert_not_called()


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


def test_soft_delete_users_missing_from_auth0_deletes_missing_auth0_user(test_db_session, mocker):
    user = _db_user(
        test_db_session,
        id="auth0|missing",
        other_user_id=None,
        email="missing@example.com",
        username="missing_user",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    client = MagicMock()
    client.get_user.side_effect = _auth0_not_found(mocker)

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 1
    assert user.is_deleted is True
    client.get_user.assert_called_once_with(user.id)


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

    client = MagicMock()
    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([exported]),
        auth0_client=client,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    client.get_user.assert_not_called()


def test_soft_delete_users_missing_from_auth0_deletes_linked_aaf_user_absent_by_both_ids(
    test_db_session, mocker
):
    user = _db_user(
        test_db_session,
        id="auth0|primary",
        other_user_id="oidc|AAF|linked-aaf",
        email="linked-missing@example.com",
        username="linked_missing_user",
        account_type=BiocommonsUserAccountType.AAF,
    )
    client = MagicMock()
    client.get_user.side_effect = _auth0_not_found(mocker)

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 1
    assert user.is_deleted is True
    assert [call.args[0] for call in client.get_user.call_args_list] == [
        user.id,
        user.other_user_id,
    ]


@pytest.mark.parametrize("lookup", ["not_found", "found", "api_error", "network_error"])
def test_soft_delete_users_missing_from_auth0_requires_live_404_for_aaf_only_user(
    test_db_session, mocker, lookup
):
    user = _db_user(
        test_db_session,
        id="oidc|AAF|pure",
        other_user_id=None,
        email="pure@example.edu.au",
        username="pure_user",
        account_type=BiocommonsUserAccountType.AAF,
    )
    client = MagicMock()
    if lookup == "not_found":
        client.get_user.side_effect = _auth0_not_found(mocker)
    elif lookup == "api_error":
        client.get_user.side_effect = HTTPStatusError(
            "Rate limited", request=mocker.Mock(), response=mocker.Mock(status_code=429)
        )
    elif lookup == "network_error":
        client.get_user.side_effect = RuntimeError("Lookup failed")
    warning = mocker.patch("scheduled_tasks.sync.users.logger.warning")

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )
    test_db_session.flush()
    test_db_session.refresh(user)

    assert deleted == int(lookup == "not_found")
    assert user.is_deleted is (lookup == "not_found")
    client.get_user.assert_called_once_with(user.id)
    assert warning.call_count == int(lookup in ("api_error", "network_error"))


@pytest.mark.parametrize("linked_identity", [False, True])
def test_soft_delete_users_missing_from_auth0_keeps_aaf_only_user_seen_in_export(
    test_db_session, mocker, linked_identity
):
    user = _db_user(
        test_db_session,
        id="oidc|AAF|pure",
        other_user_id=None,
        email="pure@example.edu.au",
        username="pure_user",
        account_type=BiocommonsUserAccountType.AAF,
    )
    exported = _exported_user(
        user_id="auth0|primary" if linked_identity else user.id,
        identities=(
            [Auth0Identity(connection="AAF", provider="oidc", user_id="pure", isSocial=False)]
            if linked_identity else []
        ),
    )
    client = MagicMock()
    client.get_user.side_effect = _auth0_not_found(mocker)

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([exported]),
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    client.get_user.assert_not_called()


def test_soft_delete_users_missing_from_auth0_skips_ambiguous_aaf_user(test_db_session, mocker):
    user = _db_user(
        test_db_session,
        id="auth0|aaf-without-link",
        other_user_id=None,
        email="aaf-without-link@example.com",
        username="aaf_without_link",
        account_type=BiocommonsUserAccountType.AAF,
    )
    client = MagicMock()
    client.get_user.side_effect = _auth0_not_found(mocker)

    deleted = soft_delete_users_missing_from_auth0(
        test_db_session,
        Auth0ExportIdentityIndex.from_user_list([_exported_user(user_id="auth0|other")]),
        auth0_client=client,
        live_lookup_delay_seconds=0,
        commit=False,
    )

    assert deleted == 0
    assert user.is_deleted is False
    client.get_user.assert_not_called()


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
