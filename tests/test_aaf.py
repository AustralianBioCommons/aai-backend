from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import MagicMock, call
from urllib.parse import parse_qs, urlparse

import httpx2
import jwt
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, select

from auth.otp import OneTimePassword
from auth0.client import Auth0Client
from db.models import AccountMigrationRequest, BiocommonsUser, EmailChangeOtp
from routers.aaf import link_aaf_account, mark_user_aaf_only, migrate_auth0_to_aaf
from routers.biocommons_register import verify_registration_token
from schemas.aaf_migration import (
    MigrateToAafRequest,
    MigrationDirection,
    MigrationStatus,
)
from schemas.biocommons import (
    Auth0Identity,
    Auth0ReadAppMetadata,
    BiocommonsUserAccountType,
)
from tests.datagen import Auth0UserDataFactory, random_auth0_id
from tests.db.datagen import BiocommonsUserFactory


@pytest.fixture(params=["auth0|migration-primary", "oidc|AAF|migration-primary"])
def aaf_migration_account(
    request, test_db_session, persistent_factories, normal_user, as_normal_user,
    mock_auth0_client, mock_settings, mock_email_service, mocker,
):
    normal_user.access_token.sub = request.param
    db_user = BiocommonsUserFactory.create_sync(
        id=request.param,
        email="original@example.edu.au",
        account_type=BiocommonsUserAccountType.AAF,
    )
    test_db_session.commit()
    current_user = Auth0UserDataFactory.build(
        user_id=db_user.id,
        email=db_user.email,
        identities=[
            Auth0Identity(connection="AAF", provider="oidc", user_id="aaf-user", isSocial=False),
            Auth0Identity(
                connection=mock_settings.auth0_db_connection,
                provider="auth0", user_id=request.param.removeprefix("auth0|") if request.param.startswith("auth0|") else "database-user", isSocial=False,
            ),
        ],
        app_metadata={"account_type": "aaf", "linking_completed": True, "registration_from": "biocommons", "aaf_migration": None},
        blocked=False,
    )
    remote_users = {current_user.user_id: current_user}
    mock_auth0_client.remote_users = remote_users
    mock_auth0_client.get_user.side_effect = lambda user_id: remote_users[user_id]
    mock_auth0_client.search_users_by_email.side_effect = lambda email, connection: [
        user for user in remote_users.values()
        if user.email.lower() == email.lower()
        and any(identity.connection == connection for identity in user.identities)
    ]

    def update_user(user_id, update_data):
        target = remote_users[user_id]
        if target.user_id.startswith("auth0|"):
            for field in ("email", "email_verified"):
                value = getattr(update_data, field)
                if value is not None:
                    setattr(target, field, value)
        if update_data.blocked is not None:
            target.blocked = update_data.blocked
        if update_data.app_metadata is not None:
            target.app_metadata = Auth0ReadAppMetadata.model_validate({
                **target.app_metadata.model_dump(),
                **update_data.app_metadata.model_dump(exclude_none=True),
            })
        return target

    def create_user(user, verify_email):
        target = Auth0UserDataFactory.build(
            user_id="auth0|new-database-user", email=user.email,
            blocked=user.blocked, email_verified=user.email_verified,
            app_metadata=user.app_metadata.model_dump(),
            identities=[Auth0Identity(connection=user.connection, provider="auth0", user_id="new-database-user", isSocial=False)],
        )
        remote_users[target.user_id] = target
        return target

    mock_auth0_client.update_user.side_effect = update_user
    mock_auth0_client.create_user.side_effect = create_user
    mocker.patch.object(mock_email_service, "send_email_change_otp", create=True)
    return db_user, current_user


def test_migrate_aaf_to_auth0_reuses_linked_identity(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_settings, mock_email_service,
):
    db_user, current_user = aaf_migration_account
    old_otp = EmailChangeOtp(
        user_id=db_user.id,
        target_email="previous@example.com",
        otp_hash=OneTimePassword.generate().hash,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    test_db_session.add(old_otp)
    test_db_session.commit()
    response = test_client.post(
        "/aaf/migrate/aaf-to-auth0",
        json={"new_email": "new@example.com", "password": "New-password123!"},
    )

    assert response.status_code == HTTPStatus.OK
    mock_auth0_client.create_user.assert_not_called()
    mock_auth0_client.search_users_by_email.assert_not_called()
    updates = mock_auth0_client.update_user.call_args_list
    assert len(updates) == 3
    assert all(update.kwargs["user_id"] == current_user.user_id for update in updates)
    email_update, password_update, block_update = [update.kwargs["update_data"] for update in updates]
    assert email_update.connection == mock_settings.auth0_db_connection
    assert email_update.email == "new@example.com"
    assert email_update.email_verified is False
    assert email_update.verify_email is False
    assert email_update.blocked is True
    assert email_update.app_metadata.account_type == BiocommonsUserAccountType.AAF
    assert email_update.app_metadata.aaf_migration.user_id == current_user.user_id
    assert password_update.connection == mock_settings.auth0_db_connection
    assert password_update.password == "New-password123!"
    assert password_update.email is None
    assert password_update.email_verified is None
    assert block_update.blocked is True
    assert block_update.app_metadata is None
    assert current_user.app_metadata.linking_completed is True
    if current_user.user_id.startswith("oidc|"):
        assert current_user.email == "original@example.edu.au"
        assert current_user.email_verified is True

    migration = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert migration.id == response.json()["migration_id"]
    assert migration.auth0_user_id == current_user.user_id
    assert migration.direction == MigrationDirection.AAF_TO_AUTH0
    assert migration.status == MigrationStatus.PENDING
    test_db_session.refresh(old_otp)
    assert old_otp.is_active is False
    otp = test_db_session.exec(select(EmailChangeOtp).where(EmailChangeOtp.is_active.is_(True))).one()
    sent = mock_email_service.send_email_change_otp.call_args.kwargs
    assert sent["aaf_migration"] is True
    assert "migration_id" not in sent
    assert sent["target_email"] == otp.target_email == "new@example.com"
    assert OneTimePassword.check_code(code=sent["code"], hash=otp.otp_hash)
    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert db_user.email == "original@example.edu.au"


@pytest.mark.parametrize("other_identity", [
    Auth0Identity(connection="other-db", provider="auth0", user_id="other", isSocial=False),
    Auth0Identity(connection="Username-Password-Authentication", provider="oidc", user_id="other", isSocial=False),
])
def test_migrate_aaf_to_auth0_creates_identity_when_no_matching_db_identity(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_settings, mock_email_service, other_identity,
):
    db_user, current_user = aaf_migration_account
    current_user.identities = [current_user.identities[0], other_identity]

    response = test_client.post(
        "/aaf/migrate/aaf-to-auth0",
        json={"new_email": "new@example.com", "password": "New-password123!"},
    )

    assert response.status_code == HTTPStatus.OK
    mock_auth0_client.update_user.assert_not_called()
    mock_auth0_client.create_user.assert_called_once()
    args, kwargs = mock_auth0_client.create_user.call_args
    registration = args[0]
    assert kwargs == {"verify_email": False}
    assert registration.email == "new@example.com"
    assert registration.password == "New-password123!"
    assert registration.username == db_user.username
    assert registration.connection == mock_settings.auth0_db_connection
    assert registration.blocked is True
    assert registration.email_verified is False
    assert registration.app_metadata.account_type == BiocommonsUserAccountType.AUTH0
    migration = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert migration.auth0_user_id == "auth0|new-database-user"
    mock_email_service.send_email_change_otp.assert_called_once()


@pytest.mark.parametrize("reason, expected_status", [("blocked", HTTPStatus.FORBIDDEN), ("ambiguous", HTTPStatus.CONFLICT)])
def test_migrate_aaf_to_auth0_rejects_unsafe_reuse(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_email_service, reason, expected_status,
):
    _, current_user = aaf_migration_account
    if reason == "blocked":
        current_user.blocked = True
    else:
        current_user.identities.append(current_user.identities[1].model_copy(update={"user_id": "another-db-user"}))

    response = test_client.post(
        "/aaf/migrate/aaf-to-auth0",
        json={"new_email": "new@example.com", "password": "New-password123!"},
    )

    assert response.status_code == expected_status
    mock_auth0_client.update_user.assert_not_called()
    mock_auth0_client.create_user.assert_not_called()
    mock_email_service.send_email_change_otp.assert_not_called()
    assert test_db_session.exec(select(AccountMigrationRequest)).all() == []
    assert test_db_session.exec(select(EmailChangeOtp)).all() == []


@pytest.mark.parametrize("failed_step", [0, 1, 2])
def test_migrate_aaf_to_auth0_does_not_send_otp_after_update_failure(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_email_service, failed_step,
):
    _, current_user = aaf_migration_account
    results = [current_user, current_user, current_user]
    results[failed_step] = ValueError("Auth0 update failed")
    mock_auth0_client.update_user.side_effect = results

    response = test_client.post(
        "/aaf/migrate/aaf-to-auth0",
        json={"new_email": "new@example.com", "password": "New-password123!"},
    )

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    mock_email_service.send_email_change_otp.assert_not_called()
    assert test_db_session.exec(select(AccountMigrationRequest)).all() == []
    assert test_db_session.exec(select(EmailChangeOtp)).all() == []
    if failed_step == 1:
        # Even a failed password update must be followed by reapplying the block.
        assert mock_auth0_client.update_user.call_args.kwargs["update_data"].blocked is True
        assert mock_auth0_client.update_user.call_count == 3


MIGRATE_AUTH0_PAYLOAD = {"new_email": "new@example.com", "password": "New-password123!"}


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("expired", [False, True])
def test_migrate_aaf_to_auth0_retry_reuses_target(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_email_service, reuse, expired,
):
    _, source = aaf_migration_account
    if not reuse:
        source.identities = source.identities[:1]
    first = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert first.status_code == HTTPStatus.OK
    previous = test_db_session.get(AccountMigrationRequest, first.json()["migration_id"])
    target_id = previous.auth0_user_id
    if expired:
        previous.status = MigrationStatus.EXPIRED
    otp = test_db_session.exec(select(EmailChangeOtp)).one()
    otp.total_attempts = 4
    test_db_session.commit()
    mock_auth0_client.create_user.reset_mock()
    mock_auth0_client.update_user.reset_mock()

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json={
        **MIGRATE_AUTH0_PAYLOAD, "password": "Different-password123!",
    })

    assert response.status_code == HTTPStatus.OK
    assert (response.json()["migration_id"] != previous.id) == expired
    test_db_session.refresh(previous)
    assert previous.status == (MigrationStatus.EXPIRED if expired else MigrationStatus.PENDING)
    migration = test_db_session.get(AccountMigrationRequest, response.json()["migration_id"])
    assert migration.auth0_user_id == target_id
    mock_auth0_client.create_user.assert_not_called()
    assert mock_auth0_client.update_user.call_count == 3
    updates = mock_auth0_client.update_user.call_args_list
    assert updates[1].kwargs["update_data"].password == "Different-password123!"
    target = mock_auth0_client.remote_users[target_id]
    assert target.blocked is True
    assert target.app_metadata.aaf_migration.user_id == source.user_id
    if not expired:
        test_db_session.refresh(otp)
        assert otp.total_attempts == 4
    assert mock_email_service.send_email_change_otp.call_count == 2


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("expired", [False, True])
def test_migrate_aaf_to_auth0_changed_email_creates_fresh_request(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_email_service, reuse, expired,
):
    _, source = aaf_migration_account
    if not reuse:
        source.identities = source.identities[:1]
    first = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert first.status_code == HTTPStatus.OK
    previous = test_db_session.get(AccountMigrationRequest, first.json()["migration_id"])
    target_id = previous.auth0_user_id
    old_otp = test_db_session.exec(select(EmailChangeOtp)).one()
    if expired:
        previous.status = MigrationStatus.EXPIRED
        test_db_session.commit()
    mock_auth0_client.get_user.reset_mock()
    mock_auth0_client.update_user.reset_mock()
    mock_auth0_client.create_user.reset_mock()
    mock_email_service.send_email_change_otp.reset_mock()

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json={
        **MIGRATE_AUTH0_PAYLOAD, "new_email": "changed@example.com",
    })

    assert response.status_code == HTTPStatus.OK
    assert response.json()["migration_id"] != previous.id
    assert response.json()["new_email"] == "changed@example.com"
    test_db_session.refresh(previous)
    assert previous.status == MigrationStatus.EXPIRED
    migration = test_db_session.get(AccountMigrationRequest, response.json()["migration_id"])
    assert migration.status == MigrationStatus.PENDING
    assert migration.auth0_user_id == target_id
    assert migration.new_email == "changed@example.com"
    updates = mock_auth0_client.update_user.call_args_list
    assert updates[0].kwargs["user_id"] == target_id
    assert updates[0].kwargs["update_data"].email == "changed@example.com"
    assert mock_auth0_client.remote_users[target_id].blocked is True
    test_db_session.refresh(old_otp)
    assert old_otp.is_active is False
    current_otp = test_db_session.exec(select(EmailChangeOtp).where(EmailChangeOtp.is_active.is_(True))).one()
    assert current_otp.id != old_otp.id
    assert current_otp.target_email == "changed@example.com"
    mock_auth0_client.create_user.assert_not_called()
    assert mock_email_service.send_email_change_otp.call_args.kwargs["target_email"] == "changed@example.com"


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("failure", ["commit", "email", "create_response", "password"])
def test_migrate_aaf_to_auth0_retry_after_failure(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
    mock_email_service, mocker, reuse, failure,
):
    _, source = aaf_migration_account
    if not reuse:
        source.identities = source.identities[:1]
    if failure == "commit":
        commit = Session.commit
        attempts = 0

        def fail_once(session):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OperationalError("injected failure", {}, Exception("failed"))
            return commit(session)

        mocker.patch.object(Session, "commit", autospec=True, side_effect=fail_once)
    elif failure == "email":
        mock_email_service.send_email_change_otp.side_effect = [RuntimeError("SES unavailable"), None]
    elif failure == "password":
        if not reuse:
            assert test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD).status_code == HTTPStatus.OK
        operation = mock_auth0_client.update_user.side_effect
        failed = False

        def fail_once(*args, **kwargs):
            nonlocal failed
            if kwargs["update_data"].password is not None and not failed:
                failed = True
                raise ValueError("Password update failed")
            return operation(*args, **kwargs)

        mock_auth0_client.update_user.side_effect = fail_once
    else:
        method = mock_auth0_client.update_user if reuse or failure == "password" else mock_auth0_client.create_user
        operation = method.side_effect
        failed = False

        def fail_once(*args, **kwargs):
            nonlocal failed
            result = operation(*args, **kwargs)
            if not failed:
                failed = True
                raise httpx2.ReadTimeout("Response lost after Auth0 write")
            return result

        method.side_effect = fail_once
    if failure == "email":
        with pytest.raises(RuntimeError, match="SES unavailable"):
            test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    else:
        first = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
        assert first.status_code == (HTTPStatus.SERVICE_UNAVAILABLE if failure == "commit" else HTTPStatus.BAD_GATEWAY)

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert response.status_code == HTTPStatus.OK
    migration = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert migration.auth0_user_id is not None
    assert mock_auth0_client.remote_users[migration.auth0_user_id].blocked is True
    assert mock_auth0_client.create_user.call_count == (0 if reuse else 1)
    assert test_db_session.exec(select(EmailChangeOtp).where(EmailChangeOtp.is_active.is_(True))).one()


def test_migrate_aaf_to_auth0_changed_email_rejects_unrelated_saved_target(
    test_client, test_db_session, aaf_migration_account, mock_auth0_client,
):
    _, source = aaf_migration_account
    source.identities = source.identities[:1]
    first = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert first.status_code == HTTPStatus.OK
    previous = test_db_session.get(AccountMigrationRequest, first.json()["migration_id"])
    unrelated = Auth0UserDataFactory.build(
        user_id="auth0|unrelated", app_metadata={"account_type": "auth0", "aaf_migration": {"user_id": "another-user"}},
    )
    mock_auth0_client.remote_users[unrelated.user_id] = unrelated
    previous.auth0_user_id = unrelated.user_id
    test_db_session.commit()
    mock_auth0_client.update_user.reset_mock()

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json={
        **MIGRATE_AUTH0_PAYLOAD, "new_email": "changed@example.com",
    })

    assert response.status_code == HTTPStatus.CONFLICT
    mock_auth0_client.update_user.assert_not_called()
    test_db_session.refresh(previous)
    assert previous.status == MigrationStatus.PENDING


def test_migrate_aaf_to_auth0_never_adopts_unrelated_email_match(
    test_client, aaf_migration_account, mock_auth0_client, mock_email_service,
):
    _, source = aaf_migration_account
    source.identities = source.identities[:1]
    unrelated = Auth0UserDataFactory.build(email="new@example.com", blocked=True)
    mock_auth0_client.search_users_by_email.side_effect = None
    mock_auth0_client.search_users_by_email.return_value = [unrelated]

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)

    assert response.status_code == HTTPStatus.CONFLICT
    mock_auth0_client.create_user.assert_not_called()
    mock_auth0_client.update_user.assert_not_called()
    mock_email_service.send_email_change_otp.assert_not_called()


def test_migrate_aaf_to_auth0_resend_does_not_reset_exhausted_attempts(
    test_client, test_db_session, aaf_migration_account, mock_email_service,
):
    first = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert first.status_code == HTTPStatus.OK
    otp = test_db_session.exec(select(EmailChangeOtp)).one()
    otp.total_attempts = 10
    otp.is_active = False
    test_db_session.commit()
    mock_email_service.send_email_change_otp.reset_mock()

    response = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)

    assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
    test_db_session.refresh(otp)
    assert otp.total_attempts == 10
    assert otp.is_active is False
    mock_email_service.send_email_change_otp.assert_not_called()


@pytest.fixture(params=[False, True])
def started_auth0_migration(request, test_client, aaf_migration_account, mock_auth0_client, mock_email_service):
    db_user, source = aaf_migration_account
    if not request.param:
        source.identities = source.identities[:1]

    def link_identity(primary_user_id, secondary_user_id, **kwargs):
        target = mock_auth0_client.remote_users.pop(f"auth0|{secondary_user_id}")
        source.identities.extend(target.identities)
        return True

    mock_auth0_client.link_identity.side_effect = link_identity
    response = test_client.post("/aaf/migrate/aaf-to-auth0", json=MIGRATE_AUTH0_PAYLOAD)
    assert response.status_code == HTTPStatus.OK
    sent = mock_email_service.send_email_change_otp.call_args.kwargs
    mock_auth0_client.update_user.reset_mock()
    return db_user, source, {"migration_id": response.json()["migration_id"], "otp": sent["code"]}


def test_complete_aaf_to_auth0_migration(test_client, test_db_session, started_auth0_migration, mock_auth0_client):
    db_user, source, payload = started_auth0_migration
    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload)

    assert response.status_code == HTTPStatus.OK
    assert response.json()["user_id"] == source.user_id
    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.email == "new@example.com"
    assert db_user.email_verified is True
    assert source.blocked is False
    assert source.app_metadata.account_type == BiocommonsUserAccountType.AUTH0
    migration = test_db_session.get(AccountMigrationRequest, payload["migration_id"])
    assert migration.status == MigrationStatus.COMPLETED
    assert test_db_session.exec(select(EmailChangeOtp)).one().is_active is False
    assert len([identity for identity in source.identities if identity.provider == "auth0"]) == 1
    last_update = mock_auth0_client.update_user.call_args.args[1]
    assert last_update.email_verified is True
    assert last_update.blocked is False
    assert last_update.verify_email is False
    assert test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload).status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("invalid", ["code", "otp_expired", "migration_expired", "direction", "email", "user", "attempts"])
def test_complete_aaf_to_auth0_rejects_invalid_verification(
    test_client, test_db_session, started_auth0_migration, mock_auth0_client, invalid,
):
    _, _, payload = started_auth0_migration
    migration = test_db_session.get(AccountMigrationRequest, payload["migration_id"])
    otp = test_db_session.exec(select(EmailChangeOtp)).one()
    expected = HTTPStatus.BAD_REQUEST
    if invalid == "code":
        payload = {**payload, "otp": "000000" if payload["otp"] != "000000" else "111111"}
    elif invalid == "otp_expired":
        otp.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif invalid == "migration_expired":
        migration.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif invalid == "direction":
        migration.direction = MigrationDirection.AUTH0_TO_AAF
    elif invalid == "email":
        otp.target_email = "wrong@example.com"
    elif invalid == "user":
        migration.user_id = BiocommonsUserFactory.create_sync().id
        expected = HTTPStatus.NOT_FOUND
    elif invalid == "attempts":
        otp.total_attempts = 10
        expected = HTTPStatus.TOO_MANY_REQUESTS
    test_db_session.commit()

    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload)

    assert response.status_code == expected
    mock_auth0_client.update_user.assert_not_called()
    mock_auth0_client.link_identity.assert_not_called()
    test_db_session.refresh(otp)
    if invalid == "code":
        assert otp.total_attempts == 1
        assert otp.is_active is True
    if invalid == "attempts":
        assert otp.is_active is False


@pytest.mark.parametrize("failure", ["auth0", "commit"])
def test_complete_aaf_to_auth0_retry_after_failure(
    test_client, test_db_session, started_auth0_migration, mock_auth0_client, mocker, failure,
):
    db_user, source, payload = started_auth0_migration
    if failure == "auth0":
        update = mock_auth0_client.update_user.side_effect
        failed = False

        def fail_final_update(user_id, update_data):
            nonlocal failed
            if user_id == source.user_id and not failed:
                failed = True
                raise ValueError("Final update failed")
            return update(user_id, update_data)

        mock_auth0_client.update_user.side_effect = fail_final_update
        expected = HTTPStatus.BAD_GATEWAY
    else:
        commit = Session.commit
        failed = False

        def fail_commit(session):
            nonlocal failed
            if not failed:
                failed = True
                raise OperationalError("commit", {}, Exception("DB unavailable"))
            return commit(session)

        mocker.patch.object(Session, "commit", autospec=True, side_effect=fail_commit)
        expected = HTTPStatus.SERVICE_UNAVAILABLE
    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload)
    assert response.status_code == expected
    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert test_db_session.exec(select(EmailChangeOtp)).one().is_active is True

    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload)

    assert response.status_code == HTTPStatus.OK
    assert response.json()["user_id"] == source.user_id
    assert mock_auth0_client.link_identity.call_count <= 1


def test_complete_aaf_to_auth0_rejects_replaced_request(
    test_client, started_auth0_migration, mock_auth0_client,
):
    _, _, old_payload = started_auth0_migration
    response = test_client.post("/aaf/migrate/aaf-to-auth0", json={
        **MIGRATE_AUTH0_PAYLOAD, "new_email": "corrected@example.com",
    })
    assert response.status_code == HTTPStatus.OK
    mock_auth0_client.update_user.reset_mock()

    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=old_payload)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    mock_auth0_client.update_user.assert_not_called()


def test_complete_aaf_to_auth0_rejects_target_for_another_user(
    test_client, test_db_session, started_auth0_migration, mock_auth0_client,
):
    _, _, payload = started_auth0_migration
    migration = test_db_session.get(AccountMigrationRequest, payload["migration_id"])
    mock_auth0_client.remote_users[migration.auth0_user_id].app_metadata.aaf_migration.user_id = "another-user"

    response = test_client.post("/aaf/migrate/aaf-to-auth0/complete", json=payload)

    assert response.status_code in (HTTPStatus.FORBIDDEN, HTTPStatus.CONFLICT)
    mock_auth0_client.update_user.assert_not_called()
    mock_auth0_client.link_identity.assert_not_called()
    assert test_db_session.exec(select(EmailChangeOtp)).one().is_active is True


@pytest.fixture
def pending_aaf_migration(test_db_session, persistent_factories):
    db_user = BiocommonsUserFactory.create_sync(
        email="original@example.edu.au",
        account_type=BiocommonsUserAccountType.AUTH0,
        other_user_id=None,
    )
    migration_request = AccountMigrationRequest(
        user_id=db_user.id,
        new_email="new@example.edu.au",
        direction=MigrationDirection.AUTH0_TO_AAF,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    test_db_session.add(migration_request)
    test_db_session.commit()
    return migration_request


@pytest.fixture
def aaf_migration_payload(pending_aaf_migration):
    return {
        **_action_token_payload(
            user_id="oidc|AAF|migration-test",
            email=pending_aaf_migration.new_email,
            purpose="aaf_migration",
        ),
        "migration_id": pending_aaf_migration.id,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
    }


@pytest.mark.parametrize("blocked", [False, None])
def test_complete_auth0_to_aaf_migration(
    test_client,
    test_db_session,
    mock_settings,
    mock_auth0_client,
    pending_aaf_migration,
    aaf_migration_payload,
    blocked,
):
    primary_id = pending_aaf_migration.user_id
    aaf_user_id = aaf_migration_payload["user_id"]
    identity = Auth0Identity(connection="AAF", provider="oidc", user_id="migration-test", isSocial=False)
    existing_account = Auth0UserDataFactory.build(user_id=primary_id, blocked=blocked)
    aaf_account = Auth0UserDataFactory.build(
        user_id=aaf_user_id,
        email=pending_aaf_migration.new_email,
        identities=[identity],
    )
    mock_auth0_client.get_user.side_effect = lambda user_id: {
        primary_id: existing_account,
        aaf_user_id: aaf_account,
    }[user_id]
    session_token = jwt.encode(aaf_migration_payload, mock_settings.auth0_management_secret, algorithm="HS256")

    state = "migration-state"
    response = test_client.get(
        "/aaf/migrate/auth0-to-aaf/complete",
        params={"session_token": session_token, "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=aaf_migration_payload,
    )
    assert decoded_token["link"] is True
    assert decoded_token["primary_id"] == primary_id
    assert decoded_token["aaf_identity"] == identity.model_dump(exclude_none=True)
    test_db_session.refresh(pending_aaf_migration)
    assert pending_aaf_migration.status == MigrationStatus.COMPLETED
    db_user = test_db_session.get(BiocommonsUser, primary_id)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert db_user.other_user_id == aaf_user_id
    assert db_user.email == "new@example.edu.au"
    assert db_user.email_verified is True
    mock_auth0_client.update_user.assert_called_once()
    call_args, call_kwargs = mock_auth0_client.update_user.call_args
    assert call_args[0] == primary_id
    update_data = call_kwargs["update_data"]
    assert update_data.email == "new@example.edu.au"
    assert update_data.email_verified is True
    assert update_data.connection == mock_settings.auth0_db_connection
    assert update_data.app_metadata.account_type == BiocommonsUserAccountType.AAF
    mock_auth0_client.search_users_by_email.assert_not_called()
    mock_auth0_client.link_identity.assert_not_called()


def test_complete_auth0_to_aaf_migration_rejects_blocked_account(
    test_client,
    test_db_session,
    mock_settings,
    mock_auth0_client,
    pending_aaf_migration,
    aaf_migration_payload,
):
    primary_id = pending_aaf_migration.user_id
    mock_auth0_client.get_user.return_value = Auth0UserDataFactory.build(
        user_id=primary_id,
        blocked=True,
    )
    session_token = jwt.encode(aaf_migration_payload, mock_settings.auth0_management_secret, algorithm="HS256")

    response = test_client.get(
        "/aaf/migrate/auth0-to-aaf/complete",
        params={"session_token": session_token, "state": "migration-state"},
        follow_redirects=False,
    )

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json() == {"detail": "This account cannot be migrated to AAF - blocked in Auth0."}
    mock_auth0_client.get_user.assert_called_once_with(user_id=primary_id)
    mock_auth0_client.update_user.assert_not_called()
    mock_auth0_client.link_identity.assert_not_called()
    test_db_session.refresh(pending_aaf_migration)
    assert pending_aaf_migration.status == MigrationStatus.PENDING
    db_user = test_db_session.get(BiocommonsUser, primary_id)
    assert db_user.email == "original@example.edu.au"
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None


@pytest.mark.parametrize("is_deleted", [False, True])
@pytest.mark.parametrize("existing_email", ["new@example.edu.au", "NEW@EXAMPLE.EDU.AU"])
def test_complete_auth0_to_aaf_migration_rejects_email_claimed_after_creation(
    test_client,
    test_db_session,
    persistent_factories,
    mock_settings,
    mock_auth0_client,
    pending_aaf_migration,
    aaf_migration_payload,
    is_deleted,
    existing_email,
):
    BiocommonsUserFactory.create_sync(email=existing_email, is_deleted=is_deleted)
    test_db_session.commit()
    session_token = jwt.encode(aaf_migration_payload, mock_settings.auth0_management_secret, algorithm="HS256")

    response = test_client.get(
        "/aaf/migrate/auth0-to-aaf/complete",
        params={"session_token": session_token, "state": "migration-state"},
        follow_redirects=False,
    )

    assert response.status_code == HTTPStatus.CONFLICT
    assert response.json() == {"detail": "Email is already in use by another user"}
    mock_auth0_client.get_user.assert_not_called()
    mock_auth0_client.update_user.assert_not_called()
    test_db_session.refresh(pending_aaf_migration)
    assert pending_aaf_migration.status == MigrationStatus.PENDING
    db_user = test_db_session.get(BiocommonsUser, pending_aaf_migration.user_id)
    assert db_user.email == "original@example.edu.au"
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None


def test_complete_auth0_to_aaf_migration_handles_email_constraint_conflict(
    test_client,
    test_db_session,
    persistent_factories,
    mock_settings,
    mock_auth0_client,
    pending_aaf_migration,
    aaf_migration_payload,
    mocker,
):
    BiocommonsUserFactory.create_sync(email=pending_aaf_migration.new_email)
    test_db_session.commit()
    mocker.patch.object(BiocommonsUser, "get_by_email", return_value=None)
    aaf_user_id = aaf_migration_payload["user_id"]
    mock_auth0_client.get_user.return_value = Auth0UserDataFactory.build(
        user_id=aaf_user_id,
        identities=[Auth0Identity(connection="AAF", provider="oidc", user_id="migration-test", isSocial=False)],
    )
    session_token = jwt.encode(aaf_migration_payload, mock_settings.auth0_management_secret, algorithm="HS256")

    response = test_client.get(
        "/aaf/migrate/auth0-to-aaf/complete",
        params={"session_token": session_token, "state": "migration-state"},
        follow_redirects=False,
    )

    assert response.status_code == HTTPStatus.CONFLICT
    assert response.json() == {"detail": "Email is already in use by another user"}
    assert mock_auth0_client.get_user.call_args_list == [
        call(user_id=pending_aaf_migration.user_id),
        call(user_id=aaf_user_id),
    ]
    mock_auth0_client.update_user.assert_not_called()
    test_db_session.refresh(pending_aaf_migration)
    assert pending_aaf_migration.status == MigrationStatus.PENDING
    db_user = test_db_session.get(BiocommonsUser, pending_aaf_migration.user_id)
    assert db_user.email == "original@example.edu.au"
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None


@pytest.mark.parametrize(
    ["request_changes", "token_changes", "expected_status"],
    [
        ({}, {"migration_id": "missing"}, HTTPStatus.NOT_FOUND),
        ({"status": MigrationStatus.COMPLETED}, {}, HTTPStatus.BAD_REQUEST),
        ({"direction": MigrationDirection.AAF_TO_AUTH0}, {}, HTTPStatus.BAD_REQUEST),
        (
            {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)},
            {},
            HTTPStatus.BAD_REQUEST,
        ),
        ({}, {"email": "other@example.edu.au"}, HTTPStatus.BAD_REQUEST),
        ({}, {"purpose": "aaf_link"}, HTTPStatus.UNAUTHORIZED),
        ({}, {"migration_id": None}, HTTPStatus.UNAUTHORIZED),
    ],
)
def test_complete_auth0_to_aaf_migration_rejects_invalid_request(
    test_client,
    test_db_session,
    mock_settings,
    mock_auth0_client,
    pending_aaf_migration,
    aaf_migration_payload,
    request_changes,
    token_changes,
    expected_status,
):
    for field_name, value in request_changes.items():
        setattr(pending_aaf_migration, field_name, value)
    test_db_session.commit()
    aaf_migration_payload.update(token_changes)
    session_token = jwt.encode(aaf_migration_payload, mock_settings.auth0_management_secret, algorithm="HS256")

    response = test_client.get(
        "/aaf/migrate/auth0-to-aaf/complete",
        params={"session_token": session_token, "state": "migration-state"},
        follow_redirects=False,
    )

    assert response.status_code == expected_status
    mock_auth0_client.get_user.assert_not_called()
    mock_auth0_client.update_user.assert_not_called()
    test_db_session.refresh(pending_aaf_migration)
    assert pending_aaf_migration.status == request_changes.get("status", MigrationStatus.PENDING)
    db_user = test_db_session.get(BiocommonsUser, pending_aaf_migration.user_id)
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.email == "original@example.edu.au"


@pytest.mark.parametrize("new_email", ["new@example.edu.au", "original@example.edu.au"])
def test_migrate_auth0_to_aaf_creates_request(
    test_client,
    test_db_session,
    persistent_factories,
    normal_user,
    as_normal_user,
    new_email,
):
    BiocommonsUserFactory.create_sync(
        id=normal_user.access_token.sub,
        email="original@example.edu.au",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    test_db_session.commit()
    assert test_db_session.exec(select(AccountMigrationRequest)).all() == []

    response = test_client.post(
        "/aaf/migrate/auth0-to-aaf",
        json={"new_email": new_email},
    )

    assert response.status_code == HTTPStatus.OK
    migration_request = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert response.json()["migration_id"] == migration_request.id
    assert migration_request.user_id == normal_user.access_token.sub
    assert migration_request.new_email == new_email
    assert migration_request.direction == MigrationDirection.AUTH0_TO_AAF
    assert migration_request.status == MigrationStatus.PENDING


@pytest.mark.parametrize("existing_email", ["new@example.edu.au", "NEW@EXAMPLE.EDU.AU"])
@pytest.mark.parametrize("has_pending_request", [False, True])
@pytest.mark.parametrize("is_deleted", [False, True])
def test_migrate_auth0_to_aaf_rejects_occupied_email(
    test_client,
    test_db_session,
    persistent_factories,
    normal_user,
    as_normal_user,
    existing_email,
    has_pending_request,
    is_deleted,
):
    BiocommonsUserFactory.create_sync(
        id=normal_user.access_token.sub,
        email="original@example.edu.au",
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    BiocommonsUserFactory.create_sync(
        email=existing_email,
        account_type=BiocommonsUserAccountType.AAF,
        is_deleted=is_deleted,
    )
    if has_pending_request:
        existing_request = AccountMigrationRequest(
            user_id=normal_user.access_token.sub,
            new_email="pending@example.edu.au",
            direction=MigrationDirection.AUTH0_TO_AAF,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        test_db_session.add(existing_request)
    test_db_session.commit()

    response = test_client.post(
        "/aaf/migrate/auth0-to-aaf",
        json={"new_email": "new@example.edu.au"},
    )

    assert response.status_code == HTTPStatus.CONFLICT
    assert response.json() == {"detail": "Email is already in use by another user"}
    requests = test_db_session.exec(select(AccountMigrationRequest)).all()
    if has_pending_request:
        assert len(requests) == 1
        assert requests[0].id == existing_request.id
        assert requests[0].new_email == "pending@example.edu.au"
        assert requests[0].status == MigrationStatus.PENDING
    else:
        assert requests == []


def test_migrate_auth0_to_aaf_replaces_pending_request(
    test_client,
    test_db_session,
    persistent_factories,
    normal_user,
    as_normal_user,
):
    BiocommonsUserFactory.create_sync(
        id=normal_user.access_token.sub,
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    existing_request = AccountMigrationRequest(
        user_id=normal_user.access_token.sub,
        new_email="existing@example.edu.au",
        direction=MigrationDirection.AUTH0_TO_AAF,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        status=MigrationStatus.PENDING,
    )
    test_db_session.add(existing_request)
    test_db_session.commit()
    existing_request_id = existing_request.id

    response = test_client.post(
        "/aaf/migrate/auth0-to-aaf",
        json={"new_email": "new@example.edu.au"},
    )

    assert response.status_code == HTTPStatus.OK
    migration_request = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert response.json()["migration_id"] == migration_request.id
    assert migration_request.id != existing_request_id
    assert migration_request.user_id == normal_user.access_token.sub
    assert migration_request.new_email == "new@example.edu.au"
    assert migration_request.direction == MigrationDirection.AUTH0_TO_AAF
    assert migration_request.status == MigrationStatus.PENDING


def test_migrate_auth0_to_aaf_rolls_back_on_concurrent_request(
    test_db_session, persistent_factories, normal_user, mocker
):
    db_user = BiocommonsUserFactory.create_sync(
        id=normal_user.access_token.sub,
        account_type=BiocommonsUserAccountType.AUTH0,
    )
    now = datetime.now(timezone.utc)
    existing_request = AccountMigrationRequest(
        user_id=db_user.id,
        new_email="existing@example.edu.au",
        direction=MigrationDirection.AUTH0_TO_AAF,
        expires_at=now + timedelta(minutes=10),
    )
    test_db_session.add(existing_request)
    test_db_session.commit()
    existing_request_id = existing_request.id
    # Simulate the simultaneous requests by skipping the initial check for a pending
    #   request
    mocker.patch.object(AccountMigrationRequest, "get_pending_by_user_id", return_value=None)
    rollback = mocker.spy(test_db_session, "rollback")

    with pytest.raises(HTTPException) as exc_info:
        migrate_auth0_to_aaf(
            migrate_data=MigrateToAafRequest(new_email="new@example.edu.au"),
            user=normal_user,
            db_user=db_user,
            session=test_db_session,
            now=now,
        )

    assert exc_info.value.status_code == HTTPStatus.CONFLICT
    assert exc_info.value.detail == (
        "A pending migration request already exists for this user. Please try again."
    )
    rollback.assert_called_once_with()
    remaining_request = test_db_session.exec(select(AccountMigrationRequest)).one()
    assert remaining_request.id == existing_request_id
    assert remaining_request.new_email == "existing@example.edu.au"


def test_link_aaf_account_links_identity_updates_metadata_and_db(test_db_session, persistent_factories):
    db_user = BiocommonsUserFactory.create_sync(account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None)
    test_db_session.commit()

    aaf_user_id = random_auth0_id()
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    auth0_client = MagicMock(spec=Auth0Client)
    auth0_client.get_user.return_value = aaf_user_data

    result = link_aaf_account(
        db_user_id=db_user.id,
        aaf_user_id=aaf_user_id,
        auth0_client=auth0_client,
        session=test_db_session,
    )

    auth0_client.get_user.assert_called_once_with(user_id=aaf_user_id)
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_called_once()
    call_args, call_kwargs = auth0_client.update_user.call_args
    assert call_args[0] == db_user.id
    app_metadata = call_kwargs["update_data"].app_metadata
    assert app_metadata.account_type == BiocommonsUserAccountType.AAF
    assert app_metadata.linking_completed is True
    assert app_metadata.linking_completed_at is not None

    assert result == aaf_user_data.identities[0]

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert db_user.other_user_id == aaf_user_id


def test_link_aaf_account_raises_404_when_no_aaf_identity(test_db_session, persistent_factories):
    db_user = BiocommonsUserFactory.create_sync(account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None)
    test_db_session.commit()

    aaf_user_id = random_auth0_id()
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[
            Auth0Identity(
                connection="Username-Password-Authentication",
                provider="auth0",
                user_id=aaf_user_id,
                isSocial=False,
            )
        ]
    )
    auth0_client = MagicMock(spec=Auth0Client)
    auth0_client.get_user.return_value = aaf_user_data

    with pytest.raises(HTTPException) as exc_info:
        link_aaf_account(
            db_user_id=db_user.id,
            aaf_user_id=aaf_user_id,
            auth0_client=auth0_client,
            session=test_db_session,
        )

    assert exc_info.value.status_code == HTTPStatus.NOT_FOUND
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_not_called()

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None


@pytest.mark.parametrize("new_email", [None, "new@example.edu.au"])
def test_link_aaf_account_raises_502_when_auth0_update_fails(
    test_db_session, persistent_factories, new_email
):
    db_user = BiocommonsUserFactory.create_sync(account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None)
    test_db_session.commit()
    original_email = db_user.email
    original_email_verified = db_user.email_verified

    aaf_user_id = random_auth0_id()
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    auth0_client = MagicMock(spec=Auth0Client)
    auth0_client.get_user.return_value = aaf_user_data
    auth0_client.update_user.side_effect = ValueError("Auth0 update failed")

    with pytest.raises(HTTPException) as exc_info:
        link_aaf_account(
            db_user_id=db_user.id,
            aaf_user_id=aaf_user_id,
            auth0_client=auth0_client,
            session=test_db_session,
            new_email=new_email,
            connection="Username-Password-Authentication" if new_email is not None else None,
        )

    assert exc_info.value.status_code == HTTPStatus.BAD_GATEWAY
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_called_once()

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None
    assert db_user.email == original_email
    assert db_user.email_verified == original_email_verified


def test_link_aaf_account_idempotent_when_already_linked(test_db_session, persistent_factories):
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        account_type=BiocommonsUserAccountType.AAF, other_user_id=aaf_user_id
    )
    test_db_session.commit()

    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    auth0_client = MagicMock(spec=Auth0Client)
    auth0_client.get_user.return_value = aaf_user_data

    result = link_aaf_account(
        db_user_id=db_user.id,
        aaf_user_id=aaf_user_id,
        auth0_client=auth0_client,
        session=test_db_session,
    )

    auth0_client.get_user.assert_called_once_with(user_id=aaf_user_id)
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_not_called()
    assert result == aaf_user_data.identities[0]


def _action_token_payload(
    user_id: str,
    email: str,
    purpose: str = "aaf_link",
    client_id: str = "test-client",
    sub: str | None = None,
    iss: str | None = "mock-domain",
) -> dict:
    payload = {
        "user_id": user_id,
        "email": email,
        "client_id": client_id,
        "purpose": purpose,
    }
    if sub is not None:
        payload["sub"] = sub
    if iss is not None:
        payload["iss"] = iss
    return payload


def _aaf_registration_token_payload(
    user_id: str,
    email: str,
    purpose: str = "aaf_registration",
) -> dict:
    return {
        **_action_token_payload(user_id=user_id, email=email, purpose=purpose),
        "given_name": "AAF",
        "family_name": "User",
        "name": "AAF User",
        "exp": int((datetime.now() + timedelta(minutes=5)).timestamp()),
    }


def _assert_marked_aaf_only(update_user_mock, aaf_user_id: str, email: str):
    update_user_mock.assert_called_once()
    call_args, call_kwargs = update_user_mock.call_args
    assert call_kwargs["user_id"] == aaf_user_id
    app_metadata = call_kwargs["update_data"].app_metadata
    assert app_metadata.account_type == BiocommonsUserAccountType.AAF
    assert app_metadata.aaf_only is True
    assert app_metadata.checked_email == email
    assert app_metadata.linking_completed is True
    assert app_metadata.linking_completed_at is not None


def _expected_auth0_continue_base_url(incoming_token: dict, settings) -> str:
    issuer = incoming_token.get("iss")
    if issuer is None:
        return settings.auth0_custom_domain or f"https://{settings.auth0_domain}"
    issuer = issuer.rstrip("/")
    parsed_issuer = urlparse(issuer)
    if parsed_issuer.scheme and parsed_issuer.netloc:
        return f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"
    return f"https://{issuer}"


def _decode_check_link_redirect(
    response,
    state: str,
    settings,
    incoming_token: dict,
) -> dict:
    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert response.is_redirect
    redirect = urlparse(response.headers["location"])
    expected_base_url = _expected_auth0_continue_base_url(incoming_token, settings)
    expected_continue_url = urlparse(f"{expected_base_url}/continue")
    assert redirect.scheme == expected_continue_url.scheme
    assert redirect.netloc == expected_continue_url.netloc
    assert redirect.path == expected_continue_url.path
    query_params = parse_qs(redirect.query)
    assert query_params["state"] == [state]
    assert "session_token" in query_params
    decoded_token = jwt.decode(
        query_params["session_token"][0],
        key=settings.auth0_management_secret,
        algorithms=["HS256"],
    )
    assert decoded_token["state"] == state
    assert decoded_token["sub"] == incoming_token.get("sub", incoming_token["user_id"])
    assert decoded_token["iss"] == incoming_token.get("iss", settings.auth0_domain)
    return decoded_token


def test_verify_registration_token_accepts_token_signed_with_settings_secret(mock_settings):
    aaf_user_id = random_auth0_id()
    payload = _aaf_registration_token_payload(
        user_id=aaf_user_id,
        email="aaf-user@example.edu.au",
    )
    token = jwt.encode(
        payload,
        key=mock_settings.auth0_management_secret,
        algorithm="HS256",
    )

    result = verify_registration_token(token, settings=mock_settings)

    assert result.user_id == aaf_user_id
    assert str(result.email) == "aaf-user@example.edu.au"
    assert result.client_id == "test-client"
    assert result.purpose == "aaf_registration"
    assert result.given_name == "AAF"
    assert result.family_name == "User"
    assert result.name == "AAF User"


def test_verify_registration_token_rejects_wrong_purpose(mock_settings):
    token = jwt.encode(
        _aaf_registration_token_payload(
            user_id=random_auth0_id(),
            email="aaf-user@example.edu.au",
            purpose="aaf_link",
        ),
        key=mock_settings.auth0_management_secret,
        algorithm="HS256",
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_registration_token(token, settings=mock_settings)

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED
    assert exc_info.value.detail == "Token from Auth0 expired."


def test_mark_user_aaf_only():
    aaf_user_id = random_auth0_id()
    email = "aaf-user@example.com"
    auth0_client = MagicMock(spec=Auth0Client)

    mark_user_aaf_only(email, aaf_user_id, auth0_client)

    _assert_marked_aaf_only(auth0_client.update_user, aaf_user_id, email)


def test_check_link_no_existing_account(test_client, mocker, mock_settings):
    aaf_user_id = random_auth0_id()
    email = "new-aaf-user@example.com"
    action_token_payload = _action_token_payload(
        aaf_user_id,
        email,
        sub=aaf_user_id,
        iss="https://login.example.com/",
    )
    mocker.patch("dependencies.auth.verify_action_token", return_value=action_token_payload)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[])
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    state = "dummy"
    response = test_client.get(
        "/aaf/check-link",
        params={"session_token": "valid_token", "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=action_token_payload,
    )
    assert decoded_token["link"] is False
    assert decoded_token["aaf_only"] is True
    assert decoded_token["primary_id"] == aaf_user_id

    link_identity.assert_not_called()
    _assert_marked_aaf_only(update_user, aaf_user_id, email)


def test_check_link_no_exact_email_match(test_client, mocker, mock_settings):
    aaf_user_id = random_auth0_id()
    email = "aaf-user@example.com"
    action_token_payload = _action_token_payload(
        aaf_user_id,
        email,
        sub="auth0|original-sub",
    )
    mocker.patch("dependencies.auth.verify_action_token", return_value=action_token_payload)
    near_miss_account = Auth0UserDataFactory.build(email="different-user@example.com")
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[near_miss_account])
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    state = "dummy"
    response = test_client.get(
        "/aaf/check-link",
        params={"session_token": "valid_token", "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=action_token_payload,
    )
    assert decoded_token["link"] is False
    assert decoded_token["aaf_only"] is True
    assert decoded_token["primary_id"] == aaf_user_id
    link_identity.assert_not_called()
    _assert_marked_aaf_only(update_user, aaf_user_id, email)


def test_check_link_existing_account_blocked(test_client, mocker, mock_settings):
    aaf_user_id = random_auth0_id()
    email = "blocked-user@example.com"
    action_token_payload = _action_token_payload(aaf_user_id, email)
    mocker.patch(
        "dependencies.auth.verify_action_token",
        return_value=action_token_payload,
    )
    existing_account = Auth0UserDataFactory.build(email=email, blocked=True)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])
    get_user = mocker.patch("routers.aaf.Auth0Client.get_user")
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    state = "dummy"
    response = test_client.get(
        "/aaf/check-link",
        params={"session_token": "valid_token", "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=action_token_payload,
    )
    assert decoded_token["link"] is True
    assert decoded_token["aaf_only"] is False
    assert decoded_token["blocked"] is True
    assert decoded_token["primary_id"] == existing_account.user_id

    get_user.assert_not_called()
    link_identity.assert_not_called()
    update_user.assert_not_called()


def test_check_link_existing_account_links(test_client, test_db_session, persistent_factories, mocker, mock_settings):
    email = "existing-user@example.com"
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        email=email, account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None
    )
    test_db_session.commit()

    action_token_payload = _action_token_payload(aaf_user_id, email, sub=aaf_user_id)
    mocker.patch("dependencies.auth.verify_action_token", return_value=action_token_payload)
    existing_account = Auth0UserDataFactory.build(user_id=db_user.id, email=email, blocked=False)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    mocker.patch("routers.aaf.Auth0Client.get_user", return_value=aaf_user_data)
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    state = "dummy"
    response = test_client.get(
        "/aaf/check-link",
        params={"session_token": "valid_token", "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=action_token_payload,
    )
    assert decoded_token["link"] is True
    assert decoded_token["aaf_only"] is False
    assert decoded_token["primary_id"] == db_user.id
    assert decoded_token["aaf_identity"] == {
        "connection": "AAF",
        "provider": "samlp",
        "user_id": aaf_user_id,
        "isSocial": False,
    }
    link_identity.assert_not_called()
    update_user.assert_called_once()

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert db_user.other_user_id == aaf_user_id


def test_check_link_already_linked_is_idempotent(test_client, test_db_session, persistent_factories, mocker, mock_settings):
    email = "already-linked@example.com"
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        email=email, account_type=BiocommonsUserAccountType.AAF, other_user_id=aaf_user_id
    )
    test_db_session.commit()

    action_token_payload = _action_token_payload(
        aaf_user_id,
        email,
        sub=None,
        iss=None,
    )
    mocker.patch("dependencies.auth.verify_action_token", return_value=action_token_payload)
    existing_account = Auth0UserDataFactory.build(user_id=db_user.id, email=email, blocked=False)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    get_user = mocker.patch("routers.aaf.Auth0Client.get_user", return_value=aaf_user_data)
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    state = "dummy"
    response = test_client.get(
        "/aaf/check-link",
        params={"session_token": "valid_token", "state": state},
        follow_redirects=False,
    )

    decoded_token = _decode_check_link_redirect(
        response,
        state=state,
        settings=mock_settings,
        incoming_token=action_token_payload,
    )
    assert decoded_token["link"] is True
    assert decoded_token["aaf_only"] is False
    assert decoded_token["primary_id"] == db_user.id
    assert decoded_token["aaf_identity"] == {
        "connection": "AAF",
        "provider": "samlp",
        "user_id": aaf_user_id,
        "isSocial": False,
    }
    get_user.assert_called_once_with(user_id=aaf_user_id)
    link_identity.assert_not_called()
    update_user.assert_not_called()


def test_register_aaf_returns_registration_error_when_auth0_update_fails(
    test_client,
    test_db_session,
    mock_auth0_client,
    mocker,
):
    aaf_user_id = random_auth0_id()
    email = "new-aaf-user@example.edu.au"
    action_token_payload = _action_token_payload(
        aaf_user_id,
        email,
        purpose="aaf_registration",
    )
    action_token_payload.update(
        {
            "given_name": "New",
            "family_name": "User",
            "name": "New User",
        }
    )
    mocker.patch("routers.biocommons_register.verify_action_token", return_value=action_token_payload)
    mocker.patch("routers.biocommons_register.validate_recaptcha", return_value=True)
    mocker.patch("routers.biocommons_register.is_aaf_email", return_value=True)
    mock_auth0_client.update_user.side_effect = ValueError("Failed to update user auth0|123: {'message': 'bad request'}")

    response = test_client.post(
        "/biocommons/register-aaf",
        json={
            "session_token": "valid_token",
            "username": "new_aaf_user",
            "recaptcha_token": "valid_recaptcha",
        },
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {
        "message": "AAF registration failed - couldn't update app_metadata: Failed to update user auth0|123: {'message': 'bad request'}",
        "field_errors": [],
    }
    mock_auth0_client.update_user.assert_called_once()


def test_register_aaf_sbp_disabled_rejects_before_creating_user(
    test_client,
    mock_settings,
    mock_auth0_client,
    mocker,
):
    mock_settings.sbp_enabled = False
    aaf_user_id = random_auth0_id()
    email = "researcher@unimelb.edu.au"
    action_token_payload = _action_token_payload(
        aaf_user_id,
        email,
        purpose="aaf_registration",
    )
    action_token_payload.update(
        {
            "given_name": "SBP",
            "family_name": "Disabled",
            "name": "SBP Disabled",
        }
    )
    mocker.patch("routers.biocommons_register.verify_action_token", return_value=action_token_payload)
    mocker.patch("routers.biocommons_register.validate_recaptcha", return_value=True)
    is_aaf_email = mocker.patch("routers.biocommons_register.is_aaf_email", return_value=True)
    institution_check = mocker.patch("register.utils.is_australian_research_institution_email")

    response = test_client.post(
        "/biocommons/register-aaf",
        json={
            "session_token": "valid_token",
            "username": "sbp_disabled_user",
            "bundles": [{"bundle_id": "sbp_workflow_execution", "reason": "SBP access"}],
            "recaptcha_token": "valid_recaptcha",
        },
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {
        "message": "SBP workflow execution is currently unavailable.",
        "field_errors": [],
    }
    is_aaf_email.assert_not_called()
    institution_check.assert_not_called()
    mock_auth0_client.update_user.assert_not_called()
