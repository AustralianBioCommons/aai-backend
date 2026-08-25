from http import HTTPStatus
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from auth0.client import Auth0Client
from routers.aaf import link_aaf_account
from schemas.biocommons import Auth0Identity, BiocommonsUserAccountType
from tests.datagen import Auth0UserDataFactory, random_auth0_id
from tests.db.datagen import BiocommonsUserFactory


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
    auth0_client.link_identity.assert_called_once_with(
        primary_user_id=db_user.id,
        secondary_user_id=aaf_user_id,
        secondary_provider="samlp",
        secondary_connection_name="AAF",
    )

    auth0_client.update_user.assert_called_once()
    call_args, call_kwargs = auth0_client.update_user.call_args
    assert call_args[0] == db_user.id
    app_metadata = call_kwargs["update_data"].app_metadata
    assert app_metadata.account_type == BiocommonsUserAccountType.AAF
    assert app_metadata.linking_completed is True
    assert app_metadata.linking_completed_at is not None

    assert result.id == db_user.id
    assert result.account_type == BiocommonsUserAccountType.AAF
    assert result.other_user_id == aaf_user_id

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


def test_link_aaf_account_idempotent_when_already_linked(test_db_session, persistent_factories):
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        account_type=BiocommonsUserAccountType.AAF, other_user_id=aaf_user_id
    )
    test_db_session.commit()

    auth0_client = MagicMock(spec=Auth0Client)

    result = link_aaf_account(
        db_user_id=db_user.id,
        aaf_user_id=aaf_user_id,
        auth0_client=auth0_client,
        session=test_db_session,
    )

    auth0_client.get_user.assert_not_called()
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_not_called()
    assert result.id == db_user.id


def _action_token_payload(user_id: str, email: str, purpose: str = "aaf_link", client_id: str = "test-client") -> dict:
    return {"user_id": user_id, "email": email, "client_id": client_id, "purpose": purpose}


def test_check_link_no_existing_account(test_client, mocker):
    aaf_user_id = random_auth0_id()
    email = "new-aaf-user@example.com"
    mocker.patch("dependencies.auth.verify_action_token", return_value=_action_token_payload(aaf_user_id, email))
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[])
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    response = test_client.get("/aaf/check-link", params={"session_token": "valid_token"})

    assert response.status_code == 200
    assert response.json() == {"link": False, "aaf_only": True, "primary_id": aaf_user_id}
    link_identity.assert_not_called()
    update_user.assert_not_called()


def test_check_link_existing_account_blocked(test_client, mocker):
    aaf_user_id = random_auth0_id()
    email = "blocked-user@example.com"
    mocker.patch("dependencies.auth.verify_action_token", return_value=_action_token_payload(aaf_user_id, email))
    existing_account = Auth0UserDataFactory.build(email=email, blocked=True)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])

    response = test_client.get("/aaf/check-link", params={"session_token": "valid_token"})

    assert response.status_code == 403


def test_check_link_existing_account_links(test_client, test_db_session, persistent_factories, mocker):
    email = "existing-user@example.com"
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        email=email, account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None
    )
    test_db_session.commit()

    mocker.patch("dependencies.auth.verify_action_token", return_value=_action_token_payload(aaf_user_id, email))
    existing_account = Auth0UserDataFactory.build(user_id=db_user.id, email=email, blocked=False)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])
    aaf_user_data = Auth0UserDataFactory.build(
        identities=[Auth0Identity(connection="AAF", provider="samlp", user_id=aaf_user_id, isSocial=False)]
    )
    mocker.patch("routers.aaf.Auth0Client.get_user", return_value=aaf_user_data)
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    response = test_client.get("/aaf/check-link", params={"session_token": "valid_token"})

    assert response.status_code == 200
    assert response.json() == {"link": True, "aaf_only": False, "primary_id": db_user.id}
    link_identity.assert_called_once_with(
        primary_user_id=db_user.id,
        secondary_user_id=aaf_user_id,
        secondary_provider="samlp",
        secondary_connection_name="AAF",
    )
    update_user.assert_called_once()

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AAF
    assert db_user.other_user_id == aaf_user_id


def test_check_link_already_linked_is_idempotent(test_client, test_db_session, persistent_factories, mocker):
    email = "already-linked@example.com"
    aaf_user_id = random_auth0_id()
    db_user = BiocommonsUserFactory.create_sync(
        email=email, account_type=BiocommonsUserAccountType.AAF, other_user_id=aaf_user_id
    )
    test_db_session.commit()

    mocker.patch("dependencies.auth.verify_action_token", return_value=_action_token_payload(aaf_user_id, email))
    existing_account = Auth0UserDataFactory.build(user_id=db_user.id, email=email, blocked=False)
    mocker.patch("routers.aaf.Auth0Client.search_users_by_email", return_value=[existing_account])
    get_user = mocker.patch("routers.aaf.Auth0Client.get_user")
    link_identity = mocker.patch("routers.aaf.Auth0Client.link_identity")
    update_user = mocker.patch("routers.aaf.Auth0Client.update_user")

    response = test_client.get("/aaf/check-link", params={"session_token": "valid_token"})

    assert response.status_code == 200
    assert response.json() == {"link": True, "aaf_only": False, "primary_id": db_user.id}
    get_user.assert_not_called()
    link_identity.assert_not_called()
    update_user.assert_not_called()
