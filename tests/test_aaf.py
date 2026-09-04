from http import HTTPStatus
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from fastapi import HTTPException

from auth0.client import Auth0Client
from routers.aaf import link_aaf_account, mark_user_aaf_only
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


def test_link_aaf_account_raises_502_when_auth0_update_fails(test_db_session, persistent_factories):
    db_user = BiocommonsUserFactory.create_sync(account_type=BiocommonsUserAccountType.AUTH0, other_user_id=None)
    test_db_session.commit()

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
        )

    assert exc_info.value.status_code == HTTPStatus.BAD_GATEWAY
    auth0_client.link_identity.assert_not_called()
    auth0_client.update_user.assert_called_once()

    test_db_session.refresh(db_user)
    assert db_user.account_type == BiocommonsUserAccountType.AUTH0
    assert db_user.other_user_id is None


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


def _assert_marked_aaf_only(update_user_mock, aaf_user_id: str, email: str):
    update_user_mock.assert_called_once()
    call_args, call_kwargs = update_user_mock.call_args
    assert call_kwargs["user_id"] == aaf_user_id
    app_metadata = call_kwargs["update_data"].app_metadata
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
