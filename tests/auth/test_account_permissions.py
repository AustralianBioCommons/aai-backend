import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth.account_permissions import (
    AccountActions,
    account_action_allowed,
    require_account_permission,
)
from auth.user_permissions import get_db_user
from tests.db.datagen import BiocommonsUserFactory


@pytest.mark.parametrize(
    ["action", "expected"],
    [(action, True) for action in AccountActions]
)
def test_account_action_allowed_auth0(action: AccountActions, expected: bool, persistent_factories):
    """
    Test which actions are allowed for auth0 accounts (currently all actions are allowed)
    """
    user = BiocommonsUserFactory.create_sync(account_type="auth0")
    allowed = account_action_allowed(action=action, user=user)
    assert allowed == expected


@pytest.mark.parametrize(
    ["action", "expected"],
    [
        (AccountActions.CHANGE_EMAIL, False),
        (AccountActions.CHANGE_USERNAME, True),
        (AccountActions.CHANGE_PASSWORD, False),
        (AccountActions.CHANGE_NAME, True)
    ]
)
def test_account_action_allowed_aaf(action: AccountActions, expected: bool, persistent_factories):
    """
    Test which actions are allowed for AAF accounts
    """
    user = BiocommonsUserFactory.create_sync(account_type="aaf")
    allowed = account_action_allowed(action=action, user=user)
    assert allowed == expected


@pytest.mark.parametrize(
    ["allowed", "expected_status", "expected_json"],
    [
        (True, 200, {"result": "ok"}),
        (
            False,
            403,
            {"detail": "You do not have permission to perform this action."},
        ),
    ],
)
def test_require_account_permission_dependency(
    allowed: bool,
    expected_status: int,
    expected_json: dict,
    mocker,
):
    user = BiocommonsUserFactory.build(account_type="aaf")
    account_action_allowed_mock = mocker.patch(
        "auth.account_permissions.account_action_allowed",
        return_value=allowed,
    )
    app = FastAPI()
    app.dependency_overrides[get_db_user] = lambda: user

    @app.get(
        "/dummy",
        dependencies=[require_account_permission(AccountActions.CHANGE_EMAIL)],
    )
    def dummy_endpoint():
        return {"result": "ok"}

    client = TestClient(app)
    response = client.get("/dummy")

    assert response.status_code == expected_status
    assert response.json() == expected_json
    account_action_allowed_mock.assert_called_once_with(
        AccountActions.CHANGE_EMAIL,
        user,
    )
