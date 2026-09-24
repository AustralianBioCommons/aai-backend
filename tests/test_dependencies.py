from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from dependencies.auth import require_action_token
from schemas.auth0 import Auth0ActionToken
from tests.datagen import random_auth0_id


def create_signed_action_token(payload: Auth0ActionToken, secret: str) -> str:
    claims = payload.model_dump(mode="json")
    claims["exp"] = datetime.now(timezone.utc) + timedelta(minutes=5)
    return jwt.encode(claims, key=secret, algorithm="HS256")


def test_require_action_token(mock_settings):
    user_id = random_auth0_id()
    payload = Auth0ActionToken(user_id=user_id,
                               email="test@example.com",
                               client_id="abc123",
                               purpose="action_purpose",
                               sub=user_id,
                               iss="mock-domain")
    signed_token = create_signed_action_token(payload, secret=mock_settings.auth0_management_secret)
    checker = require_action_token(purpose="action_purpose")
    checked_payload = checker(signed_token, mock_settings)
    assert checked_payload == payload


def test_require_action_token_wrong_purpose(mock_settings):
    user_id = random_auth0_id()
    payload = Auth0ActionToken(user_id=user_id,
                               email="test@example.com",
                               client_id="abc123",
                               purpose="wrong_purpose",
                               sub=user_id,
                               iss="mock-domain")
    signed_token = create_signed_action_token(payload, secret=mock_settings.auth0_management_secret)
    checker = require_action_token(purpose="action_purpose")
    with pytest.raises(HTTPException):
        checker(signed_token, mock_settings)
