import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from unittest.mock import patch

import jwt
import pytest
import respx

# Tools from hazmat should only be used for testing!
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from httpx import Response
from jwt.algorithms import RSAAlgorithm

from auth import auth0_security, get_auth0_token
from auth.user_permissions import user_is_general_admin
from auth.validator import (
    KEY_CACHE,
    _fetch_rsa_keys,
    get_rsa_key,
    verify_action_token,
    verify_jwt,
)
from config import Settings
from db.models import BiocommonsUser
from tests.datagen import AccessTokenPayloadFactory, SessionUserFactory

TEST_HS256_SECRET = "test-hs256-secret-key-with-32-bytes"
TEST_MANAGEMENT_SECRET = "test-management-secret-key-with-32b"
TEST_WRONG_MANAGEMENT_SECRET = "wrong-management-secret-key-32b!"
TEST_CORRECT_MANAGEMENT_SECRET = "correct-management-secret-key-32"


def generate_public_private_key_pair():
    # Code from https://fmpm.dev/mocking-auth0-tokens
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


@dataclass
class AuthTokenData:
    """
    Stores all the information needed to generate an access token and
    test that it can be decoded.
    """

    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    access_token_str: str
    access_token_data: dict
    key_id: str


def create_access_token(
    email: str = "user@example.com",
    roles: Optional[list[str]] = None,
    iss: str = "https://issuer.example.com",
    sub: Optional[str] = None,
    iat: Optional[int] = None,
    exp: Optional[int] = None,
    aud: str = "https://audience.example.com",
    scope: Optional[list[str]] = None,
    azp: Optional[str] = None,
    permissions: Optional[list[str]] = None,
    algorithm: str = "RS256",
    public_key_id: str = "example-key",
) -> AuthTokenData:
    """
    Create an OIDC access token along with a dummy private and public key
    for signing it. Each field of the payload can be set, but otherwise
    will get a sensible default (e.g. expiry time in the future).
    """
    if roles is None:
        roles = []
    # Generate a random alphanumeric ID
    if sub is None:
        sub = uuid.uuid4().hex
    if iat is None:
        iat = int(datetime.now().strftime("%s"))
    if exp is None:
        exp = int((datetime.now() + timedelta(hours=1)).strftime("%s"))
    if azp is None:
        azp = uuid.uuid4().hex
    if permissions is None:
        permissions = []

    payload = {
        "email": email,
        "https://biocommons.org.au/roles": roles,
        "iss": iss,
        "sub": sub,
        "aud": [aud],
        "iat": iat,
        "exp": exp,
        "scope": scope,
        "azp": azp,
        "permissions": permissions,
    }
    public_key, private_key = generate_public_private_key_pair()
    from cryptography.hazmat.primitives import serialization
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    access_token_encoded = jwt.encode(
        payload,
        key=pem_private_key,
        algorithm=algorithm,
        headers={"kid": public_key_id},
    )
    return AuthTokenData(
        private_key=private_key,
        public_key=public_key,
        access_token_str=access_token_encoded,
        access_token_data=payload,
        key_id=public_key_id,
    )


def test_get_rsa_key_returns_key(mock_settings: Settings):
    token = jwt.encode({"some": "payload"}, TEST_HS256_SECRET, algorithm="HS256")
    unverified_header = {"kid": "testkey"}

    with patch("auth.validator.jwt.get_unverified_header", return_value=unverified_header), \
         patch("auth.validator.httpx.get") as mock_get:

        mock_get.return_value.json.return_value = {
            "keys": [{
                "kid": "testkey",
                "kty": "RSA",
                "alg": "RS256",
                "n": "sXchfZm9UOCNHQ",  # base64url-encoded dummy values
                "e": "AQAB"
            }]
        }

        key = get_rsa_key(token, settings=mock_settings)
        assert key is not None


def generate_dummy_rsa_key(key_id: str) -> dict:
    """Generate a test RSA key in JWKS format."""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Convert public key to JWK and add metadata
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk_dict["kid"] = key_id
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"

    return jwk_dict


@respx.mock
def test_get_rsa_key_retry_on_failure(mock_settings: Settings):
    """Test that get_rsa_key retries after clearing cache when key is not found."""
    token = jwt.encode({"some": "payload"}, TEST_HS256_SECRET, algorithm="HS256")
    unverified_header = {"kid": "missing_key"}

    other_key = generate_dummy_rsa_key("other_key")
    missing_key = generate_dummy_rsa_key("missing_key")

    # Mock the cached response (first call) - key not found
    cached_jwks = {
        "keys": [other_key]
    }

    # Mock the fresh response (second call after cache clear) - key found
    fresh_jwks = {
        "keys": [other_key, missing_key]
    }

    jwks_url = f"https://{mock_settings.auth0_domain}/.well-known/jwks.json"
    route = respx.get(jwks_url).mock(
        side_effect=[
            Response(200, json=cached_jwks),
            Response(200, json=fresh_jwks)
        ]
    )

    # Clear the cache before the test to ensure clean state
    from auth.validator import KEY_CACHE
    KEY_CACHE.clear()
    with patch("auth.validator.jwt.get_unverified_header", return_value=unverified_header):
        # Call get_rsa_key
        key = get_rsa_key(token, settings=mock_settings)
        # Verify the key was found after retry
        assert key is not None
        # Verify that the endpoint was called twice (cached + fresh)
        assert route.call_count == 2


@respx.mock
def test_get_rsa_key_no_retry_needed_when_key_found_first_time(mock_settings: Settings):
    """Test that get_rsa_key doesn't retry when key is found on first attempt."""
    token = jwt.encode({"some": "payload"}, TEST_HS256_SECRET, algorithm="HS256")
    unverified_header = {"kid": "found_key"}

    # Generate test key using jose
    found_key = generate_dummy_rsa_key("found_key")

    jwks_response = {
        "keys": [found_key]
    }

    jwks_url = f"https://{mock_settings.auth0_domain}/.well-known/jwks.json"
    route = respx.get(jwks_url).mock(return_value=Response(200, json=jwks_response))

    # Clear the cache before the test to ensure clean state
    from auth.validator import KEY_CACHE
    KEY_CACHE.clear()

    with patch("auth.validator.jwt.get_unverified_header", return_value=unverified_header):
        # Call get_rsa_key
        key = get_rsa_key(token, settings=mock_settings)

        # Verify key was found
        assert key is not None

        # Verify endpoint was called only once (no retry needed)
        assert route.call_count == 1


def test_auth0_security_passes_bearer_token_to_route():
    """
    Test that our auth0_security dependency correctly extracts and passes the bearer token to the route.
    :return:
    """
    app = FastAPI()

    @app.get("/protected")
    def protected_route(
        bearer_token: HTTPAuthorizationCredentials = Depends(auth0_security),
    ):
        return {
            "token": bearer_token.credentials
        }

    client = TestClient(app)

    response = client.get(
        "/protected",
        headers={"Authorization": "Bearer test-access-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "token": "test-access-token",
    }


def test_get_auth0_token_missing_authorization_header_returns_unauthorized():
    """
    Test that get_auth0_token returns an unauthorized response when the Authorization header is missing.
    """
    app = FastAPI()

    @app.get("/protected")
    def protected_route(token: str = Depends(get_auth0_token)):
        return {"token": token}

    client = TestClient(app)
    response = client.get("/protected")
    assert response.status_code == 401
    body = response.json()
    assert isinstance(body, dict)
    assert "detail" in body


def test_get_auth0_token_invalid_authorization_scheme_returns_unauthorized():
    """
    Test that get_auth0_token returns an unauthorized response when the Authorization header uses an invalid scheme.
    """
    app = FastAPI()

    @app.get("/protected")
    def protected_route(token: str = Depends(get_auth0_token)):
        return {"token": token}

    client = TestClient(app)
    response = client.get(
        "/protected",
        headers={"Authorization": "Basic test-access-token"},
    )
    assert response.status_code == 401
    body = response.json()
    assert isinstance(body, dict)
    assert "detail" in body


def test_verify_jwt(mock_settings: Settings, mocker):
    """
    Test we can verify a JWT based on issuer and audience.
    """
    mock_settings.auth0_audience = f"https://{mock_settings.auth0_domain}/api/"
    token = create_access_token(
        email="user@example.com",
        # Our verify code assumes the issuer will be the auth0 domain
        iss=f"https://{mock_settings.auth0_domain}/",
        aud=f"https://{mock_settings.auth0_domain}/api/",
    )
    mocker.patch("auth.validator.get_rsa_key", return_value=token.public_key)
    decoded = verify_jwt(token.access_token_str, settings=mock_settings)
    assert decoded.email == "user@example.com"


def test_verify_jwt_invalid_issuer(mock_settings: Settings, mocker):
    """
    Test invalid JWT issuer returns unauthorized.
    """
    mock_settings.auth0_audience = f"https://{mock_settings.auth0_domain}/api/"
    token = create_access_token(
        email="user@example.com",
        iss="https://other.example.com/",
        aud=f"https://{mock_settings.auth0_domain}/api/",
    )
    mocker.patch("auth.validator.get_rsa_key", return_value=token.public_key)

    with pytest.raises(HTTPException) as excinfo:
        verify_jwt(token.access_token_str, settings=mock_settings)

    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Not authorized"


def test_verify_jwt_custom_domain_issuer(mock_settings: Settings, mocker):
    """
    Check that our verify code also works with the auth0_issuer setting
    """
    mock_settings.auth0_audience = f"https://{mock_settings.auth0_domain}/api/"
    mock_settings.auth0_issuer = "https://mydomain.org/"
    token = create_access_token(
        email="user@example.com",
        iss=mock_settings.auth0_issuer,
        aud=mock_settings.auth0_audience,
    )
    mocker.patch("auth.validator.get_rsa_key", return_value=token.public_key)
    decoded = verify_jwt(token.access_token_str, settings=mock_settings)
    assert decoded.email == "user@example.com"


def test_verify_jwt_missing_kid_returns_unauthorized(mock_settings: Settings, mocker):
    """
    Test a token with no kid header returns 401 instead of crashing.
    """
    mock_settings.auth0_audience = f"https://{mock_settings.auth0_domain}/api/"
    token = create_access_token(
        email="user@example.com",
        iss=f"https://{mock_settings.auth0_domain}/",
        aud=f"https://{mock_settings.auth0_domain}/api/",
    )
    mocker.patch("auth.validator.jwt.get_unverified_header", return_value={"alg": "RS256"})

    with pytest.raises(HTTPException) as excinfo:
        verify_jwt(token.access_token_str, settings=mock_settings)

    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Not authorized"


def test_user_is_general_admin_returns_current_user_for_biocommons_admin(
    mock_settings: Settings,
    mocker,
    test_db_session,
):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["Admin"])
    current_user = SessionUserFactory.build(access_token=payload)
    db_user = mocker.Mock(spec=BiocommonsUser)
    db_user.is_any_platform_admin = mocker.Mock()
    db_user.is_any_group_admin = mocker.Mock()

    result = user_is_general_admin(
        current_user=current_user,
        settings=mock_settings,
        db_user=db_user,
        db_session=test_db_session,
    )

    assert result is current_user
    db_user.is_any_platform_admin.assert_not_called()
    db_user.is_any_group_admin.assert_not_called()


def test_user_is_general_admin_accepts_platform_admin(
    mock_settings: Settings,
    mocker,
    test_db_session,
):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/platform/admin"])
    current_user = SessionUserFactory.build(access_token=payload)
    db_user = mocker.Mock(spec=BiocommonsUser)
    db_user.is_any_platform_admin = mocker.Mock(return_value=True)
    db_user.is_any_group_admin = mocker.Mock()

    result = user_is_general_admin(
        current_user=current_user,
        settings=mock_settings,
        db_user=db_user,
        db_session=test_db_session,
    )

    assert result is current_user
    db_user.is_any_platform_admin.assert_called_once_with(
        access_token=current_user.access_token,
        db_session=test_db_session,
    )
    db_user.is_any_group_admin.assert_not_called()


def test_user_is_general_admin_accepts_group_admin(
    mock_settings: Settings,
    mocker,
    test_db_session,
):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/group/admin"])
    current_user = SessionUserFactory.build(access_token=payload)
    db_user = mocker.Mock(spec=BiocommonsUser)
    db_user.is_any_platform_admin = mocker.Mock(return_value=False)
    db_user.is_any_group_admin = mocker.Mock(return_value=True)

    result = user_is_general_admin(
        current_user=current_user,
        settings=mock_settings,
        db_user=db_user,
        db_session=test_db_session,
    )

    assert result is current_user
    db_user.is_any_platform_admin.assert_called_once_with(
        access_token=current_user.access_token,
        db_session=test_db_session,
    )
    db_user.is_any_group_admin.assert_called_once_with(
        access_token=current_user.access_token,
        db_session=test_db_session,
    )


def test_user_is_general_admin_raises_when_not_admin(
    mock_settings: Settings,
    mocker,
    test_db_session,
):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=["biocommons/role/user"])
    current_user = SessionUserFactory.build(access_token=payload)
    db_user = mocker.Mock(spec=BiocommonsUser)
    db_user.is_any_platform_admin = mocker.Mock(return_value=False)
    db_user.is_any_group_admin = mocker.Mock(return_value=False)

    with pytest.raises(HTTPException, match="You must be an admin to access this endpoint."):
        user_is_general_admin(
            current_user=current_user,
            settings=mock_settings,
            db_user=db_user,
            db_session=test_db_session,
        )


def test_user_is_general_admin_raises_when_db_user_missing(
    mock_settings: Settings,
    test_db_session,
):
    payload = AccessTokenPayloadFactory.build(biocommons_roles=[])
    current_user = SessionUserFactory.build(access_token=payload)

    with pytest.raises(HTTPException, match="You must be an admin to access this endpoint."):
        user_is_general_admin(
            current_user=current_user,
            settings=mock_settings,
            db_user=None,
            db_session=test_db_session,
        )


def test_verify_action_token_success(mock_settings: Settings):
    """
    Test that verify_action_token successfully decodes a valid HS256 token.
    """
    secret = TEST_MANAGEMENT_SECRET
    mock_settings.auth0_management_secret = secret
    payload = {
        "sub": "auth0|123",
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now().timestamp())
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    decoded = verify_action_token(token, mock_settings)
    assert decoded["sub"] == "auth0|123"


def test_verify_action_token_expired(mock_settings: Settings):
    """
    Test that verify_action_token raises 401 when the token is expired.
    """
    secret = TEST_MANAGEMENT_SECRET
    mock_settings.auth0_management_secret = secret
    payload = {
        "sub": "auth0|123",
        "exp": int((datetime.now() - timedelta(hours=1)).timestamp()),
        "iat": int((datetime.now() - timedelta(hours=2)).timestamp())
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    with pytest.raises(HTTPException) as excinfo:
        verify_action_token(token, mock_settings)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "session_token expired"


def test_verify_action_token_invalid_signature(mock_settings: Settings):
    """
    Test that verify_action_token raises 401 when the signature is invalid.
    """
    mock_settings.auth0_management_secret = TEST_CORRECT_MANAGEMENT_SECRET
    payload = {
        "sub": "auth0|123",
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp())
    }
    # Sign with a different secret
    token = jwt.encode(payload, TEST_WRONG_MANAGEMENT_SECRET, algorithm="HS256")

    with pytest.raises(HTTPException) as excinfo:
        verify_action_token(token, mock_settings)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "invalid session_token"


def test_verify_action_token_missing_exp(mock_settings: Settings):
    """
    Test that verify_action_token raises 401 when the exp claim is missing.
    """
    secret = TEST_MANAGEMENT_SECRET
    mock_settings.auth0_management_secret = secret
    payload = {
        "sub": "auth0|123"
        # exp missing
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    with pytest.raises(HTTPException) as excinfo:
        verify_action_token(token, mock_settings)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "invalid session_token"


@respx.mock
def test_fetch_rsa_keys_only_refreshes_once_when_cache_is_expired(mock_settings: Settings):
    """
    Demonstrate that concurrent requests only trigger one JWKS refresh.
    """
    KEY_CACHE.clear()

    jwks_url = f"https://{mock_settings.auth0_domain}/.well-known/jwks.json"
    jwks_response = {"keys": [generate_dummy_rsa_key("test-key")]}

    start_gate = threading.Barrier(5)
    first_request_started = threading.Event()
    release_refresh = threading.Event()
    call_count = 0
    call_count_lock = threading.Lock()

    def slow_response(*args, **kwargs):
        nonlocal call_count
        with call_count_lock:
            call_count += 1
        first_request_started.set()
        release_refresh.wait()
        return Response(200, json=jwks_response)

    respx.get(jwks_url).mock(side_effect=slow_response)

    results = []
    results_lock = threading.Lock()

    def worker():
        start_gate.wait(timeout=10)
        result = _fetch_rsa_keys(mock_settings.auth0_domain)
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()

    first_request_started.wait()
    release_refresh.set()

    for thread in threads:
        thread.join(timeout=10)

    # Check all calls went through
    assert len(results) == 5
    assert all(result == jwks_response for result in results)
    # Check the Auth0 API was only called once
    assert call_count == 1
