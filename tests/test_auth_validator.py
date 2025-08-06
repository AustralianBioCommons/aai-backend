import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from unittest.mock import patch

import pytest

# Tools from hazmat should only be used for testing!
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from fastapi import HTTPException
from jose import jwt
from jose.backends.cryptography_backend import CryptographyRSAKey

from auth.validator import get_rsa_key, verify_jwt
from config import Settings


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
    token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
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
        assert isinstance(key, CryptographyRSAKey)


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
    Test invalid JWT issuer raises an error
    """
    mock_settings.auth0_audience = f"https://{mock_settings.auth0_domain}/api/"
    token = create_access_token(
        email="user@example.com",
        iss="https://other.example.com/",
        aud=f"https://{mock_settings.auth0_domain}/api/",
    )
    mocker.patch("auth.validator.get_rsa_key", return_value=token.public_key)
    with pytest.raises(HTTPException, match="Invalid issuer"):
        verify_jwt(token.access_token_str, settings=mock_settings)


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
