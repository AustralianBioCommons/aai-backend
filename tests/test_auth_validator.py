from unittest.mock import patch

from jose import jwt
from jose.backends.rsa_backend import RSAKey

from auth.config import Settings
from auth.validator import get_rsa_key


def test_get_rsa_key_returns_key():
    token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    unverified_header = {"kid": "testkey"}

    with patch("auth.validator.jwt.get_unverified_header", return_value=unverified_header), \
         patch("auth.validator.httpx.get") as mock_get, \
         patch("auth.validator.get_settings", return_value=Settings(
             auth0_domain="yourdomain.auth0.com",
             auth0_management_id="testid",
             auth0_management_secret="testsecret",
             auth0_audience="https://your-auth0-api-audience",
             jwt_secret_key="supersecret",
             cors_allowed_origins=["*"]
         )):

        mock_get.return_value.json.return_value = {
            "keys": [{
                "kid": "testkey",
                "kty": "RSA",
                "alg": "RS256",
                "n": "sXchfZm9UOCNHQ",  # base64url-encoded dummy values
                "e": "AQAB"
            }]
        }

        key = get_rsa_key(token)
        assert key is not None
        assert isinstance(key, RSAKey)
