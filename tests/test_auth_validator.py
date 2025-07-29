from unittest.mock import patch

from jose import jwt
from jose.backends.cryptography_backend import CryptographyRSAKey

from auth.validator import get_rsa_key
from config import Settings


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
