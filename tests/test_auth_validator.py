import pytest
from auth.validator import get_rsa_key
from jose import jwt
from unittest.mock import patch

def test_get_rsa_key_returns_key():
    token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    unverified_header = {"kid": "testkey"}

    with patch("auth.validator.jwt.get_unverified_header", return_value=unverified_header), \
         patch("auth.validator.httpx.get") as mock_get:

        mock_get.return_value.json.return_value = {
            "keys": [{
                "kid": "testkey",
                "kty": "RSA",
                "alg": "RS256",  # ✅ Required
                "n": "AQAB",
                "e": "AQAB"
            }]
        }

        key = get_rsa_key(token)
        assert key is not None
