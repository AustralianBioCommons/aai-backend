from schemas.tokens import AccessTokenPayload
from schemas.user import User


def test_is_admin_true():
    payload = AccessTokenPayload(
        exp=9999999999,
        iat=9999999000,
        iss="https://example.com/",
        sub="abc123",
        aud=["client_id"],
        scope="read:all",
        **{
            "biocommons.org.au/roles": ["PlatformAdmin"],  # ✅ match schema key
            "permissions": ["read"]
        }
    )
    user = User(access_token=payload)
    assert user.is_admin() is True

def test_is_admin_false():
    payload = AccessTokenPayload(
        exp=9999999999,
        iat=9999999000,
        iss="https://example.com/",
        sub="abc123",
        aud=["client_id"],
        scope="read:all",
        **{
            "biocommons.org.au/roles": ["guest"],  # ✅ match schema key
            "permissions": ["read"]
        }
    )
    user = User(access_token=payload)
    assert user.is_admin() is False
