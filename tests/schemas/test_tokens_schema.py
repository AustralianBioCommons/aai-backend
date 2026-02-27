from schemas.tokens import AccessTokenPayload


def test_access_token_payload_accepts_roles_alias():
    payload = AccessTokenPayload(
        **{
            "https://biocommons.org.au/roles": ["Admin"],
            "email": "user@example.com",
            "iss": "https://issuer.example.com/",
            "sub": "auth0|123",
            "aud": ["audience"],
            "exp": 9999999999,
            "iat": 9999999000,
            "permissions": [],
        }
    )
    assert payload.biocommons_roles == ["Admin"]


def test_access_token_payload_accepts_roles_field_name():
    payload = AccessTokenPayload(
        biocommons_roles=["User"],
        email="user@example.com",
        iss="https://issuer.example.com/",
        sub="auth0|123",
        aud=["audience"],
        exp=9999999999,
        iat=9999999000,
        permissions=[],
    )
    assert payload.biocommons_roles == ["User"]


def test_has_admin_role_true(mock_settings):
    payload = AccessTokenPayload(
        biocommons_roles=["Admin"],
        email="user@example.com",
        iss="https://issuer.example.com/",
        sub="auth0|123",
        aud=["audience"],
        exp=9999999999,
        iat=9999999000,
        permissions=[],
    )
    assert payload.has_admin_role(mock_settings)


def test_has_admin_role_false(mock_settings):
    payload = AccessTokenPayload(
        biocommons_roles=["User"],
        email="user@example.com",
        iss="https://issuer.example.com/",
        sub="auth0|123",
        aud=["audience"],
        exp=9999999999,
        iat=9999999000,
        permissions=[],
    )
    assert not payload.has_admin_role(mock_settings)
