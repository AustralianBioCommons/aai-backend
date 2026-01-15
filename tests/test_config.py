import pytest

from config import Settings


def _base_settings_kwargs():
    return {
        "auth0_domain": "mock-domain",
        "auth0_management_id": "mock-id",
        "auth0_management_secret": "mock-secret",
        "auth0_audience": "mock-audience",
        "recaptcha_secret": "mock-recaptcha",
        "jwt_secret_key": "mock-secret-key",
        "cors_allowed_origins": "https://test",
    }


@pytest.mark.parametrize(
    ("environment", "expected_url"),
    [
        ("dev", "https://dev.portal.aai.test.biocommons.org.au"),
        ("development", "https://dev.portal.aai.test.biocommons.org.au"),
        ("staging", "https://staging.portal.aai.test.biocommons.org.au"),
        ("stage", "https://staging.portal.aai.test.biocommons.org.au"),
    ],
)
def test_aai_portal_url_defaults_by_environment(environment, expected_url):
    settings = Settings(_env_file=None, environment=environment, **_base_settings_kwargs())
    assert settings.aai_portal_url == expected_url


def test_aai_portal_url_override_strips_trailing_slash():
    settings = Settings(
        _env_file=None,
        aai_portal_url="https://example.test/",
        **_base_settings_kwargs(),
    )
    assert settings.aai_portal_url == "https://example.test"


def test_unknown_environment_requires_explicit_portal_url():
    with pytest.raises(ValueError, match="Unknown ENVIRONMENT value"):
        Settings(_env_file=None, environment="qa", **_base_settings_kwargs())
