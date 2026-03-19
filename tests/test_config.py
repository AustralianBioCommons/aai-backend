import pytest
from pydantic import ValidationError

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
        "no_reply_email_sender": "no-reply@example.com",
    }


@pytest.mark.parametrize(
    ("environment", "expected_url"),
    [
        ("dev", "https://dev.portal.aai.test.biocommons.org.au"),
        ("development", "https://dev.portal.aai.test.biocommons.org.au"),
        ("staging", "https://staging.portal.aai.test.biocommons.org.au"),
        ("stage", "https://staging.portal.aai.test.biocommons.org.au"),
        ("production", "https://portal.access.services.biocommons.org.au"),
        ("prod", "https://portal.access.services.biocommons.org.au"),
    ],
)
def test_aai_portal_url_defaults_by_environment(environment, expected_url):
    settings = Settings(_env_file=None, environment=environment, **_base_settings_kwargs())
    assert settings.aai_portal_url == expected_url


def test_no_reply_email_sender_manual():
    """
    Test manually setting the no-reply email sender works.
    """
    custom_email = "no-reply@aai.test.biocommons.org.au"
    settings = Settings(
        _env_file=None,
        **{**_base_settings_kwargs(), "no_reply_email_sender": custom_email}
    )
    assert settings.no_reply_email_sender == custom_email


def test_no_reply_email_sender_required():
    """
    Test that omitting the no-reply email sender raises a validation error.
    """
    # Start with a valid base config and remove the required field.
    kwargs = _base_settings_kwargs()
    kwargs.pop("no_reply_email_sender")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **kwargs)


def test_aai_portal_url_override_strips_trailing_slash():
    settings = Settings(
        _env_file=None,
        aai_portal_url="https://example.test/",
        **_base_settings_kwargs(),
    )
    assert settings.aai_portal_url == "https://example.test"


def test_unknown_environment_requires_explicit_portal_url():
    with pytest.raises(ValidationError, match="Input should be 'dev', 'staging' or 'production'"):
        Settings(_env_file=None, environment="qa", **_base_settings_kwargs())
