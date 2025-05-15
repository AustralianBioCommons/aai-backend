from unittest.mock import patch

from auth.config import Settings
from auth.management import get_management_token


def test_get_management_token_success():
    with patch("auth.management.httpx.post") as mock_post, \
         patch("auth.management.get_settings", return_value=Settings(
            auth0_domain="yourdomain.auth0.com",
            auth0_management_id="testid",
            auth0_management_secret="testsecret",
            auth0_audience="https://your-auth0-api-audience",
            jwt_secret_key="supersecret",
            cors_allowed_origins=["*"]
        )):

        mock_post.return_value.json.return_value = {"access_token": "abc123"}
        mock_post.return_value.raise_for_status = lambda: None

        token = get_management_token()
        assert token == "abc123"
