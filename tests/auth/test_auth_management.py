from unittest.mock import patch

from auth.management import get_management_token


def test_get_management_token_success(mock_settings):
    with patch("auth.management.httpx.post") as mock_post:
        mock_post.return_value.json.return_value = {"access_token": "abc123"}
        mock_post.return_value.raise_for_status = lambda: None

        token = get_management_token(settings=mock_settings)
        assert token == "abc123"
