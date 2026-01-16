from biocommons.emails import get_default_sender_email


def test_get_default_sender(mock_settings):
    email = get_default_sender_email(mock_settings)
    assert email == mock_settings.default_email_sender


def test_get_default_sender_email_fetches_settings(mock_settings, mocker):
    mocker.patch('biocommons.emails.get_settings', return_value=mock_settings)
    email = get_default_sender_email()
    assert email == mock_settings.default_email_sender
