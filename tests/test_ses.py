from unittest.mock import MagicMock, patch

import pytest

from auth.ses import EmailService


@pytest.fixture
def mock_boto_client():
    with patch("auth.ses.boto3.client") as mock_client:
        yield mock_client

def test_send_email_success(mock_boto_client):
    """Test successful email sending"""
    mock_ses = MagicMock()
    mock_ses.send_email.return_value = {"MessageId": "test-message-id"}
    mock_boto_client.return_value = mock_ses

    service = EmailService()
    service.send(
        to_address="recipient@example.com",
        subject="Test Subject",
        body_html="<p>This is a test</p>",
        sender="sender@example.com",
    )

    mock_ses.send_email.assert_called_once_with(
        Source="sender@example.com",
        Destination={"ToAddresses": ["recipient@example.com"]},
        Message={
            "Subject": {"Data": "Test Subject"},
            "Body": {"Html": {"Data": "<p>This is a test</p>"}},
        },
    )

def test_send_email_failure(mock_boto_client):
    """Test SES failure raises exception and logs"""
    from botocore.exceptions import ClientError

    mock_ses = MagicMock()
    mock_ses.send_email.side_effect = ClientError(
        error_response={
            "Error": {"Message": "Invalid email", "Code": "MessageRejected"}
        },
        operation_name="SendEmail",
    )
    mock_boto_client.return_value = mock_ses

    service = EmailService()

    with pytest.raises(ClientError):
        service.send(
            to_address="bad@example.com",
            subject="Failing",
            body_html="<p>Bad request</p>",
            sender="no-reply@example.com",
        )
