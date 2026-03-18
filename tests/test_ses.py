import boto3
import pytest
from moto import mock_aws

from auth.ses import EmailService


@pytest.fixture
def ses_client():
    with mock_aws():
        client = boto3.client("ses", region_name="ap-southeast-2")
        client.verify_email_identity(EmailAddress="sender@example.com")
        yield client


@pytest.fixture
def ses_service(mocker):
    mock_client = mocker.Mock()
    mocker.patch("auth.ses.boto3.client", return_value=mock_client)
    mocker.patch("auth.ses.get_default_sender_email", return_value="sender@example.com")
    return EmailService(region_name="ap-southeast-2"), mock_client


def test_send_email_success_with_moto(ses_client, mocker, mock_settings):
    service = EmailService(region_name="ap-southeast-2")
    mocker.patch("auth.ses.get_default_sender_email", return_value="sender@example.com")
    service.send(
        to_address="recipient@example.com",
        subject="Test Moto Subject",
        body_html="<p>This is a moto test email</p>",
        settings=mock_settings,
    )
    # If no exception, we assume success with moto


def test_send_email_failure_with_moto(ses_client, mocker, mock_settings):
    service = EmailService(region_name="ap-southeast-2")

    # Deliberately use an unverified sender to cause failure
    mocker.patch("auth.ses.get_default_sender_email", return_value="unverified@example.com")
    with pytest.raises(Exception):
        service.send(
            to_address="recipient@example.com",
            subject="Should Fail",
            body_html="<p>Should not send</p>",
            settings=mock_settings
        )


def test_send_uses_source_arn_when_defined(ses_service, mocker):
    service, mock_client = ses_service
    mock_settings = mocker.Mock(ses_resource_arn="arn:aws:ses:ap-southeast-2:123456789012:identity/example.com")
    mock_client.send_email.return_value = {'MessageId': 'test-id'}

    service.send(
        to_address="recipient@example.com",
        subject="Test Subject",
        body_html="<p>Hello</p>",
        settings=mock_settings,
    )

    mock_client.send_email.assert_called_once_with(
        Source="sender@example.com",
        SourceArn="arn:aws:ses:ap-southeast-2:123456789012:identity/example.com",
        Destination={"ToAddresses": ["recipient@example.com"]},
        Message={
            "Subject": {"Data": "Test Subject"},
            "Body": {"Html": {"Data": "<p>Hello</p>"}},
        },
    )


def test_send_omits_source_arn_when_not_defined(ses_service, mocker):
    service, mock_client = ses_service
    mock_settings = mocker.Mock(ses_resource_arn=None)
    mock_client.send_email.return_value = {'MessageId': 'test-id'}

    service.send(
        to_address="recipient@example.com",
        subject="Test Subject",
        body_html="<p>Hello</p>",
        settings=mock_settings,
    )

    mock_client.send_email.assert_called_once_with(
        Source="sender@example.com",
        Destination={"ToAddresses": ["recipient@example.com"]},
        Message={
            "Subject": {"Data": "Test Subject"},
            "Body": {"Html": {"Data": "<p>Hello</p>"}},
        },
    )
