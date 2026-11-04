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
        FromEmailAddress="sender@example.com",
        Destination={"ToAddresses": ["recipient@example.com"]},
        Content={
            "Simple": {
                "Subject": {"Data": "Test Subject", "Charset": "UTF-8"},
                "Body": {"Html": {"Data": "<p>Hello</p>", "Charset": "UTF-8"}},
            }
        },
        FromEmailAddressIdentityArn="arn:aws:ses:ap-southeast-2:123456789012:identity/example.com",
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
        FromEmailAddress="sender@example.com",
        Destination={"ToAddresses": ["recipient@example.com"]},
        Content={
            "Simple": {
                "Subject": {"Data": "Test Subject", "Charset": "UTF-8"},
                "Body": {"Html": {"Data": "<p>Hello</p>", "Charset": "UTF-8"}},
            }
        },
    )

@pytest.mark.parametrize("aaf_migration", [False, True])
def test_send_email_change_otp(ses_service, mock_settings, aaf_migration):
    service, client = ses_service
    client.send_email.return_value = {"MessageId": "migration-email"}
    service.send_email_change_otp(
        code="123456", target_email="new@example.com", aaf_migration=aaf_migration,
        expiration_minutes=10, settings=mock_settings,
    )
    sent = client.send_email.call_args.kwargs
    assert sent["Destination"] == {"ToAddresses": ["new@example.com"]}
    html = sent["Content"]["Simple"]["Body"]["Html"]["Data"]
    assert "123456" in html
    assert "new@example.com" in html
    assert "10 minutes" in html
    assert "/aaf/migrate/" not in html
    assert "migration_id" not in html
    if aaf_migration:
        assert "institutional login (via AAF)" in html
        assert sent["Content"]["Simple"]["Subject"]["Data"] == "Complete your BioCommons Access account migration"
    else:
        assert "request to change the email address" in html
        assert sent["Content"]["Simple"]["Subject"]["Data"] == "Confirm your new BioCommons Access email address"
