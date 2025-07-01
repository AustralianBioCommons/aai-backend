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

def test_send_email_success_with_moto(ses_client):
    service = EmailService(region_name="ap-southeast-2")
    service.send(
        to_address="recipient@example.com",
        subject="Test Moto Subject",
        body_html="<p>This is a moto test email</p>",
        sender="sender@example.com",
    )
    # If no exception, we assume success with moto

def test_send_email_failure_with_moto(ses_client):
    service = EmailService(region_name="ap-southeast-2")

    # Deliberately use an unverified sender to cause failure
    with pytest.raises(Exception):
        service.send(
            to_address="recipient@example.com",
            subject="Should Fail",
            body_html="<p>Should not send</p>",
            sender="unverified@example.com",
        )
