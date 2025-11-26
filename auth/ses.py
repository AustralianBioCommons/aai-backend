import logging

import os

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from config import get_settings

logger = logging.getLogger(__name__)

DEFAULT_EMAIL_SENDER_FALLBACK = "amanda@biocommons.org.au"


def _default_sender() -> str:
    try:
        return get_settings().default_email_sender
    except ValidationError:
        return os.environ.get("DEFAULT_EMAIL_SENDER", DEFAULT_EMAIL_SENDER_FALLBACK)


class EmailService:
    def __init__(self, region_name="ap-southeast-2"):
        self.client = boto3.client("ses", region_name=region_name)

    def send(self, to_address: str, subject: str, body_html: str, sender: str | None = None):
        sender = sender or _default_sender()
        try:
            response = self.client.send_email(
                Source=sender,
                Destination={"ToAddresses": [to_address]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {"Html": {"Data": body_html}}
                }
            )
            logger.info(f"Email sent: {response['MessageId']}")
        except ClientError as e:
            logger.error(f"Failed to send email: {e.response['Error']['Message']}")
            raise


def get_email_service():
    return EmailService()
