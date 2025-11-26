import logging

import boto3
from botocore.exceptions import ClientError

from email_settings import DEFAULT_EMAIL_SENDER

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self, region_name="ap-southeast-2"):
        self.client = boto3.client("ses", region_name=region_name)

    def send(self, to_address: str, subject: str, body_html: str, sender: str = DEFAULT_EMAIL_SENDER):
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
