import logging

import boto3
from botocore.exceptions import ClientError

from biocommons.emails import get_default_sender_email

logger = logging.getLogger('uvicorn.error')


class EmailService:
    def __init__(self, region_name="ap-southeast-2"):
        self.client = boto3.client("ses", region_name=region_name)

    def send(self, to_address: str, subject: str, body_html: str):
        source = get_default_sender_email()
        logger.info(f"Sending email to {to_address} from {source}")
        try:
            response = self.client.send_email(
                Source=source,
                Destination={"ToAddresses": [to_address]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {"Html": {"Data": body_html}}
                }
            )
            logger.info(f"Email sent: {response['MessageId']}")
        except ClientError as e:
            logger.error(f"Failed to send email: {e.response['Error']['Message']}")
            logger.error(f"Response: {e.response}")
            raise


def get_email_service():
    return EmailService()
