import logging

import boto3
from botocore.exceptions import ClientError

from biocommons.emails import get_default_sender_email
from config import Settings

logger = logging.getLogger('uvicorn.error')


class EmailService:
    def __init__(self, region_name="ap-southeast-2"):
        self.client = boto3.client("sesv2", region_name=region_name)

    def send(self, to_address: str, subject: str, body_html: str, settings: Settings):
        source = get_default_sender_email(settings=settings)
        send_email_kwargs = None
        try:
            send_email_kwargs = {
                "FromEmailAddress": source,
                "Destination": {"ToAddresses": [to_address]},
                "Content": {
                    "Simple": {
                        "Subject": {"Data": subject, "Charset": "UTF-8"},
                        "Body": {"Html": {"Data": body_html, "Charset": "UTF-8"}}
                    }
                }
            }
            if settings.ses_resource_arn is not None:
                send_email_kwargs["FromEmailAddressIdentityArn"] = settings.ses_resource_arn
            response = self.client.send_email(**send_email_kwargs)
            logger.info(f"Email sent from {source}: {response['MessageId']}")
        except ClientError as e:
            logger.error(f"Failed to send email: {e.response}")
            logger.error(f"send_email arguments: {send_email_kwargs}")
            raise


def get_email_service():
    return EmailService()
