import logging

import boto3
from botocore.exceptions import ClientError

from biocommons.emails import get_default_sender_email
from config import Settings

logger = logging.getLogger('uvicorn.error')


class EmailService:
    def __init__(self, region_name="ap-southeast-2"):
        self.client = boto3.client("ses", region_name=region_name)

    def send(self, to_address: str, subject: str, body_html: str, settings: Settings):
        source = get_default_sender_email(settings=settings)
        logger.info(f"Sending email to {to_address} from {source}")
        try:
            send_email_kwargs = {
                "Source": source,
                "Destination": {"ToAddresses": [to_address]},
                "Message": {
                    "Subject": {"Data": subject},
                    "Body": {"Html": {"Data": body_html}}
                }
            }
            if settings.ses_resource_arn is not None:
                send_email_kwargs["SourceArn"] = settings.ses_resource_arn
                logger.info(f"Using SES resource ARN: {settings.ses_resource_arn}")
            response = self.client.send_email(**send_email_kwargs)
            logger.info(f"Email sent: {response['MessageId']}")
        except ClientError as e:
            logger.error(f"Failed to send email: {e.response['Error']['Message']}")
            logger.error(f"Response: {e.response}")
            raise


def get_email_service():
    return EmailService()
