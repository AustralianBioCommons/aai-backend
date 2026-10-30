import logging

import boto3
from botocore.exceptions import ClientError

from biocommons.emails import compose_email_change_otp_email, get_default_sender_email
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
            logger.error(f"From address: {send_email_kwargs['FromEmailAddress']}")
            logger.error(f"Identity ARN: {send_email_kwargs.get('FromEmailAddressIdentityArn', 'None')}")
            raise

    def send_email_change_otp(self, code: str, target_email: str, expiration_minutes: int, settings: Settings):
        subject, body_html = compose_email_change_otp_email(
            code=code,
            target_email=target_email,
            expiration_minutes=expiration_minutes,
            portal_url=settings.aai_portal_url or "",
        )
        try:
            self.send(
                to_address=target_email,
                subject=subject,
                body_html=body_html,
                settings=settings,
            )
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or str(exc)
            logger.error("Failed to send OTP email via SES: {}", message)
            raise




def get_email_service():
    return EmailService()
