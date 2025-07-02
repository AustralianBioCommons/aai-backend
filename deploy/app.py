#!/usr/bin/env python3
import os

import aws_cdk as cdk
from aai_backend_deploy.aai_backend_deploy_stack import AaiBackendDeployStack
from dotenv import load_dotenv


def get_dotenv_config():
    load_dotenv()
    return {
        "AWS_CERTIFICATE_ARN": os.getenv("AWS_CERTIFICATE_ARN"),
        "AWS_ZONE_ID": os.getenv("AWS_ZONE_ID"),
        "AWS_ZONE_DOMAIN": os.getenv("AWS_ZONE_DOMAIN"),
        "AWS_DB_HOST": os.getenv("AWS_DB_HOST"),
        # Secret name for the secret storing DB username and password
        "AWS_DB_SECRET": os.getenv("AWS_DB_SECRET"),
    }

config = get_dotenv_config()
app = cdk.App()
AaiBackendDeployStack(app, "AaiBackendDeployStack", config=config,
    # If you don't specify 'env', this stack will be environment-agnostic.
    # Account/Region-dependent features and context lookups will not work,
    # but a single synthesized template can be deployed anywhere.

    # Uncomment the next line to specialize this stack for the AWS Account
    # and Region that are implied by the current CLI configuration.

    env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),

    # Uncomment the next line if you know exactly what Account and Region you
    # want to deploy the stack to. */

    #env=cdk.Environment(account='123456789012', region='us-east-1'),

    # For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
    )

app.synth()
