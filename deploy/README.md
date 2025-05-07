# CDK Python Deployment

This CDK stack deploys the `aai-backend` service
to AWS. Note that it doesn't directly
use the code in the repo - it expects that
the code has been built as a container separately
and uploaded to the AWS ECR.