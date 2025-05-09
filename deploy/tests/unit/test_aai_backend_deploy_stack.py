import aws_cdk as core
import aws_cdk.assertions as assertions
from aai_backend_deploy.aai_backend_deploy_stack import AaiBackendDeployStack


# example tests. To run these tests, uncomment this file along with the example
# resource in aai_backend_deploy/aai_backend_deploy_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AaiBackendDeployStack(app, "aai-backend-deploy")
    template = assertions.Template.from_stack(stack)
