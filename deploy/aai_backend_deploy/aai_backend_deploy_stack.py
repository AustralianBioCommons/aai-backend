import datetime

from aws_cdk import (
    CfnOutput,
    Stack,
)
from aws_cdk import (
    aws_certificatemanager as acm,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_ecr as ecr,
)
from aws_cdk import (
    aws_ecs as ecs,
)
from aws_cdk import (
    aws_ecs_patterns as ecs_patterns,
)
from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)
from aws_cdk import aws_iam as iam
from aws_cdk import (
    aws_route53 as route53,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class AaiBackendDeployStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, config: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        try:
            self.certificate_arn = config["AWS_CERTIFICATE_ARN"]
            self.zone_id = config["AWS_ZONE_ID"]
            self.zone_domain = config["AWS_ZONE_DOMAIN"]
            self.db_host = config["AWS_DB_HOST"]
            self.db_secret = config["AWS_DB_SECRET"]
        except KeyError as e:
            raise ValueError(f"Missing required configuration: {e}. These should be set in .env locally, or GitHub Secrets.")

        db_secret = secretsmanager.Secret.from_secret_name_v2(
            self, "DbCredentials", secret_name=self.db_secret
        )

        # VPC
        vpc = ec2.Vpc(self, "AaiBackendVPC", max_azs=2)

        # ECS Cluster
        cluster = ecs.Cluster(self, "AaiBackendCluster", vpc=vpc)

        # Reference the existing ECR repository
        ecr_repo = ecr.Repository.from_repository_name(self, "AaiBackendRepo", "aai-backend")

        # Task definition for Fargate
        task_definition = ecs.FargateTaskDefinition(self, "AaiBackendTaskDef",
                                                    memory_limit_mib=1024,
                                                    cpu=512)
        # Allow executing comands in the ECS container
        task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
        )

        container = task_definition.add_container(
            "FastAPIContainer",
            image=ecs.ContainerImage.from_ecr_repository(
                ecr_repo,
                tag="latest"
            ),
            # Set an env variable to the current time to force redeploy -
            #   might be better to use an image tag in future
            environment={
                "FORCE_REDEPLOY": str(datetime.datetime.now()),
                "DB_HOST": self.db_host,
            },
            secrets={
                "DB_USER": ecs.Secret.from_secrets_manager(db_secret, field="username"),
                "DB_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, field="password"),
            },
            logging=ecs.LogDrivers.aws_logs(stream_prefix="FastAPI"),
        )

        container.add_port_mappings(
            ecs.PortMapping(container_port=8000)
        )

        # HTTPS Certificate
        certificate = acm.Certificate.from_certificate_arn(self, "BackendCert", self.certificate_arn)

        # Create ALB + Fargate Service
        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, "AaiBackendService",
            cluster=cluster,
            task_definition=task_definition,
            public_load_balancer=True,
            listener_port=443,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            certificate=certificate,
            redirect_http=True,
            domain_name="aaibackend." + self.zone_domain,
            domain_zone=route53.HostedZone.from_lookup(
                self, "AaiBackendZone", domain_name=self.zone_domain
            ),
            enable_execute_command=True
        )

        service.target_group.configure_health_check(path="/", healthy_http_codes="200-399")

        CfnOutput(self, "LoadBalancerDNS", value=service.load_balancer.load_balancer_dns_name)
