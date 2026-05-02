"""CDK stack: AgentCore Runtime agent for AnyCompany customer support.

Creates:
- S3 asset for the agent code (zip uploaded by CDK)
- IAM execution role for AgentCore Runtime
- AgentCore Runtime (AWS::BedrockAgentCore::Runtime) with CodeConfiguration
- CloudWatch vended-log delivery (application logs + X-Ray traces)
- API Gateway REST API + Lambda proxy for HTTP access

No Docker, no ECR, no CodeBuild — uses AgentCore's direct code deployment.
"""

from __future__ import annotations

import pathlib

import aws_cdk as cdk
from aws_cdk import (
    aws_apigateway as apigw,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
)
from constructs import Construct

_APP_DIR = str(pathlib.Path(__file__).resolve().parent.parent / "app")


class AgentStack(cdk.Stack):
    """AgentCore Runtime stack with code-zip deploy, API Gateway, and logging."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        policy_bucket: s3.IBucket,
        policy_object_key: str,
        guardrail_id: str,
        guardrail_version: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── S3 asset: zip the app/ directory ──────────────────────────
        code_asset = s3_assets.Asset(
            self,
            "AgentCodeAsset",
            path=_APP_DIR,
        )

        # ── IAM: AgentCore execution role ─────────────────────────────
        agent_role = iam.Role(
            self,
            "AgentCoreExecRole",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": cdk.Aws.ACCOUNT_ID},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:bedrock-agentcore:{cdk.Aws.REGION}"
                            f":{cdk.Aws.ACCOUNT_ID}:*"
                        ),
                    },
                },
            ),
            description="Execution role for the AnyCompany AgentCore Runtime",
        )

        # Allow AgentCore to read the code asset from S3
        code_asset.grant_read(agent_role)

        # Bedrock model invocation (Strands → Converse API)
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockModelInvocation",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:GetInferenceProfile",
                    "bedrock:ListInferenceProfiles",
                ],
                resources=["*"],
            )
        )
        # Cross-region inference profiles require marketplace permissions
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="MarketplaceForInferenceProfiles",
                actions=[
                    "aws-marketplace:ViewSubscriptions",
                    "aws-marketplace:Subscribe",
                    "aws-marketplace:Unsubscribe",
                ],
                resources=["*"],
            )
        )
        # Bedrock Converse API
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockConverse",
                actions=[
                    "bedrock:Converse",
                    "bedrock:ConverseStream",
                ],
                resources=["*"],
            )
        )
        # Bedrock guardrail
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockGuardrail",
                actions=["bedrock:ApplyGuardrail"],
                resources=[
                    f"arn:aws:bedrock:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:guardrail/*",
                ],
            )
        )
        # S3 read for returns-policy document
        policy_bucket.grant_read(agent_role)
        # CloudWatch logs
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="CloudWatchLogs",
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents",
                ],
                resources=["*"],
            )
        )
        # X-Ray tracing
        agent_role.add_to_policy(
            iam.PolicyStatement(
                sid="XRayTracing",
                actions=[
                    "xray:PutTraceSegments",
                    "xray:PutTelemetryRecords",
                    "xray:GetSamplingRules",
                    "xray:GetSamplingTargets",
                ],
                resources=["*"],
            )
        )

        # ── AgentCore Runtime (L1 CloudFormation) ─────────────────────
        runtime = cdk.CfnResource(
            self,
            "AgentCoreRuntime",
            type="AWS::BedrockAgentCore::Runtime",
            properties={
                "AgentRuntimeName": "AnyCompanySupportAgent",
                "Description": (
                    "AnyCompany customer-support agent "
                    "(Strands + Claude Sonnet 4.6, code-zip deploy)"
                ),
                "RoleArn": agent_role.role_arn,
                "AgentRuntimeArtifact": {
                    "CodeConfiguration": {
                        "Code": {
                            "S3": {
                                "Bucket": code_asset.s3_bucket_name,
                                "Prefix": code_asset.s3_object_key,
                            },
                        },
                        "EntryPoint": ["main.py"],
                        "Runtime": "PYTHON_3_13",
                    },
                },
                "NetworkConfiguration": {
                    "NetworkMode": "PUBLIC",
                },
                "ProtocolConfiguration": "HTTP",
                "EnvironmentVariables": {
                    "POLICY_BUCKET_NAME": policy_bucket.bucket_name,
                    "POLICY_OBJECT_KEY": policy_object_key,
                    "GUARDRAIL_ID": guardrail_id,
                    "GUARDRAIL_VERSION": guardrail_version,
                },
            },
        )

        runtime_id = runtime.get_att("AgentRuntimeId").to_string()
        runtime_arn = runtime.get_att("AgentRuntimeArn").to_string()

        # ── CloudWatch vended-log delivery ────────────────────────────
        log_group = logs.LogGroup(
            self,
            "AgentCoreLogGroup",
            log_group_name=cdk.Fn.join("", [
                "/aws/vendedlogs/bedrock-agentcore/", runtime_id,
            ]),
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # Application logs: source → destination → delivery
        log_source = cdk.CfnResource(
            self, "LogDeliverySource",
            type="AWS::Logs::DeliverySource",
            properties={
                "Name": cdk.Fn.join("-", [runtime_id, "logs-source"]),
                "LogType": "APPLICATION_LOGS",
                "ResourceArn": runtime_arn,
            },
        )
        log_source.node.add_dependency(runtime)

        log_dest = cdk.CfnResource(
            self, "LogDeliveryDest",
            type="AWS::Logs::DeliveryDestination",
            properties={
                "Name": cdk.Fn.join("-", [runtime_id, "logs-dest"]),
                "DeliveryDestinationType": "CWL",
                "DestinationResourceArn": log_group.log_group_arn,
            },
        )

        log_delivery = cdk.CfnResource(
            self, "LogDelivery",
            type="AWS::Logs::Delivery",
            properties={
                "DeliverySourceName": cdk.Fn.join("-", [runtime_id, "logs-source"]),
                "DeliveryDestinationArn": log_dest.get_att("Arn").to_string(),
            },
        )
        log_delivery.add_dependency(log_source)
        log_delivery.add_dependency(log_dest)

        # X-Ray traces: configured post-deploy via UpdateTraceSegmentDestination API
        # (omitted from CDK — requires CloudWatch Logs trace segment destination enabled first)

        # ── API Gateway + Lambda proxy ────────────────────────────────
        api_log_group = logs.LogGroup(
            self,
            "ApiLogGroup",
            log_group_name="/anycompany/api-handler",
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        handler_fn = lambda_.Function(
            self,
            "ApiHandlerFn",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset(_APP_DIR),
            timeout=cdk.Duration.seconds(120),
            memory_size=256,
            log_group=api_log_group,
            environment={
                "AGENT_RUNTIME_ARN": runtime_arn,
            },
        )
        handler_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=[runtime_arn, f"{runtime_arn}/*"],
            )
        )

        api = apigw.RestApi(
            self,
            "AgentApi",
            rest_api_name="AnyCompanySupportApi",
            description="REST API for the AnyCompany AgentCore customer-support agent",
            deploy_options=apigw.StageOptions(stage_name="prod"),
        )
        chat_resource = api.root.add_resource("chat")
        chat_resource.add_method("POST", apigw.LambdaIntegration(handler_fn))

        # ── Outputs ───────────────────────────────────────────────────
        cdk.CfnOutput(self, "AgentRuntimeId", value=runtime_id)
        cdk.CfnOutput(self, "AgentRuntimeArn", value=runtime_arn)
        cdk.CfnOutput(self, "ApiEndpoint", value=api.url)
        cdk.CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
