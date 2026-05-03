"""CDK stack: Observability — alarms, dashboard, SNS alerts, API rate limiting.

Creates:
- SNS topic + email subscription for cost/spend alerts
- CloudWatch Alarm on estimated charges for Bedrock + AgentCore (>$50/24h)
- API Gateway usage plan with 10 req/sec throttle
- CloudWatch Dashboard: invocation count, latency, error rate for both
  the AgentCore Runtime and Bedrock model calls
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_apigateway as apigw,
    aws_cloudwatch as cw,
    aws_cloudwatch_actions as cw_actions,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
)
from constructs import Construct


class ObservabilityStack(cdk.Stack):
    """Alarms, dashboard, SNS alerts, and API Gateway rate limiting."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api: apigw.RestApi,
        api_stage: str,
        handler_fn: lambda_.IFunction,
        agent_runtime_id: str,
        log_group: logs.ILogGroup,
        alert_email: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ==================================================================
        # 1. SNS Topic + Email Subscription
        # ==================================================================
        alert_topic = sns.Topic(
            self,
            "SpendAlertTopic",
            display_name="Bedrock RedTeam Spend Alerts",
            topic_name="bedrock-redteam-spend-alerts",
        )
        alert_topic.add_subscription(subs.EmailSubscription(alert_email))

        # ==================================================================
        # 2. Cost Alarms — Bedrock Invocation + AgentCore Runtime
        # ==================================================================
        # AWS exposes estimated charges via the AWS/Billing namespace.
        # These metrics require "Receive Billing Alerts" enabled in the
        # Billing console and only appear in us-east-1.
        #
        # Alarm: total estimated charges > $50 (evaluated over 24h / 1-day)
        # We create two alarms: one for Bedrock, one for AgentCore.

        bedrock_cost_alarm = cw.Alarm(
            self,
            "BedrockCostAlarm",
            alarm_name="BedrockInvocationCost-Exceeds-50USD",
            alarm_description=(
                "Fires when estimated Bedrock charges exceed $50 in a 24-hour window."
            ),
            metric=cw.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "ServiceName": "Amazon Bedrock",
                    "Currency": "USD",
                },
                statistic="Maximum",
                period=cdk.Duration.hours(24),
            ),
            threshold=50,
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
        )
        bedrock_cost_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))

        agentcore_cost_alarm = cw.Alarm(
            self,
            "AgentCoreCostAlarm",
            alarm_name="AgentCoreRuntimeCost-Exceeds-50USD",
            alarm_description=(
                "Fires when estimated AgentCore Runtime charges exceed $50 "
                "in a 24-hour window."
            ),
            metric=cw.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "Currency": "USD",
                },
                statistic="Maximum",
                period=cdk.Duration.hours(24),
            ),
            threshold=50,
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
        )
        agentcore_cost_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))

        # ==================================================================
        # 3. API Gateway Usage Plan — 10 req/sec throttle
        # ==================================================================
        # Create an API key and usage plan to enforce rate limiting.
        api_key = api.add_api_key(
            "RedTeamApiKey",
            api_key_name="redteam-api-key",
            description="API key for rate-limited access to the support agent",
        )

        usage_plan = api.add_usage_plan(
            "RedTeamUsagePlan",
            name="RedTeamUsagePlan",
            description="10 req/sec throttle for the AnyCompany support API",
            throttle=apigw.ThrottleSettings(
                rate_limit=10,     # 10 requests per second
                burst_limit=20,    # burst up to 20
            ),
            quota=apigw.QuotaSettings(
                limit=50000,                          # 50k requests per month
                period=apigw.Period.MONTH,
            ),
        )
        usage_plan.add_api_key(api_key)
        usage_plan.add_api_stage(
            stage=api.deployment_stage,
        )

        # ==================================================================
        # 4. CloudWatch Dashboard
        # ==================================================================
        dashboard = cw.Dashboard(
            self,
            "RedTeamDashboard",
            dashboard_name="BedrockRedTeam-AgentObservability",
            default_interval=cdk.Duration.hours(6),
        )

        # ── Row 1: API Gateway metrics ────────────────────────────────
        api_name = api.rest_api_name

        apigw_invocations = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="Count",
            dimensions_map={"ApiName": api_name, "Stage": api_stage},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="API Invocations",
        )
        apigw_latency = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="Latency",
            dimensions_map={"ApiName": api_name, "Stage": api_stage},
            statistic="Average",
            period=cdk.Duration.minutes(5),
            label="API Latency (avg ms)",
        )
        apigw_4xx = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="4XXError",
            dimensions_map={"ApiName": api_name, "Stage": api_stage},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="4XX Errors",
        )
        apigw_5xx = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="5XXError",
            dimensions_map={"ApiName": api_name, "Stage": api_stage},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="5XX Errors",
        )

        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# API Gateway",
                width=24,
                height=1,
            ),
        )
        dashboard.add_widgets(
            cw.GraphWidget(
                title="API Invocation Count",
                left=[apigw_invocations],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="API Latency (ms)",
                left=[apigw_latency],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="API Error Rate",
                left=[apigw_4xx, apigw_5xx],
                width=8,
                height=6,
            ),
        )

        # ── Row 2: Lambda proxy metrics ───────────────────────────────
        fn_name = handler_fn.function_name

        lambda_invocations = cw.Metric(
            namespace="AWS/Lambda",
            metric_name="Invocations",
            dimensions_map={"FunctionName": fn_name},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Lambda Invocations",
        )
        lambda_duration = cw.Metric(
            namespace="AWS/Lambda",
            metric_name="Duration",
            dimensions_map={"FunctionName": fn_name},
            statistic="Average",
            period=cdk.Duration.minutes(5),
            label="Lambda Duration (avg ms)",
        )
        lambda_errors = cw.Metric(
            namespace="AWS/Lambda",
            metric_name="Errors",
            dimensions_map={"FunctionName": fn_name},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Lambda Errors",
        )
        lambda_throttles = cw.Metric(
            namespace="AWS/Lambda",
            metric_name="Throttles",
            dimensions_map={"FunctionName": fn_name},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Lambda Throttles",
        )

        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# Lambda Proxy (AgentCore Invoker)",
                width=24,
                height=1,
            ),
        )
        dashboard.add_widgets(
            cw.GraphWidget(
                title="Lambda Invocations",
                left=[lambda_invocations],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="Lambda Duration (ms)",
                left=[lambda_duration],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="Lambda Errors & Throttles",
                left=[lambda_errors, lambda_throttles],
                width=8,
                height=6,
            ),
        )

        # ── Row 3: Bedrock Model Invocation metrics ───────────────────
        # AWS/Bedrock namespace publishes per-model metrics.
        # We use a wildcard-style approach with a math expression to
        # capture all model IDs, but also show the primary model.
        bedrock_invocations = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="Invocations",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Bedrock Invocations (all models)",
        )
        bedrock_latency = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="InvocationLatency",
            statistic="Average",
            period=cdk.Duration.minutes(5),
            label="Bedrock Latency (avg ms)",
        )
        bedrock_errors = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="InvocationClientErrors",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Bedrock Client Errors",
        )
        bedrock_server_errors = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="InvocationServerErrors",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Bedrock Server Errors",
        )
        bedrock_throttles = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="InvocationThrottles",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Bedrock Throttles",
        )
        bedrock_input_tokens = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="InputTokenCount",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Input Tokens",
        )
        bedrock_output_tokens = cw.Metric(
            namespace="AWS/Bedrock",
            metric_name="OutputTokenCount",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="Output Tokens",
        )

        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# Bedrock Model Invocations",
                width=24,
                height=1,
            ),
        )
        dashboard.add_widgets(
            cw.GraphWidget(
                title="Bedrock Invocation Count",
                left=[bedrock_invocations],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="Bedrock Invocation Latency (ms)",
                left=[bedrock_latency],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="Bedrock Errors & Throttles",
                left=[bedrock_errors, bedrock_server_errors, bedrock_throttles],
                width=8,
                height=6,
            ),
        )
        dashboard.add_widgets(
            cw.GraphWidget(
                title="Bedrock Token Usage",
                left=[bedrock_input_tokens, bedrock_output_tokens],
                width=12,
                height=6,
            ),
            cw.SingleValueWidget(
                title="Bedrock Invocations (last 6h)",
                metrics=[bedrock_invocations],
                width=6,
                height=6,
            ),
            cw.SingleValueWidget(
                title="Bedrock Avg Latency (last 6h)",
                metrics=[bedrock_latency],
                width=6,
                height=6,
            ),
        )

        # ── Row 4: AgentCore Runtime metrics (from vended logs) ───────
        # AgentCore publishes metrics under AWS/BedrockAgentCore.
        agentcore_invocations = cw.Metric(
            namespace="AWS/BedrockAgentCore",
            metric_name="Invocations",
            dimensions_map={"AgentRuntimeId": agent_runtime_id},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="AgentCore Invocations",
        )
        agentcore_latency = cw.Metric(
            namespace="AWS/BedrockAgentCore",
            metric_name="InvocationLatency",
            dimensions_map={"AgentRuntimeId": agent_runtime_id},
            statistic="Average",
            period=cdk.Duration.minutes(5),
            label="AgentCore Latency (avg ms)",
        )
        agentcore_errors = cw.Metric(
            namespace="AWS/BedrockAgentCore",
            metric_name="InvocationErrors",
            dimensions_map={"AgentRuntimeId": agent_runtime_id},
            statistic="Sum",
            period=cdk.Duration.minutes(5),
            label="AgentCore Errors",
        )

        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# AgentCore Runtime",
                width=24,
                height=1,
            ),
        )
        dashboard.add_widgets(
            cw.GraphWidget(
                title="AgentCore Invocation Count",
                left=[agentcore_invocations],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="AgentCore Invocation Latency (ms)",
                left=[agentcore_latency],
                width=8,
                height=6,
            ),
            cw.GraphWidget(
                title="AgentCore Errors",
                left=[agentcore_errors],
                width=8,
                height=6,
            ),
        )

        # ── Row 5: Cost tracking ─────────────────────────────────────
        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# Cost Tracking (requires Billing Alerts enabled in us-east-1)",
                width=24,
                height=1,
            ),
        )
        dashboard.add_widgets(
            cw.SingleValueWidget(
                title="Bedrock Estimated Charges (USD)",
                metrics=[
                    cw.Metric(
                        namespace="AWS/Billing",
                        metric_name="EstimatedCharges",
                        dimensions_map={
                            "ServiceName": "Amazon Bedrock",
                            "Currency": "USD",
                        },
                        statistic="Maximum",
                        period=cdk.Duration.hours(6),
                    ),
                ],
                width=12,
                height=4,
            ),
            cw.SingleValueWidget(
                title="AgentCore Estimated Charges (USD)",
                metrics=[
                    cw.Metric(
                        namespace="AWS/Billing",
                        metric_name="EstimatedCharges",
                        dimensions_map={
                            "ServiceName": "Amazon Bedrock AgentCore",
                            "Currency": "USD",
                        },
                        statistic="Maximum",
                        period=cdk.Duration.hours(6),
                    ),
                ],
                width=12,
                height=4,
            ),
        )

        # ── Alarm status widget ───────────────────────────────────────
        dashboard.add_widgets(
            cw.AlarmStatusWidget(
                title="Spend Alarm Status",
                alarms=[bedrock_cost_alarm, agentcore_cost_alarm],
                width=24,
                height=3,
            ),
        )

        # ── Outputs ───────────────────────────────────────────────────
        cdk.CfnOutput(self, "AlertTopicArn", value=alert_topic.topic_arn)
        cdk.CfnOutput(self, "DashboardName", value=dashboard.dashboard_name)
        cdk.CfnOutput(self, "ApiKeyId", value=api_key.key_id)
        cdk.CfnOutput(
            self,
            "DashboardUrl",
            value=cdk.Fn.join("", [
                "https://",
                cdk.Aws.REGION,
                ".console.aws.amazon.com/cloudwatch/home?region=",
                cdk.Aws.REGION,
                "#dashboards:name=",
                dashboard.dashboard_name,
            ]),
        )
