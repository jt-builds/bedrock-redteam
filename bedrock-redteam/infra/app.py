"""CDK app entry point.

Instantiates and synthesizes all stacks:
- PolicyBucketStack  – S3 bucket for the returns-policy document (seeded)
- GuardrailStack     – Bedrock Guardrail configuration
- AgentStack         – AgentCore Runtime, ECR, CodeBuild, API Gateway, CloudWatch
"""

from __future__ import annotations

import os
import sys

# Ensure the project root is on sys.path so `infra.*` and `guardrails.*` resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_cdk as cdk

from infra.agent_stack import AgentStack
from infra.guardrail_stack import GuardrailStack
from infra.policy_bucket_stack import PolicyBucketStack

app = cdk.App()

# 1. S3 bucket with the clean returns-policy document
policy_bucket_stack = PolicyBucketStack(app, "PolicyBucketStack")

# 2. Bedrock Guardrail (content, topic, PII, word filters)
guardrail_stack = GuardrailStack(app, "GuardrailStack")

# 3. AgentCore Runtime + API Gateway + CloudWatch
agent_stack = AgentStack(
    app,
    "AgentStack",
    policy_bucket=policy_bucket_stack.bucket,
    policy_object_key=policy_bucket_stack.policy_object_key,
    guardrail_id=guardrail_stack.guardrail_id,
    guardrail_version=guardrail_stack.guardrail_version,
)
agent_stack.add_dependency(policy_bucket_stack)
agent_stack.add_dependency(guardrail_stack)

app.synth()
