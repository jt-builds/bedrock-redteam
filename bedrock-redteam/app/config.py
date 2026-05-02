"""Centralised configuration loaded from environment variables.

Expected env vars (set by CDK stack outputs or .env):
- POLICY_BUCKET_NAME   – S3 bucket holding the returns-policy document
- POLICY_OBJECT_KEY    – S3 key for the returns-policy document
- GUARDRAIL_ID         – Bedrock Guardrail identifier
- GUARDRAIL_VERSION    – Bedrock Guardrail version
- AWS_REGION           – AWS region for all API calls
"""

from __future__ import annotations

import os

# S3 policy bucket
POLICY_BUCKET_NAME: str = os.environ.get("POLICY_BUCKET_NAME", "")
POLICY_OBJECT_KEY: str = os.environ.get("POLICY_OBJECT_KEY", "returns_policy.txt")

# Guardrail
GUARDRAIL_ID: str = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION: str = os.environ.get("GUARDRAIL_VERSION", "")

# Region
AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")
