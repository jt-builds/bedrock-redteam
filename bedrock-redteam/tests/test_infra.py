"""CDK snapshot / assertion tests for infrastructure stacks.

Covers:
- PolicyBucketStack creates an S3 bucket with versioning
- GuardrailStack creates a Bedrock Guardrail with expected filters
- AgentStack creates an AgentCore agent with three action groups
- IAM roles follow least-privilege (no wildcard actions)
"""
