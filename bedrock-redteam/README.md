# bedrock-redteam

AI security red-team experiment focused on **indirect prompt injection** in
Amazon Bedrock AgentCore.

## Scenario

**Target:** A customer-support chatbot for *AnyCompany*, a fictional SMB
office-supplies retailer.

**Model:** Claude Sonnet 4.6 on Amazon Bedrock, protected by a Bedrock
Guardrail.

**Agent runtime:** Amazon Bedrock AgentCore with three tools:

| Tool | Purpose |
|------|---------|
| `order_lookup` | Retrieve order details by order ID |
| `shipping_status` | Check shipping / tracking info for an order |
| `returns_policy_lookup` | Fetch the returns policy document from S3 |

**Attack surface:** The S3 object backing `returns_policy_lookup`. We poison
that document with indirect prompt-injection payloads and observe whether the
agent follows the injected instructions.

## Project layout

```
bedrock-redteam/
├── infra/          # CDK (Python) stacks – agent, guardrail, S3, IAM
├── app/            # Agent application code (tools, handler, prompts)
├── guardrails/     # Bedrock Guardrail configuration & test fixtures
├── attacks/        # Poisoned policy documents & injection payloads
├── evidence/       # Captured logs, screenshots, traces from test runs
├── tests/          # Unit & integration tests
└── pyproject.toml  # Python project metadata & dependencies
```

## Prerequisites

- Python ≥ 3.11
- AWS CDK v2 CLI (`npm install -g aws-cdk`)
- AWS credentials with permissions for Bedrock, S3, IAM, and AgentCore
- `uv` or `pip` for dependency management

## Quick start

```bash
# Install dependencies
uv sync            # or: pip install -e ".[dev]"

# Deploy infrastructure
cd infra && cdk deploy --all

# Upload a clean (benign) returns policy
python -m app.seed_policy --variant clean

# Run the agent locally
python -m app.handler

# Execute an attack
python -m attacks.run --payload unicode_tag
```

## Responsible use

This project is for **authorized security testing only**. All attacks target
infrastructure you own. Do not use these techniques against systems you do not
have explicit permission to test.
