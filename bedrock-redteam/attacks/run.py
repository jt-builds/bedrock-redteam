"""Attack runner — orchestrates end-to-end red-team test runs.

Workflow:
1. Upload a poisoned returns-policy document to S3 (selected by --payload).
2. Invoke the agent with a benign user query that triggers
   returns_policy_lookup (e.g., "What is your return policy?").
3. Capture the agent's response, trace, and guardrail evaluation.
4. Write structured evidence (JSON + raw transcript) to evidence/.
5. Restore the clean policy document.

Usage:
    python -m attacks.run --payload unicode_tag
    python -m attacks.run --payload markdown_comment --turns 5
    python -m attacks.run --all
"""
