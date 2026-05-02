"""AgentCore Runtime entrypoint for the AnyCompany customer-support agent.

This module runs INSIDE an AgentCore Runtime microVM. Heavy imports
(strands, boto3) are deferred to first invocation so the entrypoint
registers within the 30s init window.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid

# Add vendored dependencies to path
_vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
if os.path.isdir(_vendor):
    sys.path.insert(0, _vendor)

from bedrock_agentcore.runtime import BedrockAgentCoreApp

# ---------------------------------------------------------------------------
# Logging — structured JSON to stdout → CloudWatch
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("anycompany.agent")

# ---------------------------------------------------------------------------
# AgentCore app — must register entrypoint quickly
# ---------------------------------------------------------------------------
app = BedrockAgentCoreApp()

# Agent is built lazily on first invocation
_agent = None


def _get_agent():
    """Build the Strands Agent on first call (lazy import)."""
    global _agent
    if _agent is not None:
        return _agent

    # Heavy imports deferred to here
    from strands import Agent
    from strands.models import BedrockModel
    from prompts import MODEL_ID, SYSTEM_PROMPT
    from tools import order_lookup, returns_policy_lookup, shipping_status

    guardrail_id = os.environ.get("GUARDRAIL_ID", "")
    guardrail_version = os.environ.get("GUARDRAIL_VERSION", "")

    bedrock_model = BedrockModel(
        model_id=MODEL_ID,
        guardrail_config=(
            {
                "guardrailIdentifier": guardrail_id,
                "guardrailVersion": guardrail_version,
                "trace": "enabled",
            }
            if guardrail_id and guardrail_version
            else None
        ),
    )

    _agent = Agent(
        model=bedrock_model,
        system_prompt=SYSTEM_PROMPT,
        tools=[order_lookup, shipping_status, returns_policy_lookup],
    )
    return _agent


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

@app.entrypoint
def invoke(payload: dict, context: object = None) -> dict:
    """Handle an agent invocation from AgentCore Runtime."""
    user_message: str = payload.get("prompt", "")
    session_id: str = payload.get("session_id", str(uuid.uuid4()))

    logger.info(json.dumps({
        "event": "agent_invocation",
        "session_id": session_id,
        "user_message": user_message[:500],
    }))

    if not user_message:
        return {"error": "Missing 'prompt' in request body."}

    try:
        os.environ["BYPASS_TOOL_CONSENT"] = "true"
        agent = _get_agent()
        result = agent(user_message)

        # Extract text from the result
        response_text = ""
        if hasattr(result, "message"):
            msg = result.message
            if isinstance(msg, dict):
                for block in msg.get("content", []):
                    if isinstance(block, dict) and "text" in block:
                        response_text += block["text"]
            elif isinstance(msg, str):
                response_text = msg
        else:
            response_text = str(result)

        logger.info(json.dumps({
            "event": "agent_response",
            "session_id": session_id,
            "response_text": response_text[:500],
        }))

        return {
            "session_id": session_id,
            "response": response_text,
        }

    except Exception as e:
        logger.exception("Agent invocation failed")
        error_str = str(e)
        if "guardrail" in error_str.lower() or "blocked" in error_str.lower():
            logger.info(json.dumps({
                "event": "guardrail_intervention",
                "session_id": session_id,
                "detail": error_str[:500],
            }))
            return {
                "session_id": session_id,
                "response": "Sorry, I can't process that request. Please rephrase.",
                "guardrail_blocked": True,
            }

        return {"session_id": session_id, "error": "Internal server error."}


if __name__ == "__main__":
    app.run()
