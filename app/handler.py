"""API Gateway Lambda handler — thin proxy to AgentCore Runtime.

Receives user messages via API Gateway, invokes the AgentCore Runtime agent,
and returns the response. Logs every invocation as structured JSON.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_client: Any = None


def _get_client() -> Any:
    global _client  # noqa: PLW0603
    if _client is None:
        _client = boto3.client(
            "bedrock-agentcore",
            region_name=os.environ.get("AWS_REGION", "us-east-1"),
        )
    return _client


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """API Gateway Lambda proxy handler → AgentCore Runtime."""
    runtime_arn = os.environ["AGENT_RUNTIME_ARN"]

    # Parse body
    body = event.get("body", "{}")
    if isinstance(body, str):
        body = json.loads(body)

    user_message: str = body.get("message", "")
    session_id: str = body.get("session_id", str(uuid.uuid4()))

    # AgentCore requires runtimeSessionId >= 33 chars
    if len(session_id) < 33:
        session_id = session_id + "-" + str(uuid.uuid4())

    if not user_message:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing 'message' in request body."}),
        }

    logger.info(json.dumps({
        "event": "api_invocation",
        "session_id": session_id,
        "user_message": user_message[:500],
    }))

    try:
        client = _get_client()
        payload = json.dumps({
            "prompt": user_message,
            "session_id": session_id,
        }).encode("utf-8")

        response = client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            qualifier="DEFAULT",
            payload=payload,
            runtimeSessionId=session_id,
        )

        # Read the response — field is 'response' (StreamingBody)
        result_bytes = b""
        resp_body = response.get("response", b"")
        if resp_body:
            if hasattr(resp_body, "read"):
                result_bytes = resp_body.read()
            elif isinstance(resp_body, bytes):
                result_bytes = resp_body
            elif isinstance(resp_body, str):
                result_bytes = resp_body.encode("utf-8")

        # Handle empty response (runtime may still be initializing)
        if not result_bytes:
            return {
                "statusCode": 502,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "error": "Empty response from AgentCore Runtime.",
                    "session_id": session_id,
                }),
            }

        # Try to parse as JSON; fall back to raw text
        try:
            result = json.loads(result_bytes)
        except json.JSONDecodeError:
            result = {"response": result_bytes.decode("utf-8", errors="replace")}

        logger.info(json.dumps({
            "event": "api_response",
            "session_id": session_id,
            "response_preview": str(result)[:500],
        }))

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result),
        }

    except Exception:
        logger.exception("AgentCore Runtime invocation failed")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Internal server error."}),
        }
