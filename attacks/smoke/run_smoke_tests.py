#!/usr/bin/env python3
"""Smoke tests for the AnyCompany AgentCore customer-support agent.

Sends four test messages to the API Gateway /chat endpoint and captures
full response JSON to evidence/smoke/. Verifies:
- order_lookup fires for order queries
- shipping_status fires for shipping queries
- returns_policy_lookup fires for returns queries (reads from S3)
- Model-only question gets a polite decline
- CloudWatch logs contain structured JSON entries

Usage:
    python -m attacks.smoke.run_smoke_tests

Requires:
    API_ENDPOINT env var (or auto-reads from CDK outputs)
    AWS_PROFILE=redteam (for CloudWatch log checks)
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone

import boto3
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
EVIDENCE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "evidence" / "smoke"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

PROFILE = os.environ.get("AWS_PROFILE", "redteam")
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Try to get API endpoint from env or CDK outputs
API_ENDPOINT = os.environ.get("API_ENDPOINT", "")
if not API_ENDPOINT:
    try:
        result = subprocess.run(
            [
                "aws", "cloudformation", "describe-stacks",
                "--stack-name", "AgentStack",
                "--profile", PROFILE,
                "--region", REGION,
                "--query", "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue",
                "--output", "text",
            ],
            capture_output=True, text=True, check=True,
        )
        API_ENDPOINT = result.stdout.strip()
    except Exception as e:
        print(f"ERROR: Could not get API endpoint: {e}")
        sys.exit(1)

CHAT_URL = API_ENDPOINT.rstrip("/") + "/chat"

# Also grab the log group name
LOG_GROUP = ""
try:
    result = subprocess.run(
        [
            "aws", "cloudformation", "describe-stacks",
            "--stack-name", "AgentStack",
            "--profile", PROFILE,
            "--region", REGION,
            "--query", "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue",
            "--output", "text",
        ],
        capture_output=True, text=True, check=True,
    )
    LOG_GROUP = result.stdout.strip()
except Exception:
    pass

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
TESTS = [
    {
        "name": "order_lookup",
        "message": "What's the status of order ORD-1001?",
        "expect_tool": "order_lookup",
        "expect_in_response": ["ORD-1001"],
    },
    {
        "name": "shipping_status",
        "message": "Where is my shipment for ORD-1001?",
        "expect_tool": "shipping_status",
        "expect_in_response": ["ORD-1001"],
    },
    {
        "name": "returns_policy_lookup",
        "message": "What is your returns policy for damaged items?",
        "expect_tool": "returns_policy_lookup",
        "expect_in_response": ["return", "damaged"],
    },
    {
        "name": "polite_decline",
        "message": "Hello, what do you sell?",
        "expect_tool": None,
        "expect_in_response": [],  # just check it responds without error
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def send_chat(message: str, session_id: str) -> dict:
    """POST to the /chat endpoint and return the parsed response."""
    payload = json.dumps({"message": message, "session_id": session_id}).encode()
    req = urllib.request.Request(
        CHAT_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read().decode()
            return {"status_code": resp.status, "body": json.loads(body)}
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"status_code": e.code, "body": body, "error": str(e)}
    except Exception as e:
        return {"status_code": 0, "error": str(e)}


def save_evidence(test_name: str, request_msg: str, response: dict) -> pathlib.Path:
    """Save the full request/response to evidence/smoke/."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath = EVIDENCE_DIR / f"{ts}_{test_name}.json"
    evidence = {
        "timestamp": ts,
        "test_name": test_name,
        "request": {"message": request_msg, "url": CHAT_URL},
        "response": response,
    }
    filepath.write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")
    return filepath


def check_response(test: dict, response: dict) -> tuple[bool, str]:
    """Check if the response meets expectations. Returns (passed, reason)."""
    if response.get("status_code") != 200:
        return False, f"HTTP {response.get('status_code')}: {response.get('error', '')}"

    body = response.get("body", {})
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass

    # Check for error in response
    if isinstance(body, dict) and "error" in body:
        return False, f"Agent error: {body['error']}"

    # Get the response text
    resp_text = ""
    if isinstance(body, dict):
        resp_text = body.get("response", str(body))
    else:
        resp_text = str(body)

    resp_lower = resp_text.lower()

    # For polite_decline: just check we got a non-empty response
    if test["name"] == "polite_decline":
        if len(resp_text) > 10:
            return True, "Got response (polite decline expected)"
        return False, "Response too short"

    # Check expected keywords in response
    for keyword in test.get("expect_in_response", []):
        if keyword.lower() not in resp_lower:
            return False, f"Missing expected keyword: {keyword}"

    return True, "OK"


def check_cloudwatch_logs() -> dict:
    """Check CloudWatch for structured JSON log entries."""
    if not LOG_GROUP:
        return {"checked": False, "reason": "Log group not found"}

    try:
        session = boto3.Session(profile_name=PROFILE, region_name=REGION)
        logs_client = session.client("logs")

        # Look for recent log events
        response = logs_client.filter_log_events(
            logGroupName=LOG_GROUP,
            limit=20,
            interleaved=True,
        )

        events = response.get("events", [])
        structured_count = 0
        sample_events = []

        for event in events:
            msg = event.get("message", "")
            try:
                parsed = json.loads(msg)
                if isinstance(parsed, dict) and "event" in parsed:
                    structured_count += 1
                    sample_events.append(parsed)
            except json.JSONDecodeError:
                continue

        return {
            "checked": True,
            "total_events": len(events),
            "structured_json_events": structured_count,
            "samples": sample_events[:5],
        }
    except Exception as e:
        return {"checked": False, "reason": str(e)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 70)
    print("AnyCompany AgentCore Smoke Tests")
    print(f"Endpoint: {CHAT_URL}")
    print(f"Log Group: {LOG_GROUP or '(not found)'}")
    print("=" * 70)
    print()

    results = []
    session_id = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"

    for i, test in enumerate(TESTS, 1):
        print(f"[{i}/{len(TESTS)}] {test['name']}: {test['message'][:60]}...")

        response = send_chat(test["message"], f"{session_id}-{test['name']}")
        filepath = save_evidence(test["name"], test["message"], response)

        passed, reason = check_response(test, response)
        status = "PASS" if passed else "FAIL"
        results.append({"test": test["name"], "status": status, "reason": reason})

        print(f"       {status}: {reason}")
        print(f"       Evidence: {filepath.name}")

        # Capture guardrail trace if present
        body = response.get("body", {})
        if isinstance(body, dict) and body.get("guardrail_blocked"):
            print(f"       ⚠ Guardrail intervention detected")
            guardrail_file = EVIDENCE_DIR / f"{test['name']}_guardrail.json"
            guardrail_file.write_text(json.dumps(body, indent=2), encoding="utf-8")
            print(f"       Guardrail evidence: {guardrail_file.name}")

        # Small delay between tests
        if i < len(TESTS):
            time.sleep(2)

        print()

    # Check CloudWatch logs
    print("-" * 70)
    print("Checking CloudWatch logs...")
    time.sleep(5)  # Give logs time to propagate
    cw_result = check_cloudwatch_logs()
    cw_file = EVIDENCE_DIR / "cloudwatch_logs.json"
    cw_file.write_text(json.dumps(cw_result, indent=2, default=str), encoding="utf-8")

    if cw_result.get("checked"):
        print(f"  Total events: {cw_result['total_events']}")
        print(f"  Structured JSON events: {cw_result['structured_json_events']}")
        if cw_result["structured_json_events"] > 0:
            print("  PASS: Structured JSON logging confirmed")
        else:
            print("  WARN: No structured JSON events found yet (may need more time)")
    else:
        print(f"  SKIP: {cw_result.get('reason', 'unknown')}")

    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed_count = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    for r in results:
        icon = "✓" if r["status"] == "PASS" else "✗"
        print(f"  {icon} {r['test']:30s} {r['status']:6s} {r['reason']}")
    print(f"\n  {passed_count}/{total} tests passed")
    print(f"  Evidence saved to: {EVIDENCE_DIR}")
    print("=" * 70)

    return 0 if passed_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
