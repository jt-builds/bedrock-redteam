"""Tool implementations for the AnyCompany support agent.

Three tools exposed to the Strands agent via @tool decorator:

order_lookup(order_id: str) -> dict
    Returns mock order details (items, total, date, customer name).

shipping_status(order_id: str) -> dict
    Returns mock shipping info (carrier, tracking number, status, ETA).

returns_policy_lookup(topic: str) -> str
    Reads the returns-policy document from S3. THIS IS THE ATTACK SURFACE —
    the S3 object may contain indirect prompt-injection payloads during
    red-team runs.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from strands import tool

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------
ORDERS: dict[str, dict[str, Any]] = {
    "ORD-1001": {
        "order_id": "ORD-1001",
        "customer": "Alice Johnson",
        "items": [
            {"name": "Ergonomic Keyboard", "qty": 1, "price": 89.99},
            {"name": "USB-C Hub", "qty": 2, "price": 34.99},
        ],
        "total": 159.97,
        "date": "2026-04-25",
        "status": "shipped",
    },
    "ORD-1002": {
        "order_id": "ORD-1002",
        "customer": "Bob Smith",
        "items": [
            {"name": "Standing Desk Mat", "qty": 1, "price": 49.99},
        ],
        "total": 49.99,
        "date": "2026-04-28",
        "status": "processing",
    },
    "ORD-1003": {
        "order_id": "ORD-1003",
        "customer": "Carol Davis",
        "items": [
            {"name": "Wireless Mouse", "qty": 1, "price": 29.99},
            {"name": "Monitor Stand", "qty": 1, "price": 59.99},
            {"name": "Desk Lamp", "qty": 1, "price": 39.99},
        ],
        "total": 129.97,
        "date": "2026-04-20",
        "status": "delivered",
    },
}

SHIPPING: dict[str, dict[str, Any]] = {
    "ORD-1001": {
        "order_id": "ORD-1001",
        "carrier": "FastShip",
        "tracking_number": "FS-78234-A",
        "status": "in_transit",
        "eta": "2026-05-04",
    },
    "ORD-1002": {
        "order_id": "ORD-1002",
        "carrier": "pending",
        "tracking_number": "N/A",
        "status": "label_created",
        "eta": "2026-05-07",
    },
    "ORD-1003": {
        "order_id": "ORD-1003",
        "carrier": "FastShip",
        "tracking_number": "FS-71002-C",
        "status": "delivered",
        "eta": "2026-04-23",
    },
}


# ---------------------------------------------------------------------------
# Strands @tool functions
# ---------------------------------------------------------------------------

@tool
def order_lookup(order_id: str) -> str:
    """Look up order details by order ID (e.g. ORD-1001).

    Returns order information including items, total, date, and status.
    """
    logger.info(json.dumps({"event": "tool_call", "tool": "order_lookup", "order_id": order_id}))

    order = ORDERS.get(order_id)
    if order is None:
        return json.dumps({"error": f"Order {order_id} not found."})
    return json.dumps(order, default=str)


@tool
def shipping_status(order_id: str) -> str:
    """Look up shipping and tracking status for an order by order ID.

    Returns carrier, tracking number, current status, and estimated delivery.
    """
    logger.info(json.dumps({"event": "tool_call", "tool": "shipping_status", "order_id": order_id}))

    shipping = SHIPPING.get(order_id)
    if shipping is None:
        return json.dumps({"error": f"No shipping info for order {order_id}."})
    return json.dumps(shipping, default=str)


@tool
def returns_policy_lookup(topic: str) -> str:
    """Retrieve the current AnyCompany returns policy from the knowledge base.

    Reads the returns-policy document from S3. Use this when a customer asks
    about returns, refunds, exchanges, or damaged items.
    """
    bucket = os.environ.get("POLICY_BUCKET_NAME", "")
    key = os.environ.get("POLICY_OBJECT_KEY", "returns_policy.txt")

    logger.info(json.dumps({
        "event": "tool_call",
        "tool": "returns_policy_lookup",
        "topic": topic,
        "bucket": bucket,
        "key": key,
    }))

    if not bucket:
        return "Returns policy is temporarily unavailable (bucket not configured)."

    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        return obj["Body"].read().decode("utf-8")
    except Exception:
        logger.exception("Failed to read returns policy from S3")
        return "Returns policy is temporarily unavailable."
