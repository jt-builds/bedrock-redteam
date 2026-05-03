"""Unit tests for agent tool implementations (app/tools.py).

Covers:
- order_lookup returns expected mock data for known order IDs
- shipping_status returns expected mock data
- returns_policy_lookup reads from S3 (mocked with moto or stubbed boto3)
- returns_policy_lookup handles missing object gracefully
"""
