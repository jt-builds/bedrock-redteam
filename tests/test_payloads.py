"""Unit tests for attack payload generation (attacks/payloads.py).

Covers:
- Each payload function produces valid Markdown
- Injected content is present in the output
- Clean policy text is preserved around the injection
- PAYLOAD_REGISTRY contains all expected payload families
"""
