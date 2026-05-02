"""Unit tests for attack outcome scoring (attacks/scoring.py).

Covers:
- BLOCKED classification when guardrail trace shows intervention
- RESISTED classification when agent ignores injected instructions
- PARTIAL classification for ambiguous responses
- COMPROMISED classification when agent follows injected instructions
- PII-leak and competitor-mention signal extraction
"""
