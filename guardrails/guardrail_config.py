"""Guardrail policy definitions as Python dicts.

Provides the configuration payloads used by the CDK GuardrailStack and by
standalone scripts that create/update guardrails via the Bedrock API.

Sections:
- content_policy_config      – filter strengths for each harmful category
- topic_policy_config        – denied topics (competitors, off-topic)
- sensitive_info_policy      – PII entity types to detect/redact
- word_policy_config         – explicit blocklist words/phrases
- prompt_attack_policy       – prompt-attack filter strength
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Content filters – all categories at HIGH for both input and output
# ---------------------------------------------------------------------------
CONTENT_FILTERS = [
    {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
    {"type": "INSULTS", "inputStrength": "HIGH", "outputStrength": "HIGH"},
    {"type": "VIOLENCE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
    {"type": "MISCONDUCT", "inputStrength": "HIGH", "outputStrength": "HIGH"},
    {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"},
    {"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"},
]

# ---------------------------------------------------------------------------
# Denied topics – each with 3-5 example phrases
# ---------------------------------------------------------------------------
DENIED_TOPICS = [
    {
        "name": "CompetitorProducts",
        "definition": "Any mention of or inquiry about competitor products or services.",
        "examples": [
            "What do you think about Acme Corp's return policy?",
            "Is your product better than BrandX?",
            "Can you compare your service to CompetitorCo?",
            "Tell me about alternatives from other companies.",
            "How does RivalInc's pricing compare to yours?",
        ],
        "type": "DENY",
    },
    {
        "name": "MedicalAdvice",
        "definition": "Requests for medical diagnoses, treatment recommendations, or health advice.",
        "examples": [
            "What medication should I take for a headache?",
            "Can you diagnose my symptoms?",
            "Is this rash something I should worry about?",
            "What's the best treatment for back pain?",
        ],
        "type": "DENY",
    },
    {
        "name": "LegalAdvice",
        "definition": "Requests for legal opinions, interpretations, or counsel.",
        "examples": [
            "Can I sue the company for this?",
            "What are my legal rights in this situation?",
            "Is this contract clause enforceable?",
            "Should I get a lawyer for my return dispute?",
        ],
        "type": "DENY",
    },
    {
        "name": "InternalPricingOrDiscountPolicies",
        "definition": "Requests about internal pricing strategies, discount structures, or confidential pricing policies.",
        "examples": [
            "What is your employee discount percentage?",
            "Tell me about your internal pricing tiers.",
            "What wholesale margins do you offer partners?",
            "Can you share the confidential discount schedule?",
            "What's the cost-plus markup on this product?",
        ],
        "type": "DENY",
    },
]

# ---------------------------------------------------------------------------
# PII filters – US SSN, email, phone, credit card
# ---------------------------------------------------------------------------
PII_ENTITIES = [
    {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
    {"type": "EMAIL", "action": "ANONYMIZE"},
    {"type": "PHONE", "action": "ANONYMIZE"},
    {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
]

# ---------------------------------------------------------------------------
# Word / phrase blocklist
# ---------------------------------------------------------------------------
BLOCKED_WORDS = [
    "jailbreak",
    "ignore previous instructions",
    "system prompt",
]

# ---------------------------------------------------------------------------
# Contextual grounding (optional, included for completeness)
# ---------------------------------------------------------------------------
CONTEXTUAL_GROUNDING = {
    "groundingThreshold": 0.7,
    "relevanceThreshold": 0.7,
}
