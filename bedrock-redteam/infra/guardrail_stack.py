"""CDK stack: Bedrock Guardrail protecting the AnyCompany support agent.

Configures a Bedrock Guardrail with:
- Content filters (hate, insults, violence, sexual, misconduct) – all HIGH
- Prompt-attack filter – HIGH on input
- Denied topic policies (competitor products, medical/legal advice, internal pricing)
- Sensitive-information filters (US SSN, email, phone, credit card)
- Word / phrase blocklist

The guardrail ARN and version are exposed as properties so AgentStack can
attach them to the Bedrock agent.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_bedrock as bedrock
from constructs import Construct

from guardrails.guardrail_config import (
    BLOCKED_WORDS,
    CONTENT_FILTERS,
    DENIED_TOPICS,
    PII_ENTITIES,
)


class GuardrailStack(cdk.Stack):
    """Creates a Bedrock Guardrail and exposes its ARN + version for agent attachment."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Content policy ────────────────────────────────────────────
        content_policy = bedrock.CfnGuardrail.ContentPolicyConfigProperty(
            filters_config=[
                bedrock.CfnGuardrail.ContentFilterConfigProperty(
                    type=f["type"],
                    input_strength=f["inputStrength"],
                    output_strength=f["outputStrength"],
                )
                for f in CONTENT_FILTERS
            ],
        )

        # ── Topic policy ──────────────────────────────────────────────
        topic_policy = bedrock.CfnGuardrail.TopicPolicyConfigProperty(
            topics_config=[
                bedrock.CfnGuardrail.TopicConfigProperty(
                    name=t["name"],
                    definition=t["definition"],
                    examples=t["examples"],
                    type=t["type"],
                )
                for t in DENIED_TOPICS
            ],
        )

        # ── Sensitive information policy (PII) ────────────────────────
        sensitive_info_policy = (
            bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                pii_entities_config=[
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type=p["type"],
                        action=p["action"],
                    )
                    for p in PII_ENTITIES
                ],
            )
        )

        # ── Word policy ───────────────────────────────────────────────
        word_policy = bedrock.CfnGuardrail.WordPolicyConfigProperty(
            words_config=[
                bedrock.CfnGuardrail.WordConfigProperty(text=w)
                for w in BLOCKED_WORDS
            ],
        )

        # ── Guardrail resource ────────────────────────────────────────
        self._guardrail = bedrock.CfnGuardrail(
            self,
            "RedTeamGuardrail",
            name="AnyCompanySupportGuardrail",
            description=(
                "Guardrail for the AnyCompany customer-support agent. "
                "Blocks harmful content, prompt attacks, PII leakage, "
                "denied topics, and blocklisted words."
            ),
            blocked_input_messaging=(
                "Sorry, I can't process that request. "
                "Please rephrase without prohibited content."
            ),
            blocked_outputs_messaging=(
                "Sorry, I'm unable to provide that information."
            ),
            content_policy_config=content_policy,
            topic_policy_config=topic_policy,
            sensitive_information_policy_config=sensitive_info_policy,
            word_policy_config=word_policy,
        )

        # Create an explicit version so the agent can pin to it.
        self._guardrail_version = bedrock.CfnGuardrailVersion(
            self,
            "RedTeamGuardrailVersion",
            guardrail_identifier=self._guardrail.attr_guardrail_id,
            description="Initial version",
        )

        # ── Outputs ───────────────────────────────────────────────────
        cdk.CfnOutput(self, "GuardrailId", value=self._guardrail.attr_guardrail_id)
        cdk.CfnOutput(self, "GuardrailArn", value=self._guardrail.attr_guardrail_arn)
        cdk.CfnOutput(
            self,
            "GuardrailVersion",
            value=self._guardrail_version.attr_version,
        )

    # -- Public properties for cross-stack references ------------------

    @property
    def guardrail_id(self) -> str:
        """CloudFormation token for the guardrail ID."""
        return self._guardrail.attr_guardrail_id

    @property
    def guardrail_arn(self) -> str:
        """CloudFormation token for the guardrail ARN."""
        return self._guardrail.attr_guardrail_arn

    @property
    def guardrail_version(self) -> str:
        """CloudFormation token for the pinned guardrail version."""
        return self._guardrail_version.attr_version
