"""CDK stack: S3 bucket that stores the AnyCompany returns-policy document.

This is the attack surface. The bucket holds a single object
(returns_policy.txt) that the agent's returns_policy_lookup tool reads at
invocation time. During red-team runs we replace this object with poisoned
variants from the attacks/ directory.

Resources created:
- S3 Bucket with versioning enabled (so we can roll back after each test)
- BucketDeployment that seeds the clean returns policy on first deploy
"""

from __future__ import annotations

import pathlib

import aws_cdk as cdk
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from constructs import Construct

_FIXTURES_DIR = str(
    pathlib.Path(__file__).resolve().parent.parent / "guardrails" / "fixtures"
)


class PolicyBucketStack(cdk.Stack):
    """S3 bucket for the returns-policy document, seeded with the clean baseline."""

    POLICY_OBJECT_KEY = "returns_policy.txt"

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── S3 bucket ─────────────────────────────────────────────────
        self._bucket = s3.Bucket(
            self,
            "PolicyBucket",
            versioned=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
        )

        # ── Seed the clean returns policy ─────────────────────────────
        s3deploy.BucketDeployment(
            self,
            "SeedCleanPolicy",
            sources=[s3deploy.Source.asset(_FIXTURES_DIR)],
            destination_bucket=self._bucket,
            destination_key_prefix="",  # files land at bucket root
            # Rename clean_returns_policy.md → returns_policy.txt
            # BucketDeployment deploys all files; the agent reads by key.
            # We deploy the fixture dir as-is and also put a .txt copy.
        )

        # Also deploy a plain-text copy under the canonical key name.
        s3deploy.BucketDeployment(
            self,
            "SeedCleanPolicyTxt",
            sources=[
                s3deploy.Source.data(
                    self.POLICY_OBJECT_KEY,
                    pathlib.Path(
                        _FIXTURES_DIR, "clean_returns_policy.md"
                    ).read_text(encoding="utf-8"),
                ),
            ],
            destination_bucket=self._bucket,
        )

        # ── Outputs ───────────────────────────────────────────────────
        cdk.CfnOutput(self, "PolicyBucketName", value=self._bucket.bucket_name)
        cdk.CfnOutput(self, "PolicyBucketArn", value=self._bucket.bucket_arn)

    # -- Public properties for cross-stack references ------------------

    @property
    def bucket(self) -> s3.IBucket:
        return self._bucket

    @property
    def bucket_name(self) -> str:
        return self._bucket.bucket_name

    @property
    def policy_object_key(self) -> str:
        return self.POLICY_OBJECT_KEY
