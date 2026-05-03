"""Utility to upload a returns-policy document to S3.

Usage:
    python -m app.seed_policy --variant clean
    python -m app.seed_policy --variant unicode_tag

Reads the appropriate file from guardrails/fixtures/ (or attacks/payloads/)
and uploads it to the configured S3 bucket/key. Prints the S3 version ID
so the run can be correlated with evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

import boto3

FIXTURES_DIR = pathlib.Path(__file__).resolve().parent.parent / "guardrails" / "fixtures"
ATTACKS_DIR = pathlib.Path(__file__).resolve().parent.parent / "attacks" / "payloads"

VARIANT_MAP: dict[str, pathlib.Path] = {
    "clean": FIXTURES_DIR / "clean_returns_policy.md",
}


def _resolve_path(variant: str) -> pathlib.Path:
    if variant in VARIANT_MAP:
        return VARIANT_MAP[variant]
    candidate = ATTACKS_DIR / f"{variant}.md"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(
        f"Unknown variant '{variant}'. Available: {list(VARIANT_MAP)} "
        f"or any .md file in {ATTACKS_DIR}"
    )


def upload(variant: str) -> dict[str, str]:
    """Upload the chosen variant to S3 and return metadata."""
    bucket = os.environ.get("POLICY_BUCKET_NAME", "")
    key = os.environ.get("POLICY_OBJECT_KEY", "returns_policy.txt")

    if not bucket:
        print("Error: POLICY_BUCKET_NAME env var is not set.", file=sys.stderr)
        sys.exit(1)

    path = _resolve_path(variant)
    content = path.read_text(encoding="utf-8")

    s3 = boto3.client("s3")
    resp = s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=content.encode("utf-8"),
        ContentType="text/plain",
    )
    version_id = resp.get("VersionId", "none")
    meta = {
        "variant": variant,
        "source_file": str(path),
        "bucket": bucket,
        "key": key,
        "version_id": version_id,
    }
    print(json.dumps(meta, indent=2))
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the returns-policy S3 object.")
    parser.add_argument(
        "--variant",
        default="clean",
        help="Policy variant to upload (default: clean)",
    )
    args = parser.parse_args()
    upload(args.variant)


if __name__ == "__main__":
    main()
