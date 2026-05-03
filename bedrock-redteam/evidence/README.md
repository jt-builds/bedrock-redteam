# Evidence directory

Captured artifacts from red-team test runs. Each run produces a timestamped
subdirectory containing:

- `run_metadata.json`  – payload used, S3 version ID, agent config, timestamps
- `transcript.json`    – full agent conversation (user turns + assistant turns)
- `trace.json`         – Bedrock agent trace including tool invocations
- `guardrail_eval.json`– Guardrail assessment results (if triggered)
- `score.json`         – Automated scoring output (BLOCKED / RESISTED / PARTIAL / COMPROMISED)

This directory is git-ignored except for this README. Evidence is stored locally
or in a separate S3 bucket for long-term retention.
