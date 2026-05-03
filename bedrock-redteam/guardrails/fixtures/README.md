# Guardrail test fixtures

Benign (non-poisoned) documents used as baselines:

- `clean_returns_policy.md` – The legitimate AnyCompany returns policy with no
  injection payloads. Upload this to S3 to establish a control run before
  executing attack variants.
