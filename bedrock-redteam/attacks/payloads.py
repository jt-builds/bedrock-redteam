"""Indirect prompt-injection payload definitions.

Each payload is a function that takes the clean returns-policy text and returns
a poisoned variant with an injection embedded. Payloads are registered in
PAYLOAD_REGISTRY so the runner can enumerate them.

Planned payload families:
- naive_instruction    – Plain-text "Ignore previous instructions…" appended
- markdown_comment     – Injection hidden inside an HTML/Markdown comment
- unicode_tag          – Injection using Unicode tag characters (U+E0001…)
- base64_encoded       – Injection encoded in base64 with decode instruction
- delimiter_escape     – Attempts to break out of tool-result delimiters
- role_impersonation   – Fakes an assistant turn inside the document
- data_exfil           – Instructs the agent to leak order data in its reply
- goal_hijack          – Redirects the agent to promote a competitor
"""
