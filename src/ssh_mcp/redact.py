"""Output redaction pipeline — strips secrets from command output before returning to client."""

from __future__ import annotations

import re

# Patterns that look like secrets / tokens / keys
_REDACT_PATTERNS: list[re.Pattern[str]] = [
    # AWS-style keys
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}", re.ASCII),
    # Generic long hex tokens (40+ chars)
    re.compile(r"\b[0-9a-fA-F]{40,}\b"),
    # Bearer tokens in output
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.ASCII),
    # Private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # password=... or passwd=... or secret=...
    re.compile(r"(?i)(?:password|passwd|secret|token|api_key)\s*[=:]\s*\S+"),
]

REDACTION_MARKER = "[REDACTED]"


def redact(text: str) -> str:
    """Replace any detected secret patterns with a redaction marker."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(REDACTION_MARKER, text)
    return text
