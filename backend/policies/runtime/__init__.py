"""
Runtime Policy Enforcement

Runtime guardrails that execute during application operation.

SECURITY NOTES:
- Input is validated and sanitized before processing
- LLM responses are validated via LLMResponseGuard
- Audit logging is active via AuditLogger
"""

import re
import html

from .llm_response_guard import LLMResponseGuard
from .audit_logger import AuditLogger


class InputSanitizer:
    """Validates and sanitizes input before processing."""

    MAX_INPUT_LENGTH = 10_000

    # Patterns considered dangerous
    _DANGEROUS_PATTERNS = [
        re.compile(r"<script[\s\S]*?</script>", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # inline event handlers
        re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),  # control chars except \t \n \r
    ]

    def sanitize(self, user_input: str) -> str:
        """Validate and sanitize a string input.

        Raises ValueError for inputs that cannot be made safe.
        Returns a sanitized copy of the input.
        """
        if not isinstance(user_input, str):
            raise ValueError("Input must be a string.")

        # Enforce length limit
        if len(user_input) > self.MAX_INPUT_LENGTH:
            raise ValueError(
                f"Input exceeds maximum allowed length of {self.MAX_INPUT_LENGTH} characters."
            )

        # Remove null bytes
        sanitized = user_input.replace("\x00", "")

        # Strip dangerous patterns
        for pattern in self._DANGEROUS_PATTERNS:
            sanitized = pattern.sub("", sanitized)

        # Escape HTML special characters to prevent injection
        sanitized = html.escape(sanitized, quote=True)

        return sanitized

    def sanitize_dict(self, data: dict) -> dict:
        """Recursively sanitize all string values in a dictionary."""
        if not isinstance(data, dict):
            raise ValueError("Input must be a dictionary.")
        return {
            key: (
                self.sanitize(value)
                if isinstance(value, str)
                else self.sanitize_dict(value)
                if isinstance(value, dict)
                else value
            )
            for key, value in data.items()
        }


__all__ = ["LLMResponseGuard", "InputSanitizer", "AuditLogger"]
