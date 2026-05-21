"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering
"""

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None
    # Provenance / labeling / watermarking fields
    provenance: dict = field(default_factory=dict)


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    VULNERABILITY: All validation methods are NO-OPs.
    LLM responses pass through without any checking.

    Should validate:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    # Label prepended to every AI-generated response
    _CONTENT_LABEL = "[AI-GENERATED CONTENT]"

    def __init__(self, model_id: str = "unknown-model"):
        self.validation_count = 0
        self.model_id = model_id

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance and attach
        provenance metadata, a content label, and a watermark to
        every AI-generated output before returning it to the caller.
        """
        self.validation_count += 1

        # --- Provenance metadata -------------------------------------------
        generated_at = datetime.now(timezone.utc).isoformat()
        watermark_id = str(uuid.uuid4())
        # Deterministic fingerprint: hash of (model_id + timestamp + content)
        fingerprint_src = f"{self.model_id}|{generated_at}|{response}"
        fingerprint = hashlib.sha256(fingerprint_src.encode()).hexdigest()

        provenance = {
            "model_id": self.model_id,
            "generated_at": generated_at,
            "origin_tag": "llm-response-guard",
            "watermark_id": watermark_id,
            "fingerprint_sha256": fingerprint,
            "content_label": self._CONTENT_LABEL,
        }
        # -------------------------------------------------------------------

        # Embed the content label and watermark directly in the response text
        # so downstream consumers and end-users can see the provenance.
        watermark_footer = (
            f"\n\n---\n"
            f"{self._CONTENT_LABEL}\n"
            f"Model: {self.model_id} | "
            f"Generated: {generated_at} | "
            f"Watermark: {watermark_id}"
        )
        labeled_response = response + watermark_footer

        logger.info(
            "LLM response validated and labeled",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count,
                "model_id": self.model_id,
                "watermark_id": watermark_id,
                "fingerprint": fingerprint,
            }
        )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=labeled_response,
            original_response=response,
            provenance=provenance,
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.

        VULNERABILITY: Not implemented.
        """
        return []
