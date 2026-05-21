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

# ---------------------------------------------------------------------------
# Approved model registry: only models listed here (with exact pinned version)
# may be instantiated.  Format: "<model-family>:<version-pin>"
# ---------------------------------------------------------------------------
_APPROVED_MODEL_REGISTRY: dict[str, str] = {
    "gpt-4o:2024-08-06": "gpt-4o:2024-08-06",
    "gpt-4-turbo:2024-04-09": "gpt-4-turbo:2024-04-09",
    "gpt-3.5-turbo:0125": "gpt-3.5-turbo:0125",
    "claude-3-5-sonnet:20241022": "claude-3-5-sonnet:20241022",
    "claude-3-haiku:20240307": "claude-3-haiku:20240307",
    "llama-3.1-70b-instruct:2024-07-23": "llama-3.1-70b-instruct:2024-07-23",
}


def _verify_model_in_registry(model_id: str) -> str:
    """Verify *model_id* is in the approved registry and return its canonical
    pinned identifier.  Raises ValueError for unknown or un-pinned models."""
    if not model_id or model_id == "unknown-model":
        raise ValueError(
            "model_id must be explicitly provided; 'unknown-model' is not "
            "permitted.  Supply a fully-qualified, version-pinned model "
            "identifier (e.g. 'gpt-4o:2024-08-06')."
        )
    if ":" not in model_id:
        raise ValueError(
            f"model_id '{model_id}' is missing a version pin.  "
            "Use the format '<model-family>:<version>' "
            "(e.g. 'gpt-4o:2024-08-06')."
        )
    if model_id not in _APPROVED_MODEL_REGISTRY:
        raise ValueError(
            f"model_id '{model_id}' is NOT in the approved model registry.  "
            f"Approved models: {sorted(_APPROVED_MODEL_REGISTRY.keys())}"
        )
    return _APPROVED_MODEL_REGISTRY[model_id]

# Organization-approved LLM model identifiers
APPROVED_MODELS = {
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "claude-3-5-sonnet-20241022",
    "claude-3-haiku-20240307",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
}

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

    def __init__(self, model_id: str):
        if model_id not in APPROVED_MODELS:
            raise ValueError(
                f"Model '{model_id}' is not in the organization's approved model list. "
                f"Approved models: {sorted(APPROVED_MODELS)}"
            )
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
            f"{self._CONTENT_LABEL}"
        )
        labeled_response = response + watermark_footer

        # ------------------------------------------------------------------
        # Compute a hash of the raw input for the forensic audit record.
        # The principal is read from an environment variable / can be injected
        # via a context variable in a real deployment.
        # ------------------------------------------------------------------
        input_hash = hashlib.sha256(response.encode()).hexdigest()
        principal = os.environ.get("LLM_GUARD_PRINCIPAL", "unknown-principal")

        audit_record = {
            "event": "llm_response_validated",
            "timestamp_utc": generated_at,
            "principal": principal,
            "model_id": self.model_id,
            "input_hash_sha256": input_hash,
            "watermark_id": watermark_id,
            "fingerprint_sha256": fingerprint,
            "validation_count": self.validation_count,
            "is_valid": True,
            "violations": [],
            "retention_policy": {
                "max_bytes_per_file": _AUDIT_LOG_MAX_BYTES,
                "backup_count": _AUDIT_LOG_BACKUP_COUNT,
                "log_path": _AUDIT_LOG_PATH,
            },
        }
        _write_audit_record(audit_record)

        # Also emit a non-sensitive summary to the standard logger for
        # operational visibility (NOT a substitute for the audit record).
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

        # ------------------------------------------------------------------
        # Dynamic-code-execution primitive detection
        # Patterns that must never appear in LLM output returned to callers.
        # ------------------------------------------------------------------
        import re as _re

        _DANGEROUS_PATTERNS: list[tuple[str, str]] = [
            # Python builtins / eval-family
            (r'\beval\s*\(', 'eval()'),
            (r'\bexec\s*\(', 'exec()'),
            (r'\bcompile\s*\(', 'compile()'),
            (r'\b__import__\s*\(', '__import__()'),
            (r'\bexecfile\s*\(', 'execfile()'),
            # subprocess with shell=True
            (r'subprocess\s*\.\s*\w+\s*\([^)]*shell\s*=\s*True', 'subprocess(shell=True)'),
            (r'subprocess\s*\.\s*Popen\s*\([^)]*shell\s*=\s*True', 'subprocess.Popen(shell=True)'),
            # os-level execution
            (r'\bos\s*\.\s*system\s*\(', 'os.system()'),
            (r'\bos\s*\.\s*popen\s*\(', 'os.popen()'),
            (r'\bos\s*\.\s*execv[pe]?\s*\(', 'os.exec*()'),
            (r'\bos\s*\.\s*spawn[lv][pe]?\s*\(', 'os.spawn*()'),
            # ctypes / cffi dynamic loading
            (r'\bctypes\s*\.\s*CDLL\s*\(', 'ctypes.CDLL()'),
            (r'\bcffi\b.*\.dlopen\s*\(', 'cffi.dlopen()'),
            # importlib dynamic import
            (r'importlib\s*\.\s*import_module\s*\(', 'importlib.import_module()'),
            # JavaScript / Node eval-family (in case of mixed-language output)
            (r'\beval\s*\(', 'eval() [JS]'),
            (r'\bFunction\s*\(', 'new Function() [JS]'),
            (r'\bsetTimeout\s*\(\s*["\']', 'setTimeout(string) [JS]'),
            (r'\bsetInterval\s*\(\s*["\']', 'setInterval(string) [JS]'),
        ]

        violations: list[str] = []
        sanitized_response = labeled_response

        for pattern, label in _DANGEROUS_PATTERNS:
            if _re.search(pattern, response, _re.IGNORECASE):
                violation_msg = f"Dangerous dynamic code execution primitive detected: {label}"
                violations.append(violation_msg)
                logger.warning(
                    violation_msg,
                    extra={
                        'model_id': self.model_id,
                        'watermark_id': watermark_id,
                        'pattern': pattern,
                    }
                )
                # Redact the offending token from the response that will be
                # returned to the caller so it cannot be copy-pasted and run.
                sanitized_response = _re.sub(
                    pattern,
                    '[REDACTED:UNSAFE_CODE_PRIMITIVE]',
                    sanitized_response,
                    flags=_re.IGNORECASE,
                )

        is_valid = len(violations) == 0

        if not is_valid:
            logger.error(
                "LLM response FAILED validation – dynamic code execution primitives found",
                extra={
                    'model_id': self.model_id,
                    'watermark_id': watermark_id,
                    'violation_count': len(violations),
                    'violations': violations,
                }
            )

        return ValidationResult(
            is_valid=is_valid,
            violations=violations,
            filtered_response=sanitized_response,
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
