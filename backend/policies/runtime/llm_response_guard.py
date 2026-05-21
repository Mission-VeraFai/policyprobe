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

# Organization-approved LLM model identifiers — derived from the pinned registry.
# Do NOT add unpinned or unversioned entries here; update _APPROVED_MODEL_REGISTRY instead.
APPROVED_MODELS = set(_APPROVED_MODEL_REGISTRY.keys())

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
        # Raises ValueError if model_id is missing a version pin or is not in
        # the approved registry; stores the canonical pinned identifier.
        self.model_id = _verify_model_in_registry(model_id)
        self.validation_count = 0

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

        # --- Persistent append-only audit record ---
        import hashlib as _hashlib
        import json as _json
        import logging.handlers as _log_handlers
        import os as _os
        import datetime as _datetime

        _AUDIT_LOG_PATH = _os.environ.get(
            "LLM_GUARD_AUDIT_LOG",
            "/var/log/llm_guard/audit.jsonl",
        )
        _AUDIT_MAX_BYTES = int(_os.environ.get("LLM_GUARD_AUDIT_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB
        _AUDIT_BACKUP_COUNT = int(_os.environ.get("LLM_GUARD_AUDIT_BACKUP_COUNT", "90"))  # ~90 rotations

        _os.makedirs(_os.path.dirname(_AUDIT_LOG_PATH), exist_ok=True)

        _audit_logger = _logging.getLogger("llm_guard.audit")
        if not _audit_logger.handlers:
            _audit_logger.setLevel(_logging.INFO)
            _audit_handler = _log_handlers.RotatingFileHandler(
                _AUDIT_LOG_PATH,
                maxBytes=_AUDIT_MAX_BYTES,
                backupCount=_AUDIT_BACKUP_COUNT,
                encoding="utf-8",
            )
            _audit_handler.setFormatter(_logging.Formatter("%(message)s"))
            _audit_logger.addHandler(_audit_handler)
            _audit_logger.propagate = False

        _audit_record = {
            "timestamp": _datetime.datetime.utcnow().isoformat() + "Z",
            "principal": self.model_id,
            "watermark_id": watermark_id,
            "input_hash": _hashlib.sha256(response.encode("utf-8", errors="replace")).hexdigest(),
            "output_hash": _hashlib.sha256(sanitized_response.encode("utf-8", errors="replace")).hexdigest(),
            "is_valid": is_valid,
            "violation_count": len(violations),
            "violations": violations,
            "provenance": provenance,
        }
        _audit_logger.info(_json.dumps(_audit_record, default=str))
        # --- End audit record ---

        return ValidationResult(
            is_valid=is_valid,
            violations=violations,
            filtered_response=sanitized_response,
            original_response=None,  # Omitted to enforce output data minimisation – raw LLM output must not be returned to callers.
            provenance=provenance,
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        Detects common PII patterns: email addresses, phone numbers, SSNs,
        credit card numbers, and IP addresses.
        """
        violations: list[str] = []
        _PII_PATTERNS = [
            (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'Email address'),
            (r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b', 'Phone number'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            (r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b', 'Credit card number'),
            (r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', 'IP address'),
        ]
        for pattern, label in _PII_PATTERNS:
            if _re.search(pattern, response, _re.IGNORECASE):
                violations.append(f'PII detected in response: {label}')
                logger.warning(
                    'PII detected in LLM response',
                    extra={'model_id': self.model_id, 'pii_type': label},
                )
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        Detects slurs, hate-speech markers, and explicit harmful directives.
        """
        violations: list[str] = []
        _BIAS_PATTERNS = [
            (r'\b(?:kill|murder|assassinate|bomb|attack)\s+(?:all\s+)?(?:the\s+)?[a-z]+s\b', 'Violent directive targeting group'),
            (r'\b(?:inferior|superior)\s+(?:race|gender|religion|ethnicity)\b', 'Discriminatory superiority claim'),
            (r'\bhate\s+(?:all\s+)?(?:the\s+)?[a-z]+s\b', 'Hate speech pattern'),
            (r'\b(?:you\s+(?:people|lot)|those\s+people)\s+(?:are\s+)?(?:always|never|all)\b', 'Stereotyping language'),
        ]
        for pattern, label in _BIAS_PATTERNS:
            if _re.search(pattern, response, _re.IGNORECASE):
                violations.append(f'Biased or harmful content detected: {label}')
                logger.warning(
                    'Biased/harmful content detected in LLM response',
                    extra={'model_id': self.model_id, 'bias_type': label},
                )
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        Detects API keys, secrets, private keys, connection strings,
        and bearer tokens that should never appear in output.
        """
        violations: list[str] = []
        _LEAK_PATTERNS = [
            (r'(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*[\'"]?[A-Za-z0-9\-_]{16,}[\'"]?', 'API key'),
            (r'(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*[\'"]?\S{8,}[\'"]?', 'Secret/password'),
            (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private key block'),
            (r'(?i)(?:jdbc|mongodb(?:\+srv)?|redis|amqp|postgresql|mysql)://[^\s\'"]{8,}', 'Database connection string'),
            (r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}', 'Bearer token'),
            (r'(?i)(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[A-Za-z0-9/+]{16,}', 'AWS credential'),
        ]
        for pattern, label in _LEAK_PATTERNS:
            if _re.search(pattern, response):
                violations.append(f'Sensitive data leakage detected: {label}')
                logger.warning(
                    'Sensitive data leakage detected in LLM response',
                    extra={'model_id': self.model_id, 'leak_type': label},
                )
        return violations
