"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES:
- validate() actively checks for dynamic code execution primitives (eval, exec, etc.)
- Responses containing dangerous code execution patterns are rejected
- Additional bias, PII, and harmful content filtering should be layered on top
"""

import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Watermarking & provenance signing
# ---------------------------------------------------------------------------
# Secret key used to sign provenance metadata.  In production this MUST be
# loaded from a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).
# The environment variable AI_PROVENANCE_SIGNING_KEY must be set to a
# cryptographically random value of at least 32 bytes (hex-encoded).
_PROVENANCE_SIGNING_KEY: bytes = bytes.fromhex(
    os.environ.get(
        'AI_PROVENANCE_SIGNING_KEY',
        hashlib.sha256(b'__insecure_default_replace_in_production__').hexdigest(),
    )
)

# Watermark token embedded in every AI-generated response.  The Unicode
# zero-width characters form a detectable, human-invisible marker.
_WATERMARK_TOKEN: str = '\u200b\u200c\u200b\u200c\u200b'  # ZWSP ZWNJ pattern
_WATERMARK_LABEL: str = '[AI-GENERATED]'


def _sign_provenance(data: dict) -> str:
    """Return a hex-encoded HMAC-SHA256 signature over *data* serialised as
    canonical (sorted-key) JSON.  The signature covers all provenance fields
    so any post-hoc tampering is detectable."""
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
    sig = hmac.new(_PROVENANCE_SIGNING_KEY, canonical.encode('utf-8'), hashlib.sha256)
    return sig.hexdigest()


def _embed_watermark(text: str) -> str:
    """Embed a detectable watermark into *text*.

    Two complementary mechanisms are used:
    1. A visible label prepended to the response so end-users know the content
       is AI-generated.
    2. An invisible Unicode zero-width character sequence appended after the
       first sentence boundary (or at the start when no boundary is found)
       that can be detected programmatically.
    """
    # Visible label
    if not text.startswith(_WATERMARK_LABEL):
        text = f'{_WATERMARK_LABEL} {text}'
    # Invisible marker — append after the first sentence-ending punctuation
    # so it is less likely to be stripped by naive whitespace trimming.
    match = re.search(r'(?<=[.!?])\s', text)
    if match:
        insert_pos = match.start() + 1
        text = text[:insert_pos] + _WATERMARK_TOKEN + text[insert_pos:]
    else:
        text = text + _WATERMARK_TOKEN
    return text


def verify_watermark(text: str) -> bool:
    """Return True when *text* contains the embedded watermark token."""
    return _WATERMARK_TOKEN in text

# ---------------------------------------------------------------------------
# Patterns that indicate dynamic code execution primitives in LLM output.
# Any LLM response matching one of these patterns will be rejected.
# ---------------------------------------------------------------------------
_DYNAMIC_CODE_PATTERNS: list[re.Pattern] = [
    # Python builtins
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bimportlib\.import_module\s*\(', re.IGNORECASE),
    # subprocess / os execution
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(', re.IGNORECASE),
    # JavaScript / browser
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bnew\s+Function\s*\(', re.IGNORECASE),
    re.compile(r'\bsetTimeout\s*\(\s*["\']', re.IGNORECASE),
    re.compile(r'\bsetInterval\s*\(\s*["\']', re.IGNORECASE),
    # Shell injection markers
    re.compile(r'`[^`]*`'),          # backtick command substitution
    re.compile(r'\$\([^)]+\)'),      # $(...) command substitution
    # Dynamic attribute / reflection abuse
    re.compile(r'\bgetattr\s*\(.*,\s*["\']__', re.IGNORECASE),
    re.compile(r'\b__builtins__\b', re.IGNORECASE),
    re.compile(r'\b__globals__\b', re.IGNORECASE),
    re.compile(r'\b__class__\b.*\b__bases__\b', re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Approved model registry: inline, hardcoded list of organization-approved,
# version-pinned model identifiers.  Maps canonical model_id -> pinned_id.
# ALL entries must be reviewed and approved by the security team before
# being added here.  Do NOT add unpinned, unversioned, or unapproved models.
# ---------------------------------------------------------------------------
_APPROVED_MODEL_REGISTRY: dict[str, str] = {
    # Approved, version-pinned model identifiers reviewed by the security team.
    # Format: "<model-family>:<version>": "<canonical-pinned-id>"
    "gpt-4o:2024-08-06": "gpt-4o:2024-08-06",
    "gpt-4-turbo:2024-04-09": "gpt-4-turbo:2024-04-09",
    "gpt-3.5-turbo:2024-01-25": "gpt-3.5-turbo:2024-01-25",
    "claude-3-opus:20240229": "claude-3-opus:20240229",
    "claude-3-sonnet:20240229": "claude-3-sonnet:20240229",
    "claude-3-haiku:20240307": "claude-3-haiku:20240307",
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

# ---------------------------------------------------------------------------
# Persistent audit / decision log — append-only, with rotation and retention.
# Writes one JSON record per line (NDJSON) to a durable file so that every
# AI-driven validation decision is forensically recoverable.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Audit log path sanitisation — prevent log-path injection / traversal.
# The allowed base directory is fixed at module load time; any env-var value
# that would escape it is rejected and the safe default is used instead.
# ---------------------------------------------------------------------------
_AUDIT_LOG_BASE_DIR = "/var/log/llm_response_guard"
_AUDIT_LOG_DEFAULT   = os.path.join(_AUDIT_LOG_BASE_DIR, "audit.log")

def _sanitise_audit_log_path(raw: str) -> str:
    """Return *raw* only when it resolves to a path inside
    ``_AUDIT_LOG_BASE_DIR``; otherwise return the safe default.

    Defences applied:
    * ``os.path.realpath`` collapses ``..`` components and symlinks.
    * A strict prefix check ensures the resolved path cannot escape the
      approved directory tree.
    """
    try:
        resolved = os.path.realpath(os.path.abspath(raw))
        base     = os.path.realpath(os.path.abspath(_AUDIT_LOG_BASE_DIR))
        # Ensure the resolved path is *inside* the base dir (add sep so that
        # a path like /var/log/llm_response_guard_evil does not pass).
        if resolved.startswith(base + os.sep) or resolved == base:
            return resolved
    except Exception:  # pragma: no cover — defensive catch-all
        pass
    logger.warning(
        "LLM_GUARD_AUDIT_LOG_PATH value %r is outside the allowed base "
        "directory %r; falling back to default path.",
        raw,
        _AUDIT_LOG_BASE_DIR,
    )
    return _AUDIT_LOG_DEFAULT

_raw_audit_path   = os.environ.get("LLM_GUARD_AUDIT_LOG_PATH", _AUDIT_LOG_DEFAULT)
_AUDIT_LOG_PATH   = _sanitise_audit_log_path(_raw_audit_path)
_AUDIT_MAX_BYTES  = int(os.environ.get("LLM_GUARD_AUDIT_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB
_AUDIT_BACKUP_COUNT = int(os.environ.get("LLM_GUARD_AUDIT_BACKUP_COUNT", "90"))  # 90 rotated files ≈ 900 MB cap

def _build_audit_logger() -> logging.Logger:
    """Return a dedicated logger that writes NDJSON audit records to a
    rotating file.  Separated from the module logger so audit records are
    never mixed with operational log output."""
    audit_logger = logging.getLogger("llm_response_guard.audit")
    if not audit_logger.handlers:  # avoid duplicate handlers on re-import
        os.makedirs(os.path.dirname(_AUDIT_LOG_PATH), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            _AUDIT_LOG_PATH,
            maxBytes=_AUDIT_MAX_BYTES,
            backupCount=_AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))  # raw JSON lines
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False  # do not bubble up to root logger
    return audit_logger

_audit_logger = _build_audit_logger()


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

    # HMAC signing key for provenance — read from environment; must be set in production
    _PROVENANCE_SIGNING_KEY: bytes = os.environ.get(
        "LLM_GUARD_PROVENANCE_KEY", ""
    ).encode("utf-8") or secrets.token_bytes(32)

    def __init__(self, model_id: str):
        # Raises ValueError if model_id is missing a version pin or is not in
        # the approved registry; stores the canonical pinned identifier.
        self.model_id = _verify_model_in_registry(model_id)
        self.validation_count = 0

    # ------------------------------------------------------------------
    # Provenance helpers
    # ------------------------------------------------------------------

    def _build_provenance(self, response: str) -> dict:
        """Build a provenance record for an AI-generated response.

        The record includes:
        - model_id: the pinned model that produced the response
        - generation_id: a cryptographically random unique identifier
        - timestamp_utc: ISO-8601 UTC timestamp
        - content_sha256: SHA-256 hash of the *original* response text
        - label: the human-readable AI-generated content label
        - signature: HMAC-SHA256 over the canonical provenance fields
        """
        generation_id = str(uuid.uuid4())
        timestamp_utc = datetime.datetime.utcnow().isoformat() + "Z"
        content_hash = hashlib.sha256(response.encode("utf-8")).hexdigest()

        # Canonical payload — deterministic ordering for signing
        canonical = "|".join([
            self.model_id,
            generation_id,
            timestamp_utc,
            content_hash,
            self._CONTENT_LABEL,
        ])
        signature = hmac.new(
            self._PROVENANCE_SIGNING_KEY,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "model_id": self.model_id,
            "generation_id": generation_id,
            "timestamp_utc": timestamp_utc,
            "content_sha256": content_hash,
            "label": self._CONTENT_LABEL,
            "provenance_signature": signature,
        }

    @staticmethod
    def _apply_label_and_watermark(response: str, provenance: dict) -> str:
        """Prepend the AI-generated content label and embed a watermark
        comment containing the generation_id so the provenance is
        recoverable from the text itself."""
        watermark = (
            f"<!-- ai-provenance: generation_id={provenance['generation_id']} "
            f"model={provenance['model_id']} "
            f"ts={provenance['timestamp_utc']} -->"
        )
        return f"{LLMResponseGuard._CONTENT_LABEL}\n{watermark}\n{response}"

    # Patterns that indicate dynamic code execution primitives.
    # These must never appear in LLM-generated output returned to callers.
    _CODE_EXEC_PATTERNS: list[tuple[str, str]] = [
        (r"\beval\s*\(", "eval() call detected"),
        (r"\bexec\s*\(", "exec() call detected"),
        (r"\bcompile\s*\(", "compile() call detected"),
        (r"\b__import__\s*\(", "__import__() call detected"),
        (r"\bimportlib\.import_module\s*\(", "importlib.import_module() call detected"),
        (r"\bos\.system\s*\(", "os.system() call detected"),
        (r"\bos\.popen\s*\(", "os.popen() call detected"),
        (r"\bsubprocess\s*\.\w*\s*\([^)]*shell\s*=\s*True", "subprocess with shell=True detected"),
        (r"\bsubprocess\.call\s*\(", "subprocess.call() call detected"),
        (r"\bsubprocess\.run\s*\(", "subprocess.run() call detected"),
        (r"\bsubprocess\.Popen\s*\(", "subprocess.Popen() call detected"),
        (r"\bpickle\.loads?\s*\(", "pickle.load/loads() call detected"),
        (r"\bmarshal\.loads?\s*\(", "marshal.load/loads() call detected"),
        (r"\bctypes\b", "ctypes usage detected"),
        (r"\b__builtins__\b", "__builtins__ access detected"),
        (r"\bgetattr\s*\(.*,\s*['\"]__", "getattr dunder access detected"),
    ]

    def check_code_execution_primitives(self, response: str) -> list[str]:
        """
        Scan *response* for dynamic code-execution primitives.

        Returns a (possibly empty) list of human-readable violation strings.
        Any match means the response MUST be rejected before it reaches the
        caller — even a single occurrence is sufficient grounds for rejection.
        """
        import re
        violations: list[str] = []
        for pattern, description in self._CODE_EXEC_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                violations.append(
                    f"Code-execution primitive detected in LLM output: {description}"
                )
        return violations

    async def validate(
        self,
        response: str,
        trace_id: Optional[str] = None,
    ) -> ValidationResult:
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

        # Resolve or mint a trace/correlation ID so this step can be joined
        # to upstream (e.g. request ingestion) and downstream (e.g. delivery)
        # workflow steps in any distributed tracing or SIEM system.
        resolved_trace_id = (
            trace_id
            or os.environ.get("LLM_GUARD_TRACE_ID")
            or str(uuid.uuid4())  # mint a new one when none is supplied
        )

        provenance = {
            "model_id": self.model_id,
            "generated_at": generated_at,
            "origin_tag": "llm-response-guard",
            "watermark_id": watermark_id,
            "fingerprint_sha256": fingerprint,
            "content_label": self._CONTENT_LABEL,
            "trace_id": resolved_trace_id,
        }
        # -------------------------------------------------------------------

        # ------------------------------------------------------------------
        # Check for dynamic code-execution primitives in the LLM output.
        # This MUST run before the response is used or returned in any form.
        # ------------------------------------------------------------------
        code_exec_violations = self.check_code_execution_primitives(response)
        if code_exec_violations:
            logger.warning(
                "LLM response rejected: code-execution primitives detected. "
                "violations=%r watermark_id=%s model_id=%s",
                code_exec_violations,
                watermark_id,
                self.model_id,
            )
            return ValidationResult(
                is_valid=False,
                violations=code_exec_violations,
                filtered_response=None,
                original_response=response,
                provenance=provenance,
            )

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
            "trace_id": resolved_trace_id,
            "provenance": provenance,
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
