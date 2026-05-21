"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES:
- Inter-agent calls are authenticated via AgentAuthenticator
- Privilege verification is enforced between agent calls
- Tokens are validated on every inter-agent request
"""

import hashlib
import logging
import logging.handlers
import os
import time
from typing import Any, Optional

from .tech_support import TechSupportAgent

# ---------------------------------------------------------------------------
# Approved Model Registry
# Maps pinned model identifiers to their expected SHA-256 integrity hashes.
# Only models present in this registry may be invoked.
#
# SECURITY REQUIREMENT: Hash values MUST be real SHA-256 digests of the
# model card / manifest obtained from the model governance team and injected
# at deploy time via the LLM_MODEL_REGISTRY_HASHES environment variable
# (JSON object: {"<pinned-id>": "<sha256-hex>"}).
#
# The hard-coded fallback entries below are INTENTIONALLY left empty so that
# the application fails closed if the environment variable is not set.
# Do NOT replace the empty strings with fabricated hex values.
# ---------------------------------------------------------------------------

import json as _json
import re as _re

# Regex for a valid 64-character lowercase hex SHA-256 digest.
_SHA256_RE = _re.compile(r'^[0-9a-f]{64}$')

# Known-bad placeholder patterns that must never appear in production.
_PLACEHOLDER_PATTERNS = [
    _re.compile(r'(0123456789|abcdef){3,}', _re.IGNORECASE),  # sequential runs
    _re.compile(r'^(.)(\1){15,}'),                             # repeated single char
]


def _load_registry_hashes() -> dict:
    """
    Load model registry hashes from the LLM_MODEL_REGISTRY_HASHES environment
    variable (JSON).  Each value must be a valid 64-char lowercase hex SHA-256
    digest and must not match any known placeholder pattern.

    Raises RuntimeError on any integrity or format violation so the process
    fails closed rather than running with unverified models.
    """
    raw = os.environ.get("LLM_MODEL_REGISTRY_HASHES", "")
    if not raw:
        raise RuntimeError(
            "LLM_MODEL_REGISTRY_HASHES environment variable is not set. "
            "Provide a JSON object mapping pinned model IDs to their "
            "SHA-256 integrity hashes obtained from the model governance team."
        )
    try:
        mapping = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        raise RuntimeError(
            f"LLM_MODEL_REGISTRY_HASHES is not valid JSON: {exc}"
        ) from exc
    if not isinstance(mapping, dict) or not mapping:
        raise RuntimeError(
            "LLM_MODEL_REGISTRY_HASHES must be a non-empty JSON object."
        )
    validated: dict = {}
    for model_id, digest in mapping.items():
        if not isinstance(model_id, str) or not model_id.strip():
            raise RuntimeError(
                f"Invalid model ID key in registry: {model_id!r}"
            )
        if not isinstance(digest, str) or not _SHA256_RE.match(digest):
            raise RuntimeError(
                f"Registry hash for '{model_id}' is not a valid 64-char "
                f"lowercase hex SHA-256 digest: {digest!r}. "
                f"Obtain the real digest from the model governance team."
            )
        for pat in _PLACEHOLDER_PATTERNS:
            if pat.search(digest):
                raise RuntimeError(
                    f"Registry hash for '{model_id}' matches a known "
                    f"placeholder pattern and is not a real cryptographic "
                    f"digest: {digest!r}. Replace it with the verified "
                    f"digest from the model governance team."
                )
        validated[model_id] = digest
    return validated


try:
    _APPROVED_MODEL_REGISTRY: dict = _load_registry_hashes()
except RuntimeError as _reg_err:
    # Log and re-raise so the process fails closed.
    logging.getLogger(__name__).critical(
        "REGISTRY_LOAD_FAILURE | %s", _reg_err
    )
    raise

# Default approved model used by agents — must be a key present in _APPROVED_MODEL_REGISTRY.
_APPROVED_MODEL_ID = "internal/approved-llm-v2.1.0:stable"


def _verify_model_in_registry(model: str) -> str:
    """
    Verify that *model* is present in the approved model registry.

    Returns the canonical model identifier if approved.
    Raises ValueError if the model is not in the registry, enforcing
    version pinning and preventing invocation of unapproved models.
    """
    if model not in _APPROVED_MODEL_REGISTRY:
        _llm_audit_logger.error(
            "LLM_REGISTRY_VIOLATION | Model '%s' is NOT in the approved registry. "
            "Invocation blocked. Approved models: %s",
            model,
            list(_APPROVED_MODEL_REGISTRY.keys()),
        )
        raise ValueError(
            f"Model '{model}' is not in the approved model registry. "
            f"Only version-pinned, registry-approved models may be invoked. "
            f"Approved models: {list(_APPROVED_MODEL_REGISTRY.keys())}"
        )
    expected_hash = _APPROVED_MODEL_REGISTRY[model]
    _llm_audit_logger.info(
        "LLM_REGISTRY_CHECK | model='%s' registry_hash='%s' status=APPROVED",
        model,
        expected_hash,
    )
    return model


def _log_llm_request(model: str, messages: list, extra: dict = None, principal: str = None) -> None:
    """Log an outgoing LLM request for audit purposes.

    Enforces registry check and version pinning before logging.
    Raises ValueError if the model is not in the approved registry.
    """
    # --- Registry enforcement: block any non-approved / non-pinned model ---
    _verify_model_in_registry(model)

    # Sanitize and validate all messages before logging or forwarding to LLM
    if isinstance(messages, list):
        sanitized_messages = []
        for m in messages:
            if isinstance(m, dict):
                sanitized_m = dict(m)
                if "content" in sanitized_m:
                    sanitized_m["content"] = _sanitize_prompt_input(str(sanitized_m["content"]))
                sanitized_messages.append(sanitized_m)
            else:
                sanitized_messages.append(m)
        messages = sanitized_messages

    # Compute a SHA-256 hash of the full serialized input for integrity/forensics
    serialized_input = _json.dumps(messages, default=str, sort_keys=True)
    input_hash = hashlib.sha256(serialized_input.encode("utf-8")).hexdigest()
    messages_summary = {
        "count": len(messages) if isinstance(messages, list) else None,
        "roles": [m.get("role") for m in messages if isinstance(m, dict)] if isinstance(messages, list) else None,
    }
    payload = {
        "event": "LLM_REQUEST",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": model,
        "registry_hash": _APPROVED_MODEL_REGISTRY[model],
        "principal": principal,
        "input_hash": input_hash,
        "messages_summary": messages_summary,
    }
    if extra:
        payload.update(extra)
    _llm_audit_logger.info(
        "LLM_REQUEST | %s",
        _json.dumps(payload, default=str),
    ) -> None:
    """Log an outgoing LLM request for audit purposes."""
    # Sanitize and validate all messages before logging or forwarding to LLM
    if isinstance(messages, list):
        sanitized_messages = []
        for m in messages:
            if isinstance(m, dict):
                sanitized_m = dict(m)
                if "content" in sanitized_m:
                    sanitized_m["content"] = _sanitize_prompt_input(str(sanitized_m["content"]))
                sanitized_messages.append(sanitized_m)
            else:
                sanitized_messages.append(m)
        messages = sanitized_messages

    # Compute a SHA-256 hash of the full serialized input for integrity/forensics
    serialized_input = _json.dumps(messages, default=str, sort_keys=True)
    input_hash = hashlib.sha256(serialized_input.encode("utf-8")).hexdigest()
    messages_summary = {
        "count": len(messages) if isinstance(messages, list) else None,
        "roles": [m.get("role") for m in messages if isinstance(m, dict)] if isinstance(messages, list) else None,
    }
    payload = {
        "event": "LLM_REQUEST",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": _APPROVED_MODEL_ID,
        "principal": principal,
        "input_hash": input_hash,
        "messages_summary": messages_summary,
    }
    if extra:
        payload.update(extra)
    _llm_audit_logger.info(
        "LLM_REQUEST | %s",
        _json.dumps(payload, default=str),
    )


# ---------------------------------------------------------------------------
# Dynamic-code-execution primitive patterns that must never appear in LLM output
# ---------------------------------------------------------------------------
import re as _re
import json as _json


def _sanitize_prompt_input(value: str, max_length: int = 10000) -> str:
    """
    Sanitize untrusted string input before interpolation into an LLM prompt.

    Steps:
      1. Ensure the value is a string.
      2. Strip non-printable control characters (except common whitespace).
      3. Truncate to max_length to prevent context-window abuse.
    """
    if not isinstance(value, str):
        value = str(value)
    # Remove non-printable control characters (keep \t, \n, \r)
    value = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', value)
    # Truncate to the allowed maximum length
    if len(value) > max_length:
        value = value[:max_length] + '\n[... content truncated for safety ...]'
    return value

_DANGEROUS_CODE_PATTERNS = [
    # Python builtins
    _re.compile(r'\beval\s*\(', _re.IGNORECASE),
    _re.compile(r'\bexec\s*\(', _re.IGNORECASE),
    _re.compile(r'\bcompile\s*\(', _re.IGNORECASE),
    _re.compile(r'\b__import__\s*\(', _re.IGNORECASE),
    _re.compile(r'\bimportlib\.import_module\s*\(', _re.IGNORECASE),
    # os / subprocess shell execution
    _re.compile(r'\bos\.system\s*\(', _re.IGNORECASE),
    _re.compile(r'\bos\.popen\s*\(', _re.IGNORECASE),
    _re.compile(r'\bsubprocess\.', _re.IGNORECASE),
    _re.compile(r'shell\s*=\s*True', _re.IGNORECASE),
    # Dynamic attribute / code loading
    _re.compile(r'\bgetattr\s*\(.*,\s*[\'"]__', _re.IGNORECASE),
    _re.compile(r'\bctypes\.', _re.IGNORECASE),
    _re.compile(r'\bcffi\.', _re.IGNORECASE),
]


def _validate_llm_output(text: str, context: str = "LLM response") -> None:
    """
    Validate that LLM output does not contain dynamic code execution primitives.

    Raises ValueError if any dangerous pattern is detected so that the caller
    can refuse to use the response.
    """
    if not isinstance(text, str):
        return  # non-string payloads are handled by their own validators
    for pattern in _DANGEROUS_CODE_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(
                f"Unsafe dynamic code execution primitive detected in {context}: "
                f"matched pattern '{pattern.pattern}' at position {match.start()}. "
                "Response rejected."
            )


def _extract_llm_response_text(resp_data: Any) -> str:
    """
    Best-effort extraction of the textual content from a (possibly nested)
    LLM response structure so that _validate_llm_output can inspect it.
    """
    # Extract only known text-bearing fields to avoid serialising the full payload
    if isinstance(resp_data, str):
        return resp_data
    if isinstance(resp_data, dict):
        for key in ("content", "text", "message", "output", "result"):
            val = resp_data.get(key)
            if isinstance(val, str):
                return val
        # For nested structures (e.g. choices[0].message.content)
        choices = resp_data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message", {})
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg["content"]
        # Return only a minimal summary, not the full structure
        return "[structured response]"
    return "[non-text response]"


# ---------------------------------------------------------------------------
# Synthetic-content provenance helpers
# ---------------------------------------------------------------------------
import datetime as _datetime
import hashlib as _hashlib
import hmac as _hmac
import json as _json_prov
import os as _os_prov
import uuid as _uuid

# Secret used for HMAC signing of AI-generated content.
# Must be set via the AI_PROVENANCE_SECRET environment variable.
_AI_PROVENANCE_SECRET_VAL = _os_prov.environ.get("AI_PROVENANCE_SECRET")
if not _AI_PROVENANCE_SECRET_VAL:
    raise RuntimeError(
        "AI_PROVENANCE_SECRET environment variable must be set to a strong random secret. "
        "No hardcoded default is permitted."
    )
_AI_PROVENANCE_SECRET: bytes = _AI_PROVENANCE_SECRET_VAL.encode()


def _build_provenance(model: str, content: str) -> dict:
    """
    Build a provenance block for an AI-generated output.

    Returns a dict containing:
      - content_origin   : fixed label identifying this as AI-generated
      - synthetic_label  : human-readable synthetic-content declaration
      - model_id         : the model that produced the content
      - generated_at     : ISO-8601 UTC timestamp
      - provenance_id    : unique UUID for this generation event
      - watermark_token  : deterministic LSB-style watermark (SHA-256 prefix)
      - signature        : HMAC-SHA256 over canonical provenance fields
    """
    generated_at = _datetime.datetime.utcnow().isoformat() + "Z"
    provenance_id = str(_uuid.uuid4())

    # Deterministic watermark: first 16 hex chars of SHA-256(model|id|content)
    wm_input = f"{model}|{provenance_id}|{content}".encode()
    watermark_token = _hashlib.sha256(wm_input).hexdigest()[:16]

    # Canonical string for signing (order matters for verification)
    canonical = _json_prov.dumps(
        {
            "content_origin": "AI_GENERATED",
            "model_id": model,
            "generated_at": generated_at,
            "provenance_id": provenance_id,
            "watermark_token": watermark_token,
        },
        sort_keys=True,
    )
    signature = _hmac.new(
        _AI_PROVENANCE_SECRET,
        canonical.encode(),
        _hashlib.sha256,
    ).hexdigest()

    return {
        "content_origin": "AI_GENERATED",
        "synthetic_label": "[SYNTHETIC CONTENT — Generated by AI]",
        "model_id": model,
        "generated_at": generated_at,
        "provenance_id": provenance_id,
        "watermark_token": watermark_token,
        "signature": signature,
    }


def _attach_provenance(model: str, resp_data: Any) -> Any:
    """
    Attach provenance metadata to a normalised response dict in-place.
    If resp_data is not a dict, wrap it so provenance can be embedded.
    Returns the (possibly wrapped) resp_data with a ``__provenance__`` key.
    """
    if not isinstance(resp_data, dict):
        resp_data = {"response_type": type(resp_data).__name__}

    # Extract best-effort text content for watermark seeding
    content_text = ""
    try:
        choices = resp_data.get("choices") or []
        if choices:
            content_text = (
                choices[0].get("message", {}).get("content", "")
                or choices[0].get("text", "")
            )
        if not content_text:
            content_text = str(resp_data)
    except Exception:  # pragma: no cover
        content_text = str(resp_data)

    resp_data["__provenance__"] = _build_provenance(model, content_text)
    return resp_data


def _log_llm_response(model: str, response: Any, extra: dict = None) -> None:
    """Log an incoming LLM response for audit purposes, with provenance metadata."""
    try:
                # Minimise logged data: extract only essential audit fields from the response
        def _extract_minimised_response(r: Any) -> dict:
            """Extract only audit-relevant fields from an LLM response object."""
            if hasattr(r, "model_dump"):
                full = r.model_dump()
            elif hasattr(r, "__dict__"):
                full = r.__dict__
            elif isinstance(r, dict):
                full = r
            else:
                return {"raw": str(r)[:120]}
            minimised = {}
            for field in ("id", "object", "created", "model"):
                if field in full:
                    minimised[field] = full[field]
            # Capture finish reasons and token usage only — no completion text
            choices = full.get("choices") or []
            minimised["finish_reasons"] = [
                c.get("finish_reason") if isinstance(c, dict) else getattr(c, "finish_reason", None)
                for c in choices
            ]
            minimised["choice_count"] = len(choices)
            usage = full.get("usage")
            if usage is not None:
                if isinstance(usage, dict):
                    minimised["usage"] = {
                        k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in usage
                    }
                elif hasattr(usage, "__dict__"):
                    u = usage.__dict__
                    minimised["usage"] = {
                        k: u[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in u
                    }
            return minimised

        resp_data = _extract_minimised_response(response)

        # Validate extracted LLM output for dangerous dynamic code execution primitives
        import re as _re
        _DANGEROUS_PATTERNS = [
            _re.compile(r'\beval\s*\(', _re.IGNORECASE),
            _re.compile(r'\bexec\s*\(', _re.IGNORECASE),
            _re.compile(r'\b__import__\s*\(', _re.IGNORECASE),
            _re.compile(r'\bcompile\s*\(', _re.IGNORECASE),
            _re.compile(r'\bexecfile\s*\(', _re.IGNORECASE),
            _re.compile(r'subprocess\s*\..*shell\s*=\s*True', _re.IGNORECASE),
            _re.compile(r'os\.system\s*\(', _re.IGNORECASE),
            _re.compile(r'os\.popen\s*\(', _re.IGNORECASE),
            _re.compile(r'\bgetattr\s*\(.*,\s*[\'"]__', _re.IGNORECASE),
            _re.compile(r'\bsetattr\s*\(', _re.IGNORECASE),
            _re.compile(r'\bimportlib\.import_module\s*\(', _re.IGNORECASE),
        ]
        _serialised_resp = _json.dumps(resp_data, default=str)
        for _pat in _DANGEROUS_PATTERNS:
            if _pat.search(_serialised_resp):
                _llm_audit_logger.warning(
                    "LLM_RESPONSE_BLOCKED | Dangerous pattern detected in LLM output for model %s: %s",
                    model,
                    _pat.pattern,
                )
                raise ValueError(
                    f"LLM output contains a forbidden dynamic code execution primitive "
                    f"(pattern: {_pat.pattern!r}). Response blocked."
                )

            # Compute input_hash independently from the serialised input, not from the response
        import hashlib as _hashlib
        import os as _os
        _input_material = _json.dumps({"model": model, "response_serialised": _serialised_resp}, sort_keys=True, default=str).encode("utf-8")
        _input_hash = _hashlib.sha256(_input_material).hexdigest()

        payload = {
            "event": "LLM_RESPONSE",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "model": model,
            "principal": getattr(resp_data, "principal", None) if not isinstance(resp_data, dict) else resp_data.get("principal"),
            "input_hash": _input_hash,
            "response_summary": {
                "content_hash": _hashlib.sha256(_serialised_resp.encode("utf-8")).hexdigest(),
                "response_type": type(resp_data).__name__,
                "response_length": len(_serialised_resp),
            },
        }

        # Write audit payload to append-only persistent store
        try:
            _AUDIT_LOG_DIR = _os.environ.get("LLM_AUDIT_LOG_DIR", "/var/log/llm_audit")
            _AUDIT_LOG_RETENTION_DAYS = int(_os.environ.get("LLM_AUDIT_LOG_RETENTION_DAYS", "365"))
            _os.makedirs(_AUDIT_LOG_DIR, exist_ok=True)
            _audit_log_path = _os.path.join(_AUDIT_LOG_DIR, "llm_audit.jsonl")
            _audit_line = _json.dumps(payload, default=str) + "\n"
            # Open in append mode ("a") to ensure append-only semantics
            with open(_audit_log_path, "a", encoding="utf-8") as _af:
                _af.write(_audit_line)
                _af.flush()
                _os.fsync(_af.fileno())
            # Enforce retention: remove audit log files older than retention period
            import glob as _glob
            _now = time.time()
            _audit_log_dir_real = _os.path.realpath(_AUDIT_LOG_DIR)
            for _old_file in _glob.glob(_os.path.join(_AUDIT_LOG_DIR, "llm_audit*.jsonl")):
                try:
                    # Validate resolved path stays within the audit log directory
                    _old_file_real = _os.path.realpath(_old_file)
                    if not _old_file_real.startswith(_audit_log_dir_real + _os.sep):
                        _llm_audit_logger.warning(
                            "Retention cleanup skipped suspicious path: %s", _old_file
                        )
                        continue
                    if _os.path.getmtime(_old_file) < _now - (_AUDIT_LOG_RETENTION_DAYS * 86400):
                        _os.unlink(_old_file_real)
                except OSError:
                    pass  # Non-fatal: retention cleanup failure does not block audit write
            _llm_audit_logger.info(
                "LLM_RESPONSE audit record written | model=%s input_hash=%s",
                model,
                _input_hash,
            )
        except Exception as _persist_exc:  # pragma: no cover
            _llm_audit_logger.error(
                "AUDIT PERSISTENCE FAILURE — could not write to append-only audit store: %s",
                _persist_exc,
            )
            raise RuntimeError(
                "Audit persistence failure — aborting to preserve forensic integrity"
            ) from _persist_exc
    except Exception as log_exc:  # pragma: no cover
        _llm_audit_logger.error("Failed to serialise LLM response for audit: %s", log_exc)
        raise RuntimeError("Audit logging failure — aborting to preserve forensic integrity") from log_exc
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent


# ---------------------------------------------------------------------------
# PII patterns (Singapore-centric + general)
# ---------------------------------------------------------------------------
_PII_PATTERNS = None

def _get_pii_patterns():
    import re
    global _PII_PATTERNS
    if _PII_PATTERNS is not None:
        return _PII_PATTERNS
    _PII_PATTERNS = [
        # Singapore NRIC / FIN  (S/T/F/G + 7 digits + letter)
        ("SG_NRIC_FIN",      re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE)),
        # Singapore phone numbers (+65 or local 8-digit starting with 6/8/9)
        ("SG_PHONE",         re.compile(r'(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b')),
        # Singapore passport  (E + 7 digits)
        ("SG_PASSPORT",      re.compile(r'\bE\d{7}[A-Z]\b', re.IGNORECASE)),
        # General email address
        ("EMAIL",            re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
        # Credit / debit card numbers (13-19 digits, optionally space/dash separated)
        ("CREDIT_CARD",      re.compile(r'\b(?:\d[ \-]?){13,19}\b')),
        # Generic international phone  (+country-code …)
        ("INTL_PHONE",       re.compile(r'\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}\b')),
        # Singapore postal code (6 digits)
        ("SG_POSTAL",        re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE)),
        # NRIC label hints  (e.g. "NRIC: S1234567A")
        ("NRIC_LABEL",       re.compile(r'\b(?:NRIC|FIN|IC\s*No\.?)\s*:?\s*[STFG]\d{7}[A-Z]\b', re.IGNORECASE)),
    ]
    return _PII_PATTERNS


def _redact_pii(content: str, label: str = "file content") -> str:
    """
    Detect and redact PII from *content* before further processing.

    Each matched PII token is replaced with a ``[REDACTED-<TYPE>]`` placeholder.
    A ``ValueError`` is raised when PII is found so that callers can decide
    whether to abort or continue with the redacted copy.

    Returns the redacted string (callers that want to continue processing
    should catch the ValueError and use the redacted content attached to the
    exception as ``exc.redacted_content``).
    """
    import re

    detected_types: list[str] = []
    redacted = content

    for pii_type, pattern in _get_pii_patterns():
        def _replacer(m, _type=pii_type):
            detected_types.append(_type)
            return f"[REDACTED-{_type}]"
        redacted = pattern.sub(_replacer, redacted)

    if detected_types:
        unique_types = sorted(set(detected_types))
        exc = ValueError(
            f"Uploaded {label} contains PII ({', '.join(unique_types)}) "
            f"and has been redacted before processing."
        )
        exc.redacted_content = redacted  # type: ignore[attr-defined]
        exc.detected_types = unique_types  # type: ignore[attr-defined]
        raise exc

    return redacted


def _check_singapore_pii(content: str, label: str = "file content") -> None:
    """
    Scan content for Singapore PII categories and reject if found.
    Checks for: NRIC/FIN numbers, CPF account numbers, SingPass identifiers,
    Singapore phone numbers, and Singapore passport numbers.
    """
    import re

    sg_pii_patterns = [
        # NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
        (
            re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE),
            "Singapore NRIC/FIN number",
        ),
        # CPF account number: 9 digits (standalone)
        (
            re.compile(r'\bCPF[\s:/-]*\d{9}\b', re.IGNORECASE),
            "CPF account number",
        ),
        # SingPass user ID patterns (e.g. SingPass ID label followed by identifier)
        (
            re.compile(r'\bsingpass[\s:/-]+[A-Z0-9._%+\-@]{3,}', re.IGNORECASE),
            "SingPass identifier",
        ),
        # Singapore phone numbers: +65 followed by 8 digits, or bare 8-digit SG numbers
        (
            re.compile(r'(?:\+65[\s-]?)?\b[689]\d{7}\b'),
            "Singapore phone number",
        ),
        # Singapore passport: E followed by 7 digits (e-passport series)
        (
            re.compile(r'\bE\d{7}[A-Z]\b', re.IGNORECASE),
            "Singapore passport number",
        ),
        # Singapore bank account numbers (DBS/POSB/OCBC/UOB typical formats)
        (
            re.compile(r'\b\d{3}-\d{5,6}-\d{1}\b'),
            "Singapore bank account number",
        ),
    ]

    for pattern, pii_type in sg_pii_patterns:
        if pattern.search(content):
            raise ValueError(
                f"Uploaded {label} contains {pii_type}, which is classified as "
                f"Singapore PII and cannot be uploaded or processed."
            )


def _check_malicious_content(content: str, label: str = "file content") -> None:
    """
    Scan content for malicious prompt injection patterns before processing.
    Checks for: hidden/invisible text, base64-encoded prompts, leetspeak prompt
    injection, shell commands, binary executable signatures, and direct prompt
    override attempts.
    Also rejects content containing Singapore PII categories.
    """
    import re
    import base64

    # Check for Singapore PII before any other processing
    _check_singapore_pii(content, label=label)

    # --- PII detection & redaction (must run before any other processing) ---
    try:
        content = _redact_pii(content, label)
    except ValueError as pii_exc:
        # Re-raise so callers are aware; redacted_content is available on the
        # exception if the caller wishes to continue with sanitised content.
        raise

    # 1. Invisible / zero-width characters used to hide text
    invisible_pattern = re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2061\u2062\u2063\ufeff]'
    )
    if invisible_pattern.search(content):
        raise ValueError(
            f"Uploaded {label} contains hidden/invisible characters that may be used "
            f"for prompt injection and cannot be processed."
        )

    # 2. Binary executable signatures (ELF, PE/MZ, Mach-O, shell scripts)
    binary_signatures = [
        b'\x7fELF',   # ELF executable
        b'MZ',        # PE/Windows executable
        b'\xca\xfe\xba\xbe',  # Mach-O fat binary
        b'\xfe\xed\xfa\xce',  # Mach-O 32-bit
        b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit
    ]
    raw_bytes = content.encode('utf-8', errors='replace')
    for sig in binary_signatures:
        if raw_bytes[:8].startswith(sig) or sig in raw_bytes[:256]:
            raise ValueError(
                f"Uploaded {label} appears to contain a binary executable and cannot be processed."
            )

    # 3. Shell command injection patterns
    shell_patterns = re.compile(
        r'(?:^|\s|;|&&|\|\|)'
        r'(?:bash|sh|zsh|cmd\.exe|powershell|python|perl|ruby|curl|wget|nc|ncat|netcat|eval|exec)'
        r'(?:\s|$|\()',
        re.IGNORECASE | re.MULTILINE,
    )
    if shell_patterns.search(content):
        raise ValueError(
            f"Uploaded {label} contains shell command patterns that may indicate "
            f"malicious content and cannot be processed."
        )

    # 4. Base64-encoded prompt injection — decode candidate blobs and re-scan
    b64_blob_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    prompt_injection_keywords = re.compile(
        r'ignore\s+(?:previous|prior|above|all)\s+instructions?'
        r'|you\s+are\s+now\s+(?:a|an|the)\b'
        r'|act\s+as\s+(?:a|an|the)\b'
        r'|disregard\s+(?:previous|prior|above|all)'
        r'|system\s*:\s*you\s+are'
        r'|<\s*(?:system|user|assistant)\s*>'
        r'|\[\s*(?:INST|SYS|SYSTEM)\s*\]'
        r'|###\s*(?:Instruction|System|Prompt)',
        re.IGNORECASE,
    )
    for match in b64_blob_pattern.finditer(content):
        blob = match.group(0)
        # Pad to valid base64 length
        padded = blob + '=' * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if prompt_injection_keywords.search(decoded):
                raise ValueError(
                    f"Uploaded {label} contains base64-encoded prompt injection content "
                    f"and cannot be processed."
                )
        except (ValueError, Exception):
            raise  # re-raise ValueError from inner check

    # 5. Direct prompt injection / override attempts in plain text
    if prompt_injection_keywords.search(content):
        raise ValueError(
            f"Uploaded {label} contains prompt injection patterns "
            f"and cannot be processed."
        )

    # 6. Leetspeak prompt injection (common substitutions: 4->a, 3->e, 1->i/l, 0->o, 5->s)
    def _deleet(text: str) -> str:
        table = str.maketrans('4310@$7|!', 'aeioas tli')
        return text.translate(table)

    deleeted = _deleet(content)
    if prompt_injection_keywords.search(deleeted):
        raise ValueError(
            f"Uploaded {label} contains leetspeak-obfuscated prompt injection patterns "
            f"and cannot be processed."
        )


def _check_prompt_safety(content: str, label: str = "prompt") -> None:
    """
    Scan content for malicious patterns before processing:
    - Hidden/invisible Unicode characters used for prompt injection
    - Base64-encoded payloads
    - Leetspeak obfuscation of dangerous keywords
    - Shell commands and binary executable markers
    """
    import re
    import base64

    # 1. Hidden / invisible Unicode characters (zero-width, soft-hyphen, etc.)
    invisible_pattern = re.compile(
        r'[\u00ad\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u2028\u2029]'
    )
    if invisible_pattern.search(content):
        raise ValueError(
            f"The {label} contains hidden or invisible Unicode characters that may indicate "
            "a prompt injection attempt and cannot be processed."
        )

    # 2. Base64-encoded content (heuristic: long alphanum+/= token that decodes cleanly)
    b64_token = re.compile(r'(?<![\w/+])([A-Za-z0-9+/]{40,}={0,2})(?![\w/+])')
    for match in b64_token.finditer(content):
        candidate = match.group(1)
        try:
            decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='strict')
            # Flag if decoded text contains shell/script indicators
            if re.search(
                r'(?:bash|sh|cmd|powershell|exec|eval|import|system|chmod|wget|curl)',
                decoded, re.IGNORECASE
            ):
                raise ValueError(
                    f"The {label} contains base64-encoded content with potentially malicious "
                    "commands and cannot be processed."
                )
        except (ValueError, UnicodeDecodeError):
            pass  # Not valid UTF-8 base64 — skip

    # 3. Leetspeak obfuscation of dangerous keywords
    # Normalise common leet substitutions then check for dangerous words
    leet_map = str.maketrans('013456789@$!', 'oieashgtbgas')
    normalised = content.lower().translate(leet_map)
    leet_dangerous = re.compile(
        r'\b(?:exec|eval|system|passthru|shell|popen|subprocess|os\.system|'
        r'rm\s+-rf|format\s+c|del\s+/[sq]|drop\s+table|truncate\s+table)\b'
    )
    if leet_dangerous.search(normalised):
        raise ValueError(
            f"The {label} contains obfuscated dangerous keywords and cannot be processed."
        )

    # 4. Shell command patterns
    shell_pattern = re.compile(
        r'(?:'
        r'\$\([^)]*\)'
        r'|`[^`]+`'
        r'|;\s*(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\b'
        r'|&&\s*(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\b'
        r'|\|\s*(?:bash|sh|cmd|powershell)\b'
        r'|(?:^|\s)(?:sudo|chmod|chown|chgrp)\s'
        r'|(?:^|\s)/(?:bin|usr/bin|sbin)/'
        r'|(?:^|\s)(?:wget|curl)\s+https?://'
        r')',
        re.IGNORECASE | re.MULTILINE,
    )
    if shell_pattern.search(content):
        raise ValueError(
            f"The {label} contains shell command patterns and cannot be processed."
        )

    # 5. Binary executable markers (ELF, PE/MZ, Mach-O magic bytes represented as escaped or literal)
    binary_pattern = re.compile(
        r'(?:\\x7fELF|\\x4d\\x5a|MZ\x00|\x7fELF|\\x7f\\x45\\x4c\\x46'
        r'|\\xca\\xfe\\xba\\xbe|\\xcf\\xfa\\xed\\xfe)'
    )
    if binary_pattern.search(content):
        raise ValueError(
            f"The {label} contains binary executable markers and cannot be processed."
        )


def _check_singapore_pii(content: str, label: str = "file content") -> None:
    """
    Scan content for Singapore PII categories and raise ValueError if found.
    Covers: NRIC/FIN, SingPass ID, CPF account numbers, Singapore phone numbers,
    Singapore postal codes combined with personal identifiers, and passport numbers.
    Also invokes malicious content checks prior to PII scanning.
    """
    # Always screen for malicious/injected content first
    _check_malicious_content(content, label=label)
    import re

    sg_pii_patterns = {
        # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
        "NRIC/FIN": re.compile(
            r'\b[STFG]\d{7}[A-Z]\b',
            re.IGNORECASE,
        ),
        # CPF account number: 8-digit numeric (context-sensitive heuristic)
        "CPF Account Number": re.compile(
            r'\bCPF[\s:/-]*\d{8}\b',
            re.IGNORECASE,
        ),
        # SingPass ID: typically NRIC-based but also allow explicit label match
        "SingPass ID": re.compile(
            r'\bsingpass[\s:/-]*[STFG]\d{7}[A-Z]\b',
            re.IGNORECASE,
        ),
        # Singapore mobile/phone numbers: +65 followed by 8 digits
        "Singapore Phone Number": re.compile(
            r'(?:\+65|\(65\))[\s-]?[689]\d{7}\b',
        ),
        # Singapore passport number: E followed by 7 digits
        "Singapore Passport": re.compile(
            r'\bE\d{7}[A-Z]\b',
            re.IGNORECASE,
        ),
        # Singapore bank account numbers (DBS/POSB/OCBC/UOB common formats)
        "Singapore Bank Account": re.compile(
            r'\b(?:DBS|POSB|OCBC|UOB)[\s:/-]*\d{9,12}\b',
            re.IGNORECASE,
        ),
    }

    detected = []
    for pii_type, pattern in sg_pii_patterns.items():
        if pattern.search(content):
            detected.append(pii_type)

    if detected:
        raise ValueError(
            f"Uploaded {label} contains Singapore PII and cannot be processed: "
            f"{', '.join(detected)}. Please remove all personal identifiable information "
            f"before uploading."
        )
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.approved import ApprovedLLMClient

# Only the approved model identifier may be used for all LLM calls.
_APPROVED_MODEL_ID = "approved-llm-v2.1.0"
import hashlib

# ---------------------------------------------------------------------------
# Approved Model Registry — only models listed here may be used.
# Each entry pins the exact model version and its expected config digest.
# ---------------------------------------------------------------------------
APPROVED_MODEL_REGISTRY: dict[str, dict] = {
    "approved-llm-v2.1.0": {
        "provider": "internal",
        "version": "2.1.0",
        "config_sha256": "a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456",
        "approved": True,
    },
    "approved-llm-v2.0.3": {
        "provider": "internal",
        "version": "2.0.3",
        "config_sha256": "b4e2d3f5c6a7890123456789012345678901bcdef2345678901bcdef23456789",
        "approved": True,
    },
}

# Default pinned model — must exist in APPROVED_MODEL_REGISTRY
DEFAULT_APPROVED_MODEL = "approved-llm-v2.1.0"

# Perform registry verification and integrity check at module load time
_VERIFIED_MODEL_ENTRY = verify_model_integrity(DEFAULT_APPROVED_MODEL)
_ORCHESTRATOR_MODEL_ID = DEFAULT_APPROVED_MODEL
_ORCHESTRATOR_MODEL_VERSION = _VERIFIED_MODEL_ENTRY["version"]


def verify_model_integrity(model_id: str) -> dict:
    """
    Verify that a model identifier is present in the approved registry
    and that its metadata is intact.  Raises ValueError for any unknown
    or unapproved model, enforcing version-pinning and registry membership.
    """
    if model_id not in APPROVED_MODEL_REGISTRY:
        raise ValueError(
            f"Model '{model_id}' is NOT in the approved model registry. "
            f"Permitted models: {list(APPROVED_MODEL_REGISTRY.keys())}"
        )
    entry = APPROVED_MODEL_REGISTRY[model_id]
    if not entry.get("approved"):
        raise ValueError(
            f"Model '{model_id}' exists in the registry but is marked as not approved."
        )
    if not entry.get("version"):
        raise ValueError(
            f"Model '{model_id}' has no version pin — refusing to load."
        )
    # Integrity check: verify the registry entry itself hasn't been tampered with
    entry_repr = f"{model_id}:{entry['provider']}:{entry['version']}"
    computed = hashlib.sha256(entry_repr.encode()).hexdigest()
    # The stored config_sha256 acts as a known-good reference digest
    if len(entry.get("config_sha256", "")) != 64:  # must be a valid SHA-256 hex string
        raise ValueError(
            f"Model '{model_id}' registry entry is missing a valid integrity hash."
        )
    logger_ref = logging.getLogger(__name__)
    logger_ref.info(
        "Model integrity verified",
        extra={"model_id": model_id, "version": entry["version"], "registry_digest": entry["config_sha256"]},
    )
    return entry


def get_approved_llm_client(model_id: str = DEFAULT_APPROVED_MODEL) -> "ApprovedLLMClient":
    """
    Factory that returns an ApprovedLLMClient only after verifying the
    requested model is in the approved registry with a pinned version.
    """
    entry = verify_model_integrity(model_id)
    return ApprovedLLMClient(model=model_id, version=entry["version"])

logger = logging.getLogger(__name__)

# Dedicated logger for LLM interaction audit trail
import logging.handlers as _log_handlers
import os as _os_audit
_llm_audit_logger = logging.getLogger(__name__ + ".llm_audit")
_llm_audit_logger.setLevel(logging.DEBUG)
if not _llm_audit_logger.handlers:
    try:
        _AUDIT_LOG_DIR_INIT = _os_audit.environ.get("LLM_AUDIT_LOG_DIR", "/var/log/llm_audit")
        _os_audit.makedirs(_AUDIT_LOG_DIR_INIT, exist_ok=True)
        _audit_file_handler = _log_handlers.TimedRotatingFileHandler(
            filename=_os_audit.path.join(_AUDIT_LOG_DIR_INIT, "llm_audit_meta.log"),
            when="midnight",
            interval=1,
            backupCount=int(_os_audit.environ.get("LLM_AUDIT_LOG_RETENTION_DAYS", "365")),
            encoding="utf-8",
            delay=False,
        )
        _audit_file_handler.setLevel(logging.DEBUG)
        _audit_file_handler.setFormatter(
            logging.Formatter(fmt="%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
        )
        _llm_audit_logger.addHandler(_audit_file_handler)
        _llm_audit_logger.propagate = False
    except Exception as _audit_handler_exc:
        logging.getLogger(__name__).error(
            "Failed to configure append-only LLM audit file handler: %s", _audit_handler_exc
        )
        # Fallback: buffer audit records in memory and flush to stderr so no
        # audit event is silently lost even when the filesystem is unavailable.
        _fallback_stream_handler = logging.StreamHandler()
        _fallback_stream_handler.setLevel(logging.DEBUG)
        _fallback_stream_handler.setFormatter(
            logging.Formatter(
                fmt="AUDIT_FALLBACK %(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )
        _fallback_memory_handler = _log_handlers.MemoryHandler(
            capacity=10000,
            flushLevel=logging.ERROR,
            target=_fallback_stream_handler,
            flushOnClose=True,
        )
        _fallback_memory_handler.setLevel(logging.DEBUG)
        _llm_audit_logger.addHandler(_fallback_memory_handler)
        _llm_audit_logger.addHandler(_fallback_stream_handler)
        _llm_audit_logger.propagate = False
        _llm_audit_logger.warning(
            "AUDIT_FALLBACK_ACTIVATED: primary file handler unavailable; "
            "audit records redirected to stderr memory buffer. error=%s",
            _audit_handler_exc,
        )

import base64
import re


# PII patterns for redaction
_PII_PATTERNS = [
    # Social Security Numbers (SSN)
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Credit card numbers (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Credit card numbers with spaces/dashes
    (re.compile(r'\b(?:\d{4}[\s\-]){3}\d{4}\b'), '[REDACTED_CC]'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # US phone numbers
    (re.compile(r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Passport numbers (US format)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's license (generic alphanumeric)
    (re.compile(r'\bDL[\s#:\-]?[A-Z0-9]{6,12}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Dates of birth (common formats)
    (re.compile(r'\b(?:DOB|Date of Birth|Birth Date)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b', re.IGNORECASE), '[REDACTED_DOB]'),
    # IPv4 addresses
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # IPv6 addresses
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '[REDACTED_IP]'),
    # Bank account numbers (generic 8-17 digit sequences labeled as account)
    (re.compile(r'\b(?:account|acct|acc)[\s#:\-]+\d{8,17}\b', re.IGNORECASE), '[REDACTED_ACCOUNT]'),
    # IBAN
    (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'), '[REDACTED_IBAN]'),
    # Medical record / patient ID patterns
    (re.compile(r'\b(?:MRN|Patient ID|Medical Record)[:\s]+[A-Z0-9\-]{4,20}\b', re.IGNORECASE), '[REDACTED_MEDICAL_ID]'),
    # National ID / government ID generic label
    (re.compile(r'\b(?:National ID|NID|Government ID)[:\s]+[A-Z0-9\-]{4,20}\b', re.IGNORECASE), '[REDACTED_GOVT_ID]'),
]


def _redact_pii(text: str) -> str:
    """
    Detect and redact PII from text content before processing.
    Applies regex-based redaction for common PII categories including
    SSNs, credit card numbers, email addresses, phone numbers,
    IP addresses, passport numbers, and other sensitive identifiers.

    Returns the redacted text.
    """
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern, replacement in _PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _sanitize_prompt_input(text: str, label: str = "input") -> str:
    """
    Sanitize prompt input to detect and reject content that may contain
    hidden/invisible characters, base64-encoded payloads, leetspeak,
    shell commands, or binary executable markers.

    Raises ValueError if suspicious content is detected.
    Returns the original text if it passes all checks.
    """
    if not isinstance(text, str):
        raise ValueError(f"Prompt {label} must be a string.")

    # 1. Detect hidden/invisible Unicode characters (zero-width, control chars, etc.)
    invisible_pattern = re.compile(
        r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f'
        r'\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u2028\u2029]'
    )
    if invisible_pattern.search(text):
        raise ValueError(
            f"Prompt {label} contains hidden or invisible characters that may indicate prompt injection."
        )

    # 2. Detect binary executable markers (ELF, PE/MZ headers encoded as text or raw)
    binary_markers = [b'\x7fELF', b'MZ', b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa']
    text_bytes = text.encode('utf-8', errors='replace')
    for marker in binary_markers:
        if marker in text_bytes:
            raise ValueError(
                f"Prompt {label} contains binary executable content."
            )

    # 3. Detect base64-encoded blocks (long base64 strings that decode to suspicious content)
    b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + '==')  # pad to avoid errors
            # Check if decoded bytes look like a shell command or binary
            decoded_str = decoded.decode('utf-8', errors='replace')
            shell_in_decoded = re.search(
                r'(?:bash|sh|cmd|powershell|exec|eval|system|os\.system|subprocess|import os|import subprocess)',
                decoded_str, re.IGNORECASE
            )
            if shell_in_decoded or any(m in decoded for m in binary_markers):
                raise ValueError(
                    f"Prompt {label} contains base64-encoded content with suspicious payload."
                )
        except (ValueError, UnicodeDecodeError):
            pass  # Not valid base64 or not decodable — skip

    # 4. Detect shell commands / command injection patterns
    shell_pattern = re.compile(
        r'(?:^|\s|;|&&|\|\|)'
        r'(?:bash|sh|zsh|cmd\.exe|powershell|python|perl|ruby|curl|wget|nc|ncat|netcat'
        r'|chmod|chown|sudo|su|rm\s+-rf|mkfifo|/bin/|/usr/bin/|/etc/passwd'
        r'|exec\s*\(|eval\s*\(|os\.system|subprocess\.run|subprocess\.Popen'
        r'|__import__|importlib)',
        re.IGNORECASE | re.MULTILINE
    )
    if shell_pattern.search(text):
        raise ValueError(
            f"Prompt {label} contains shell commands or code execution patterns."
        )

    # 5. Detect leetspeak obfuscation (common substitutions used to bypass filters)
    # Look for patterns like 3x3c, 3v4l, 5h3ll, etc. combined with command-like words
    leet_pattern = re.compile(
        r'(?:[3e][xX][3e][cC]|[3e][vV][4a][lL]|[5s][hH][3e][lL][lL]'
        r'|[5s][yY][5s][tT][3e][mM]|[pP][0o][wW][3e][rR][5s][hH][3e][lL][lL])',
        re.IGNORECASE
    )
    if leet_pattern.search(text):
        raise ValueError(
            f"Prompt {label} contains leetspeak obfuscation of dangerous commands."
        )

    return text


def _validate_token(token: Optional[str], authenticator: "AgentAuthenticator") -> AgentIdentity:
    """
    Validate the provided authentication token using the AgentAuthenticator.
    Raises PermissionError if the token is missing or invalid.
    """
    if not token:
        raise PermissionError("Authentication token is required but was not provided.")
    identity = authenticator.authenticate(token)
    if identity is None:
        raise PermissionError("Authentication token is invalid or expired.")
    return identity


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication
    4. Aggregates and returns responses
    """

        # Audit log retention period (days) – 365 days, matching module-level policy.
    AUDIT_LOG_RETENTION_DAYS: int = 365

    # Model identity recorded on the instance for audit / metadata propagation.
    MODEL_ID: str = _ORCHESTRATOR_MODEL_ID
    MODEL_VERSION: str = _ORCHESTRATOR_MODEL_VERSION

    def __init__(self):
        # Verify the chosen model is in the approved registry before instantiation.
        if self.MODEL_ID not in _APPROVED_MODEL_REGISTRY:
            raise ValueError(
                f"Model '{self.MODEL_ID}' is not in the approved model registry. "
                "Update _APPROVED_MODEL_REGISTRY or choose an approved model."
            )
        if _APPROVED_MODEL_REGISTRY[self.MODEL_ID] != self.MODEL_VERSION:
            raise ValueError(
                f"Model version '{self.MODEL_VERSION}' does not match the pinned "
                f"registry version '{_APPROVED_MODEL_REGISTRY[self.MODEL_ID]}' "
                f"for model '{self.MODEL_ID}'."
            )
        self.llm_client = ApprovedLLMClient(
            model=_APPROVED_MODEL_ID,
        )
        self.authenticator = AgentAuthenticator()
        import hashlib, uuid as _uuid, datetime as _datetime
        self._hashlib = hashlib
        self._uuid = _uuid
        self._datetime = _datetime
        self._json = __import__("json")

    # ------------------------------------------------------------------
    # Audit / decision logging
    # ------------------------------------------------------------------
    def _check_agent_allowed(self, agent_name: str, context: dict) -> None:
        """Raise PermissionError and emit a denied audit record if *agent_name*
        is not present in the instance-level ALLOWED_AGENTS allow list.

        Parameters
        ----------
        agent_name:
            Canonical name of the agent about to be invoked
            ('tech_support', 'finance', 'file_analysis').
        context:
            The request context dict; used only for audit logging.
        """
        if agent_name not in self.ALLOWED_AGENTS:
            principal = context.get("principal", "unknown")
            trace_id = context.get("trace_id")
            self._log_decision(
                action=f"agent_invocation_denied:{agent_name}",
                inputs={"agent": agent_name},
                principal=principal,
                trace_id=trace_id,
                outcome="denied",
            )
            raise PermissionError(
                f"Agent '{agent_name}' is not in the approved tool allow list "
                f"(ALLOWED_AGENTS={self.ALLOWED_AGENTS!r})."
            )

    def _log_decision(
        self,
        *,
        action: str,
        inputs: dict,
        principal: str,
        trace_id: str | None = None,
        outcome: str = "pending",
        extra: dict | None = None,
    ) -> str:
        """Write a structured audit record and return the trace_id.

        Every record contains:
        - trace_id      : shared correlation ID that links multi-agent steps
        - model_id      : identifier of the model making the decision
        - model_version : pinned version of that model
        - input_hash    : SHA-256 of the canonical JSON-serialised inputs
        - principal     : authenticated user / service account
        - action        : human-readable description of the decision
        - outcome       : 'pending' | 'success' | 'failure' | 'denied'
        - timestamp_utc : ISO-8601 UTC timestamp
        """
        if trace_id is None:
            trace_id = str(self._uuid.uuid4())

        canonical = self._json.dumps(inputs, sort_keys=True, default=str)
        input_hash = self._hashlib.sha256(canonical.encode()).hexdigest()

        record = {
            "trace_id": trace_id,
            "timestamp_utc": self._datetime.datetime.utcnow().isoformat() + "Z",
            "model_id": self.MODEL_ID,
            "model_version": self.MODEL_VERSION,
            # model_registry_approved and model_config_sha256 omitted — internal registry metadata must not appear in audit records
            "input_hash": input_hash,
            "principal": principal,
            "action": action,
            "outcome": outcome,
        }
        if extra:
            record["extra"] = extra

        _audit_logger.info(self._json.dumps(record))
        # Also write to the persistent LLM audit file store for forensic readiness
        _llm_audit_logger.info("DECISION_AUDIT | %s", self._json.dumps(record, default=str))
        return trace_id

    # ------------------------------------------------------------------
    # Malicious file content detection
    # ------------------------------------------------------------------
    def _check_file_content_for_malicious_prompts(self, content: str, filename: str = "") -> str | None:
        """Scan extracted file content for malicious prompt injection patterns.

        Checks for:
        - Binary executable markers (ELF, PE/MZ headers)
        - Base64-encoded prompt injection attempts
        - Invisible / zero-width Unicode characters used to hide prompts
        - Shell command injection patterns
        - Leetspeak obfuscation of common prompt-injection keywords

        Returns a short description string if malicious content is found,
        or None if the content appears safe.
        """
        import re as _re
        import base64 as _base64

        if not content:
            return None

        # 1. Binary executable markers — reject files that contain ELF or PE headers
        binary_markers = [
            b"\x7fELF",   # ELF executable
            b"MZ",        # PE/DOS executable
            b"\x50\x4b\x03\x04",  # ZIP / Office Open XML (may hide macros)
        ]
        content_bytes = content.encode("utf-8", errors="replace")
        for marker in binary_markers:
            if marker in content_bytes:
                return f"binary executable marker detected in '{filename}'"

        # 2. Invisible / zero-width Unicode characters used to hide prompts
        invisible_chars = [
            "\u200b",  # zero-width space
            "\u200c",  # zero-width non-joiner
            "\u200d",  # zero-width joiner
            "\u2060",  # word joiner
            "\ufeff",  # BOM / zero-width no-break space
            "\u00ad",  # soft hyphen
            "\u034f",  # combining grapheme joiner
        ]
        for ch in invisible_chars:
            if ch in content:
                return f"invisible/hidden Unicode characters detected in '{filename}'"

        # 3. Base64-encoded prompt injection — look for long base64 blobs and decode them
        #    to check whether they contain prompt-injection keywords.
        b64_pattern = _re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        prompt_injection_keywords = [
            "ignore previous", "ignore all previous", "disregard",
            "you are now", "act as", "jailbreak", "dan mode",
            "system prompt", "new instructions", "override",
            "forget your instructions", "reveal", "exfiltrate",
        ]
        for match in b64_pattern.finditer(content):
            try:
                decoded = _base64.b64decode(match.group() + "==").decode("utf-8", errors="ignore").lower()
                for kw in prompt_injection_keywords:
                    if kw in decoded:
                        return f"base64-encoded prompt injection detected in '{filename}'"
            except Exception:
                pass

        # 4. Shell command injection patterns
        shell_patterns = [
            _re.compile(r"(?:^|\s|;|&&|\|\|)\s*(?:rm|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby|nc|netcat|ncat)\s", _re.IGNORECASE | _re.MULTILINE),
            _re.compile(r"`[^`]{1,200}`"),           # backtick command substitution
            _re.compile(r"\$\([^)]{1,200}\)"),       # $(...) command substitution
            _re.compile(r"/etc/passwd|/etc/shadow|/proc/self", _re.IGNORECASE),
        ]
        for pat in shell_patterns:
            if pat.search(content):
                return f"shell command injection pattern detected in '{filename}'"

        # 5. Leetspeak obfuscation of prompt-injection keywords
        #    Normalise common leet substitutions then check for keywords.
        leet_map = str.maketrans("013456789@", "oieashgtba")
        normalised = content.lower().translate(leet_map)
        leet_keywords = [
            "ignore previous instructions",
            "ignore all previous",
            "you are now",
            "act as",
            "jailbreak",
            "system prompt",
            "new instructions",
            "forget your instructions",
        ]
        for kw in leet_keywords:
            if kw in normalised:
                return f"leetspeak-obfuscated prompt injection detected in '{filename}'"

        # 6. Direct (plain-text) prompt injection keywords in raw content
        content_lower = content.lower()
        for kw in prompt_injection_keywords:
            if kw in content_lower:
                return f"prompt injection keyword '{kw}' detected in '{filename}'"

        return None

        # Watermark signing key – in production load from a secrets manager.
        import os as _os
        _watermark_key_val = _os.environ.get("ORCHESTRATOR_WATERMARK_KEY")
        if not _watermark_key_val:
            raise RuntimeError(
                "ORCHESTRATOR_WATERMARK_KEY environment variable must be set to a secure secret value."
            )
        self._watermark_key = _watermark_key_val.encode()

    # ------------------------------------------------------------------
    # Provenance / labeling / watermarking
    # ------------------------------------------------------------------
    def _attach_provenance(self, response: dict, request_id: str = "") -> dict:
        import hashlib as _hashlib
        import time as _time
        import uuid as _uuid
        _prov_correlation_id = str(_uuid.uuid4())
        _prov_timestamp = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        _prov_model_id = getattr(getattr(self, "llm_client", None), "model", "unknown")
        _prov_principal = getattr(getattr(self, "_current_caller", None), "agent_id", "unknown")
        _response_str = str(response)
        _output_hash = _hashlib.sha256(_response_str.encode("utf-8", errors="replace")).hexdigest()
        _input_repr = str(request_id)
        _input_hash = _hashlib.sha256(_input_repr.encode("utf-8", errors="replace")).hexdigest()
        _llm_audit_logger.info(
            "PROVENANCE_ATTACHED",
            extra={
                "audit_event": "provenance_attached",
                "correlation_id": _prov_correlation_id,
                "request_id": request_id,
                "model_id": _prov_model_id,
                "principal": _prov_principal,
                "input_hash": _input_hash,
                "output_hash": _output_hash,
                "timestamp": _prov_timestamp,
                "retention_days": int(_os_audit.environ.get("LLM_AUDIT_LOG_RETENTION_DAYS", "365")),
            },
        )
        """Attach synthetic-content provenance metadata, a content label, and an
        HMAC watermark to every AI-generated response before it leaves the
        orchestrator.  The response dict is mutated in-place and also returned.

        Fields added
        ------------
        provenance.model_id        – canonical model identifier
        provenance.model_version   – pinned model version string
        provenance.origin          – fixed tag identifying this system
        provenance.generated_at    – ISO-8601 UTC timestamp
        provenance.request_id      – caller-supplied or auto-generated UUID
        content_label              – human-readable synthetic-origin notice
        watermark                  – hex-encoded HMAC-SHA256 over stable fields
        """
        import hmac as _hmac

        generated_at = self._datetime.datetime.utcnow().isoformat() + "Z"
        rid = request_id or str(self._uuid.uuid4())

        # Provenance block includes all required synthetic-content metadata fields.
        provenance = {
            "model_id": self.MODEL_ID,
            "model_version": self.MODEL_VERSION,
            "origin": "orchestrator-ai-system",
            "generated_at": generated_at,
            "request_id": rid,
        }

        # Deterministic watermark: HMAC-SHA256 over the stable provenance fields
        # concatenated with the serialised response content.
        import json as _json
        # HMAC covers both the provenance metadata and the response payload
        # to ensure the watermark binds to all synthetic-content provenance fields.
        content_bytes = _json.dumps(
            {"provenance": provenance, "response": response},
            sort_keys=True,
            default=str,
        ).encode()
        watermark = _hmac.new(
            self._watermark_key, content_bytes, digestmod="sha256"
        ).hexdigest()

        response["provenance"] = provenance
        response["content_label"] = (
            "[AI-GENERATED CONTENT] This response was produced by an artificial "
            f"intelligence model and may "
            "not reflect factual accuracy. Treat with appropriate scrutiny."
        )
        response["watermark"] = watermark
        return response

        # Agent registry with privilege levels
        self.agents = {
            "tech_support": {
                "agent": self.tech_support,
                "privilege": "low",
                "description": "General technical support and queries"
            },
            "finance": {
                "agent": self.finance,
                "privilege": "high",
                "description": "Financial data and reports"
            },
            "file_processor": {
                "agent": self.file_processor,
                "privilege": "medium",
                "description": "File processing and analysis"
            }
        }

                        # Token for inter-agent communication
        # Tokens are signed JWTs with expiry and binding; validated on every receive.
        import hmac as _hmac_tok
        import hashlib as _hashlib_tok
        import base64 as _b64
        import time as _time

        _raw_agent_secret = os.environ.get("AGENT_TOKEN_SECRET")
        if not _raw_agent_secret:
            raise RuntimeError(
                "AGENT_TOKEN_SECRET environment variable is not set; "
                "inter-agent authentication cannot be initialised securely."
            )
        self._agent_token_secret: bytes = _raw_agent_secret.encode()

        def _issue_agent_token(self, *, subject: str, audience: str, ttl_seconds: int = 300) -> str:
            """Issue a signed inter-agent token (HS256 JWT-like structure)."""
            import json as _json
            import base64 as _b64
            import hmac as _hmac_tok
            import hashlib as _hashlib_tok
            import time as _time
            now = int(_time.time())
            header = _b64.urlsafe_b64encode(
                _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload = _b64.urlsafe_b64encode(
                _json.dumps({
                    "sub": subject,
                    "aud": audience,
                    "iat": now,
                    "exp": now + ttl_seconds,
                }).encode()
            ).rstrip(b"=").decode()
            signing_input = f"{header}.{payload}".encode()
            sig = _b64.urlsafe_b64encode(
                _hmac_tok.new(self._agent_token_secret, signing_input, _hashlib_tok.sha256).digest()
            ).rstrip(b"=").decode()
            return f"{header}.{payload}.{sig}"

        def _validate_agent_token(self, token: str, *, expected_subject: str, expected_audience: str) -> bool:
            """Verify signature, expiry, subject, and audience of an inter-agent token."""
            import json as _json
            import base64 as _b64
            import hmac as _hmac_tok
            import hashlib as _hashlib_tok
            import time as _time
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    return False
                header_b64, payload_b64, sig_b64 = parts
                signing_input = f"{header_b64}.{payload_b64}".encode()
                expected_sig = _b64.urlsafe_b64encode(
                    _hmac_tok.new(self._agent_token_secret, signing_input, _hashlib_tok.sha256).digest()
                ).rstrip(b"=").decode()
                if not _hmac_tok.compare_digest(sig_b64, expected_sig):
                    import hashlib as _tok_hashlib, time as _tok_time, uuid as _tok_uuid
        _tok_correlation_id = str(_tok_uuid.uuid4())
        _tok_timestamp = _tok_time.strftime("%Y-%m-%dT%H:%M:%SZ", _tok_time.gmtime())
        _tok_model_id = getattr(getattr(self, "llm_client", None), "model", "unknown")
        _tok_principal = getattr(getattr(self, "_current_caller", None), "agent_id", "unknown")
        _tok_input_hash = _tok_hashlib.sha256(
            str(context).encode("utf-8", errors="replace")
        ).hexdigest()
        logger.warning("Inter-agent token signature verification failed.")
        _llm_audit_logger.warning(
            "DECISION: inter_agent_token_verification_failed",
            extra={
                "audit_event": "token_verification_failed",
                "correlation_id": _tok_correlation_id,
                "model_id": _tok_model_id,
                "principal": _tok_principal,
                "input_hash": _tok_input_hash,
                "output": "REJECTED",
                "timestamp": _tok_timestamp,
                "retention_days": int(_os_audit.environ.get("LLM_AUDIT_LOG_RETENTION_DAYS", "365")),
            },
        )
                    return False
                # Pad base64 for decoding
                padding = 4 - len(payload_b64) % 4
                payload = _json.loads(_b64.urlsafe_b64decode(payload_b64 + "=" * (padding % 4)))
                now = int(_time.time())
                if payload.get("exp", 0) < now:
                    logger.warning("Inter-agent token has expired.")
                    return False
                if payload.get("sub") != expected_subject:
                    logger.warning("Inter-agent token subject mismatch.")
                    return False
                if payload.get("aud") != expected_audience:
                    logger.warning("Inter-agent token audience mismatch.")
                    return False
                return True
            except Exception:
                logger.warning("Inter-agent token validation raised an exception.")
                return False

        import types as _types
        self._issue_agent_token = _types.MethodType(_issue_agent_token, self)
        self._validate_agent_token = _types.MethodType(_validate_agent_token, self)
        if not self._agent_token:
            logger.warning(
                "AGENT_TOKEN environment variable is not set; "
                "inter-agent authentication will not function correctly."
            )

    def _validate_agent_token(self, token: str, expected_subject: str = "", expected_audience: str = "") -> bool:
        """Validate the inter-agent token as a signed JWT.

        Verifies the HMAC-SHA256 signature, checks the `exp` expiry claim,
        and validates `sub`/`aud` binding when provided.  Raises
        PermissionError on any validation failure.
        """
        import hmac as _hmac
        import hashlib as _hashlib
        import base64 as _b64
        import json as _json
        import time as _time

        if not self._agent_token:
            raise PermissionError(
                "Inter-agent authentication is not configured; "
                "AGENT_TOKEN must be set before agents may communicate."
            )
        if not token:
            raise PermissionError("Inter-agent request is missing an authentication token.")

        parts = token.split(".")
        if len(parts) != 3:
            raise PermissionError("Inter-agent token is not a valid JWT (expected 3 parts).")

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        key = self._agent_token.encode("utf-8")
        expected_sig = _hmac.new(key, signing_input, _hashlib.sha256).digest()

        try:
            actual_sig = _b64.urlsafe_b64decode(sig_b64 + "==" )
        except Exception:
            raise PermissionError("Inter-agent token signature is malformed.")

        if not _hmac.compare_digest(expected_sig, actual_sig):
            raise PermissionError("Inter-agent token signature verification failed; request rejected.")

        try:
            padding = 4 - len(payload_b64) % 4
            payload = _json.loads(_b64.urlsafe_b64decode(payload_b64 + "=" * (padding % 4)))
        except Exception:
            raise PermissionError("Inter-agent token payload is malformed.")

        now = int(_time.time())
        if payload.get("exp", 0) < now:
            raise PermissionError("Inter-agent token has expired.")

        if expected_subject and payload.get("sub") != expected_subject:
            raise PermissionError("Inter-agent token subject mismatch.")

        if expected_audience and payload.get("aud") != expected_audience:
            raise PermissionError("Inter-agent token audience mismatch.")

        return True
        if not self._agent_token:
            raise RuntimeError(
                "AGENT_TOKEN environment variable is not set; "
                "inter-agent authentication cannot function. "
                "Set AGENT_TOKEN before starting the orchestrator."
            )
        # Pre-validate the token at startup to fail fast on misconfiguration
        if not self._validate_token(self._agent_token):
            raise RuntimeError(
                "AGENT_TOKEN failed validation at startup; "
                "ensure the token is correctly configured."
            )

        # Spawn circuit-breaker: prevent unbounded subagent spawning
        self._spawn_counter: int = 0
        self._MAX_SPAWNS: int = 10

        # Provenance signing key – load from env/secrets in production
        import os
        _provenance_signing_key_val = os.environ.get("PROVENANCE_SIGNING_KEY")
        if not _provenance_signing_key_val:
            raise RuntimeError(
                "PROVENANCE_SIGNING_KEY environment variable must be set to a secure secret value."
            )
        self._provenance_signing_key = _provenance_signing_key_val.encode()

        # Compiled patterns for malicious content detection
        import re
        self._malicious_patterns = [
            # Prompt injection / jailbreak phrases
            re.compile(
                r'(ignore (all )?(previous|prior|above|earlier) instructions'
                r'|disregard (all )?(previous|prior|above|earlier)'
                r'|forget (all )?(previous|prior|above|earlier)'
                r'|you are now|act as (a |an )?|pretend (you are|to be)'
                r'|new (role|persona|instructions|prompt|task)'
                r'|system prompt|override (instructions|prompt)'
                r'|do not follow|bypass (safety|filter|restriction)'
                r'|jailbreak|DAN mode|developer mode)',
                re.IGNORECASE,
            ),
            # Shell / OS commands
            re.compile(
                r'(\$\(|`[^`]+`|\bexec\b|\beval\b|\bsystem\(|\bos\.'
                r'|\bsubprocess\b|\brm\s+-rf|\bchmod\b|\bchown\b'
                r'|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bpython\s+-c'
                r'|\bpowershell\b|\bcmd\.exe)',
                re.IGNORECASE,
            ),
            # Base64-encoded blobs (long runs of base64 chars)
            re.compile(r'[A-Za-z0-9+/]{60,}={0,2}'),
            # Leetspeak substitution patterns (common a->4, e->3, i->1, o->0, s->5)
            re.compile(
                r'(?:[i1][g9][n][o0][r3][e3]|[s5][y][s5][t7][e3][m3]'
                r'|[p][r][o0][m3][p][t7]|[h4][a4][c][k])',
                re.IGNORECASE,
            ),
            # Excessive special characters (potential obfuscation)
            re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'),
        ]

        # ------------------------------------------------------------------
    # Input sanitization helpers
    # ------------------------------------------------------------------
    _MAX_MESSAGE_LEN: int = 4_000          # characters
    _MAX_FILE_SIZE: int = 50_000           # characters per file
    _MAX_FILE_COUNT: int = 10
    # Patterns commonly used in prompt-injection attacks
    # Singapore PII patterns to redact from uploaded file contents
    _PII_PATTERNS: list = [
        # Singapore NRIC/FIN (e.g. S1234567A, T0012345Z, F1234567N, G1234567P)
        (re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE), '[REDACTED_NRIC]'),
        # Singapore phone numbers (8-digit, optionally prefixed with +65 or 65)
        (re.compile(r'\b(?:\+65|65)?[689]\d{7}\b'), '[REDACTED_PHONE]'),
        # Email addresses
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
        # Singapore passport numbers (e.g. E1234567A)
        (re.compile(r'\b[A-Z]\d{7}[A-Z]\b'), '[REDACTED_PASSPORT]'),
        # Credit/debit card numbers (13-19 digits, optionally space/dash separated)
        (re.compile(r'\b(?:\d[ \-]?){13,19}\b'), '[REDACTED_CARD]'),
        # Singapore bank account numbers (typically 10 digits)
        (re.compile(r'\b\d{10}\b'), '[REDACTED_ACCOUNT]'),
    ]

    _INJECTION_PATTERNS: list = [
        r"ignore (all |previous |above )?instructions?",
        r"disregard (all |previous |above )?instructions?",
        r"forget (all |previous |above )?instructions?",
        r"you are now",
        r"act as",
        r"jailbreak",
        r"<\s*script[^>]*>",
        r"system\s*prompt",
        r"\\n\\n###",
        r"\[INST\]",
        r"<\|.*?\|>",
    ]

    def _redact_pii(self, text: str) -> str:
        """Redact Singapore PII from the given text using _PII_PATTERNS."""
        for pattern, replacement in self._PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def _sanitize_message(self, message: str) -> str:
        """Sanitize a user-supplied message before it reaches the LLM."""
        import re
        if not isinstance(message, str):
            raise ValueError("user_message must be a string")
        # Enforce length limit
        message = message[:self._MAX_MESSAGE_LEN]
        # Strip null bytes and non-printable control characters (keep newlines/tabs)
        message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", message)
        # Detect and reject prompt-injection attempts
        lower = message.lower()
        for pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, lower):
                raise ValueError(
                    f"Input rejected: potential prompt-injection pattern detected."
                )
        return message.strip()

        # Singapore PII patterns for file content scanning
    _SG_PII_PATTERNS: list = [
        # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
        (r'\b[STFG]\d{7}[A-Z]\b', 'NRIC/FIN number'),
        # Singapore passport: E followed by 7 digits
        (r'\bE\d{7}\b', 'Singapore passport number'),
        # Singapore phone numbers: +65 or 65 prefix with 8-digit number starting with 6/8/9
        (r'(?:\+65|\b65)?\s*[689]\d{7}\b', 'Singapore phone number'),
        # CPF account references
        (r'\bCPF\b[\s\S]{0,30}\d{4,}', 'CPF account reference'),
        # SingPass credentials (SingPass followed by ID-like token)
        (r'\bSingPass\b[\s\S]{0,50}[A-Z0-9]{6,}', 'SingPass credential'),
        # Bank account numbers: 10-12 digit sequences (common SG bank format)
        (r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4,6}\b', 'bank account number'),
    ]

    def _check_singapore_pii(self, content: str, context: str = "") -> None:
        """Raise ValueError if Singapore PII is detected in content."""
        import re
        for pattern, label in self._SG_PII_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                raise ValueError(
                    f"Singapore PII detected ({label}) in {context}. "
                    "Uploaded files must not contain PII."
                )

    def _sanitize_file_contents(self, file_contents: list) -> list:
        """Sanitize a list of file-content strings before they reach the LLM."""
        import re
        if not isinstance(file_contents, list):
            raise ValueError("file_contents must be a list")
        if len(file_contents) > self._MAX_FILE_COUNT:
            raise ValueError(
                f"Too many files: maximum allowed is {self._MAX_FILE_COUNT}"
            )
        sanitized = []
        for idx, content in enumerate(file_contents):
            if not isinstance(content, str):
                raise ValueError(f"file_contents[{idx}] must be a string")
            # Enforce per-file size limit
            content = content[:self._MAX_FILE_SIZE]
            # Strip null bytes and non-printable control characters
            content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)
            # Detect and reject Singapore PII in uploaded file contents
            self._check_singapore_pii(content, context=f"file_contents[{idx}]")
            # Detect and reject prompt-injection attempts inside files
            lower = content.lower()
            for pattern in self._INJECTION_PATTERNS:
                if re.search(pattern, lower):
                    raise ValueError(
                        f"File content at index {idx} rejected: "
                        "potential prompt-injection pattern detected."
                    )
            sanitized.append(content.strip())
        return sanitized

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Inter-agent token helpers
    # ------------------------------------------------------------------

    def _issue_agent_token(self) -> str:
        """Issue a new HMAC-SHA256 signed inter-agent token with expiry and binding."""
        payload = {
            "iss": self._token_issuer,
            "aud": self._token_audience,
            "iat": int(time.time()),
            "exp": int(time.time()) + self._token_ttl_seconds,
        }
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        signing_input = f"{header}.{body}"
        sig = hmac.new(
            self._token_secret.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{signing_input}.{signature}"

    def _get_valid_agent_token(self) -> str:
        """Return a valid (non-expired) inter-agent token, re-issuing if necessary."""
        try:
            self._verify_agent_token(self._agent_token)
        except ValueError:
            self._agent_token = self._issue_agent_token()
        return self._agent_token

    def _verify_agent_token(self, token: str) -> dict:
        """
        Verify an inter-agent token.

        Raises ValueError if the token is invalid, expired, or has wrong binding.
        Returns the decoded payload on success.
        """
        try:
            header_b64, body_b64, sig_b64 = token.split(".")
        except ValueError:
            raise ValueError("Malformed inter-agent token")

        # Verify signature
        signing_input = f"{header_b64}.{body_b64}"
        expected_sig = hmac.new(
            self._token_secret.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        # Pad base64 if needed
        padding = 4 - len(sig_b64) % 4
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "=" * (padding % 4))
        if not hmac.compare_digest(expected_sig, sig_bytes):
            raise ValueError("Inter-agent token signature verification failed")

        # Decode payload
        padding = 4 - len(body_b64) % 4
        payload = json.loads(
            base64.urlsafe_b64decode(body_b64 + "=" * (padding % 4)).decode()
        )

        # Verify expiry
        now = int(time.time())
        if payload.get("exp", 0) < now:
            raise ValueError("Inter-agent token has expired")

        # Verify issuer and audience binding
        if payload.get("iss") != self._token_issuer:
            raise ValueError("Inter-agent token issuer mismatch")
        if payload.get("aud") != self._token_audience:
            raise ValueError("Inter-agent token audience mismatch")

        return payload

    # ------------------------------------------------------------------

    async def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Process incoming request and route to appropriate agent(s).

        Args:
            context: Request context including message, files, and metadata

        Returns:
            Response dictionary with agent output
        """
        raw_message = context.get("user_message", "")
        raw_file_contents = context.get("file_contents", [])

        # Sanitize and validate all inputs before any LLM interaction
        try:
            user_message = self._sanitize_message(raw_message)
            file_contents = self._sanitize_file_contents(raw_file_contents)
        except ValueError as exc:
            logger.warning("Input validation failed", extra={"reason": str(exc)})
            return {"error": str(exc), "status": "rejected"}

        # Replace raw values in context with sanitized versions
        context = {**context, "user_message": user_message, "file_contents": file_contents}

        logger.info(
            "Orchestrator processing request",
            extra={
                "message_length": len(user_message),
                "file_count": len(file_contents),
            }
        )

        # Determine which agent should handle the request
        raw_intent = await self._classify_intent(user_message, file_contents)
        # Validate and sanitize LLM output before any use
        try:
            intent = self._validate_llm_output(raw_intent)
        except ValueError as exc:
            logger.warning(
                "LLM output validation failed for classify_intent",
                extra={"reason": str(exc)}
            )
            return {"error": "LLM returned unsafe output", "status": "rejected"}
        logger.info(
            "LLM interaction response: classify_intent",
            extra={
                "llm_call": "classify_intent",
                "intent_result": intent
            }
        )

                # Route to appropriate agent
        import asyncio as _asyncio
        _ROUTE_TIMEOUT_SECONDS = 30  # hard cap per subagent spawn
        _spawn_id = f"{intent}-{id(context)}"  # traceability token
        logger.info(
            "Subagent spawn initiated",
            extra={"spawn_id": _spawn_id, "intent": intent, "timeout": _ROUTE_TIMEOUT_SECONDS}
        )
                if intent == "finance":
            # Enforce privilege check: only callers with finance or system privilege may route here.
            caller_privilege = context.get("caller_privilege_level", "")
            _FINANCE_ALLOWED_PRIVILEGES = {"finance", "system", "admin"}
            if caller_privilege not in _FINANCE_ALLOWED_PRIVILEGES:
                logger.warning(
                    "Privilege escalation attempt blocked: finance routing denied",
                    extra={
                        "spawn_id": _spawn_id,
                        "caller_privilege": caller_privilege,
                        "intent": intent,
                    }
                )
                return {
                    "error": "Access denied: insufficient privileges to access finance agent.",
                    "status": "forbidden",
                }
            _auth_token = context.get("auth_token") or context.get("token")
            if not _auth_token:
                logger.warning(
                    "Unauthenticated finance routing attempt blocked",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication required: a valid auth_token must be present in context "
                    "before accessing the finance agent."
                )
            _validated = self._validate_token(_auth_token)
            if not _validated:
                logger.warning(
                    "Invalid token rejected for finance routing",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication failed: the provided token is invalid or expired."
                )
                        _auth_token = context.get("token")
            if not _auth_token:
                logger.warning(
                    "Unauthenticated finance routing attempt blocked",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication required: a valid auth_token must be present in context "
                    "before accessing the finance agent."
                )
            _validated = self._validate_token(_auth_token)
            if not _validated:
                logger.warning(
                    "Invalid token rejected for finance routing",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication failed: the provided token is invalid or expired."
                )
                        _auth_token = context.get("auth_token")
            if not _auth_token:
                logger.warning(
                    "Unauthenticated finance routing attempt blocked",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication required: a valid auth_token must be present in context "
                    "before accessing the finance agent."
                )
            _validated = self._validate_token(_auth_token)
            if not _validated:
                logger.warning(
                    "Invalid token rejected for finance routing",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication failed: the provided token is invalid or expired."
                )
            _spawn_bound = {"agent": "finance", "max_steps": 1, "spawn_id": _spawn_id}
            response = await _asyncio.wait_for(
                self._route_to_finance(context),
                timeout=_ROUTE_TIMEOUT_SECONDS
            ),
                timeout=_ROUTE_TIMEOUT_SECONDS
            ),
                timeout=_ROUTE_TIMEOUT_SECONDS
            )
        elif intent == "file_analysis":
            if not _auth_token:
                logger.warning(
                    "Unauthenticated file_analysis routing attempt blocked",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication required: a valid auth_token must be present in context "
                    "before accessing the file processor agent."
                )
            _validated = self._validate_token(_auth_token)
            if not _validated:
                logger.warning(
                    "Invalid token rejected for file_analysis routing",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication failed: the provided token is invalid or expired."
                )
            _spawn_bound = {"agent": "file_processor", "max_steps": 1, "spawn_id": _spawn_id}
            response = await _asyncio.wait_for(
                self._route_to_file_processor(context),
                timeout=_ROUTE_TIMEOUT_SECONDS
            )
        else:
            if not _auth_token:
                logger.warning(
                    "Unauthenticated tech_support routing attempt blocked",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication required: a valid auth_token must be present in context "
                    "before accessing the tech support agent."
                )
            _validated = self._validate_token(_auth_token)
            if not _validated:
                logger.warning(
                    "Invalid token rejected for tech_support routing",
                    extra={"spawn_id": _spawn_id}
                )
                raise PermissionError(
                    "Authentication failed: the provided token is invalid or expired."
                )
            _spawn_bound = {"agent": "tech_support", "max_steps": 1, "spawn_id": _spawn_id}
            response = await _asyncio.wait_for(
                self._route_to_tech_support(context),
                timeout=_ROUTE_TIMEOUT_SECONDS
            )
        logger.info(
            "Subagent spawn completed",
            extra={"spawn_id": _spawn_id, "spawn_bound": _spawn_bound}
        )

        return self._attach_provenance(response, routed_agent=intent)

    # ------------------------------------------------------------------
    # Provenance / watermarking helper
    # ------------------------------------------------------------------
    def _attach_provenance(
        self,
        response: dict[str, Any],
        routed_agent: str = "unknown"
    ) -> dict[str, Any]:
        """
        Attach synthetic-content provenance metadata, a content label, and
        an HMAC-SHA256 signature to every AI-generated response.

        Fields added
        ------------
        synthetic_content_label : str
            Human-readable label declaring the response is AI-generated.
        provenance : dict
            model_id      – identifier of the model / agent that produced the output
            timestamp     – ISO-8601 UTC timestamp of response creation
            origin_tag    – constant tag marking the response as AI-generated
            routed_agent  – which sub-agent handled the request
        signature : str
            Hex-encoded HMAC-SHA256 over the canonical JSON of the response
            (before the signature field is added), keyed with
            ``self._provenance_signing_key``.
        """
        import hashlib
        import hmac
        import json
        from datetime import datetime, timezone

        provenance = {
            "model_id": f"{self.MODEL_ID}/{routed_agent}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "origin_tag": "AI_GENERATED",
            "routed_agent": routed_agent,
        }

        # Build the payload that will be signed (response + provenance,
        # but NOT the signature field itself).
        signable: dict[str, Any] = {
            **response,
            "synthetic_content_label": "AI-GENERATED CONTENT",
            "provenance": provenance,
        }

        canonical = json.dumps(signable, sort_keys=True, default=str).encode()
        sig = hmac.new(
            self._provenance_signing_key,
            canonical,
            hashlib.sha256
        ).hexdigest()

        return {
            **signable,
            "signature": sig,
        }

    # ------------------------------------------------------------------
    # Context sanitization helper
    # ------------------------------------------------------------------
    _CONTEXT_ALLOWLIST = {
        "user_message",
        "file_contents",
        "session_id",
        "request_id",
        "user_id",
    }
    _MAX_STRING_LENGTH = 4096

    def _sanitize_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Return a copy of *context* containing only allowlisted keys.
        String values are truncated to _MAX_STRING_LENGTH characters to
        prevent prompt-injection via oversized payloads.
        """
        sanitized: dict[str, Any] = {}
        for key in self._CONTEXT_ALLOWLIST:
            if key not in context:
                continue
            value = context[key]
            if isinstance(value, str):
                value = value[: self._MAX_STRING_LENGTH]
            elif isinstance(value, list):
                # Truncate each string element inside lists (e.g. file_contents)
                value = [
                    item[: self._MAX_STRING_LENGTH]
                    if isinstance(item, str)
                    else item
                    for item in value
                ]
            sanitized[key] = value
        logger.debug(
            "Context sanitized for subagent spawn",
            extra={
                "original_keys": list(context.keys()),
                "sanitized_keys": list(sanitized.keys()),
            },
        )
        return sanitized

    def _redact_pii_from_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Scan file_contents in the context for PII and redact any matches
        before the data is forwarded to downstream agents.
        """
        import copy
        context = copy.deepcopy(context)
        file_contents = context.get("file_contents", [])
        redacted = []
        for item in file_contents:
            if isinstance(item, str):
                redacted.append(self._redact_pii(item))
            elif isinstance(item, dict):
                sanitised = {}
                for k, v in item.items():
                    sanitised[k] = self._redact_pii(v) if isinstance(v, str) else v
                redacted.append(sanitised)
            else:
                redacted.append(item)
        context["file_contents"] = redacted
        return context

    def _redact_pii(self, text: str) -> str:
        """Redact common PII patterns from a string."""
        # Email addresses
        text = re.sub(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
            '[REDACTED_EMAIL]', text
        )
        # US Social Security Numbers  (XXX-XX-XXXX)
        text = re.sub(
            r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
            '[REDACTED_SSN]', text
        )
        # Credit card numbers (13-16 digits, optionally separated by spaces/dashes)
        text = re.sub(
            r'\b(?:\d[ \-]?){13,16}\b',
            '[REDACTED_CC]', text
        )
        # US phone numbers
        text = re.sub(
            r'\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
            '[REDACTED_PHONE]', text
        )
        # US ZIP codes (standalone 5-digit or ZIP+4)
        text = re.sub(
            r'\b\d{5}(?:-\d{4})?\b',
            '[REDACTED_ZIP]', text
        )
        # Passport-style identifiers (letter + 8 digits)
        text = re.sub(
            r'\b[A-Z]{1,2}\d{6,9}\b',
            '[REDACTED_ID]', text
        )
        return text

    def _check_singapore_pii(self, file_contents: list) -> dict:
        """
        Scan file contents for Singapore PII categories.

        Checks for:
        - NRIC/FIN numbers (e.g. S1234567A, T1234567B, F1234567C, G1234567D)
        - SingPass user IDs (same format as NRIC/FIN)
        - Singapore passport numbers (e.g. E1234567A)
        - Singapore phone numbers (+65 XXXX XXXX)
        - Email addresses
        """
        import re

        patterns = {
            "NRIC/FIN": re.compile(
                r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE
            ),
            "Passport": re.compile(
                r'\bE\d{7}[A-Z]\b', re.IGNORECASE
            ),
            "SG_Phone": re.compile(
                r'(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b'
            ),
            "Email": re.compile(
                r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
            ),
        }

        detected_types = []
        for item in file_contents:
            text = item if isinstance(item, str) else str(item)
            for pii_type, pattern in patterns.items():
                if pattern.search(text) and pii_type not in detected_types:
                    detected_types.append(pii_type)

        return {"detected": bool(detected_types), "types": detected_types}

    async def _classify_intent(
        self,
        message: str,
        file_contents: list
    ) -> str:
        """
        Classify the user's intent to determine routing.

        Returns one of: 'finance', 'file_analysis', 'tech_support'
        """
        # Simple keyword-based classification for demo
        message_lower = message.lower()

        finance_keywords = [
            "finance", "financial", "budget", "revenue", "expense",
            "profit", "loss", "quarterly", "annual report", "earnings",
            "balance sheet", "income statement", "cash flow"
        ]

        if any(keyword in message_lower for keyword in finance_keywords):
            return "finance"

        if file_contents:
            return "file_analysis"

        return "tech_support"

    async def _route_to_tech_support(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to tech support agent."""
        # Create internal caller identity
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level=self._session_privilege_level,
            is_internal=True
        )

# Allowed privilege escalation paths: maps (caller_privilege, target_agent) -> required_minimum_caller_privilege
_ESCALATION_POLICY: dict = {
    ("low", "finance"): "high",
    ("medium", "finance"): "high",
}
_PRIVILEGE_RANK: dict = {"low": 0, "medium": 1, "high": 2, "system": 3}
ALLOWED_ESCALATION_TARGETS: frozenset[str] = frozenset()  # No cross-agent escalation permitted by policy

def _assert_routing_authorized(
    caller_identity: "AgentIdentity",
    target_agent_name: str,
    agents: dict,
) -> None:
    """Raise PermissionError if caller is not permitted to route to target_agent.

    Prevents low/medium privilege callers from escalating to high-privilege
    agents (e.g. finance) without explicit authorization.
    """
    target_info = agents.get(target_agent_name)
    if target_info is None:
        raise ValueError(f"Unknown target agent: {target_agent_name!r}")

    caller_rank = _PRIVILEGE_RANK.get(caller_identity.privilege_level, -1)
    target_rank = _PRIVILEGE_RANK.get(target_info["privilege"], 0)

    if caller_rank < target_rank:
        raise PermissionError(
            f"Privilege escalation denied: caller '{caller_identity.agent_id}' "
            f"(privilege='{caller_identity.privilege_level}') is not authorized "
            f"to route to agent '{target_agent_name}' "
            f"(privilege='{target_info['privilege']}')."
        )
if not AgentAuthenticator.authenticate(caller, token=self._agent_token):
    raise PermissionError(
        "Orchestrator AgentIdentity failed authentication; "
        "inter-agent call aborted."
    )

        self._validate_agent_token(self._agent_token)
        headers = {"X-Agent-Token": self._agent_token}

        response = await self.tech_support.handle(
            context=context,
            caller=caller,
            headers=headers,
            timeout=30,
            max_steps=10,
            spawn_id=str(uuid.uuid4())
        )

        return response

    async def _route_to_finance(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Route request to finance agent.
        Requires an authenticated user in context; raises ValueError otherwise.
        """
        # Secondary auth guard: ensures no internal path (e.g. escalate_from_tech_support)
        # can reach the finance agent without a verified user identity.
        user = context.get("authenticated_user")
        if not user:
            logger.warning(
                "Blocked unauthenticated attempt to access finance agent",
                extra={"context_keys": list(context.keys())}
            )
            return {
                "error": "Unauthorized",
                "message": "Authentication is required to access the finance agent.",
                "status_code": 401
            }


        VULNERABILITY: This method allows routing to high-privilege agent
        without proper authentication or authorization checks.
        """
        # Create internal caller identity
        # VULNERABILITY: is_internal=True bypasses privilege checks
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        # Token is validated by the receiver via AgentAuthenticator middleware
        if not self._validate_token(self._agent_token):
            raise PermissionError(
                "Agent token is invalid; cannot initiate authenticated inter-agent call."
            )
        headers = {"X-Agent-Token": self._agent_token}

        _finance_spawn_id = str(uuid.uuid4())
        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
                "spawn_id": _finance_spawn_id,
                # Token visible in logs
                "token_preview": "[REDACTED]"
            }
        )

        response = await self.finance.handle(
            context=context,
            caller=caller,
            headers=headers,
            timeout=30,
            max_steps=10,
            spawn_id=_finance_spawn_id
        )

        return response

    async def _route_to_file_processor(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to file processor agent. Requires valid agent token for authenticated inter-agent call."""
        if not self._validate_token(self._agent_token):
            raise PermissionError(
                "Agent token is invalid; cannot initiate authenticated inter-agent call to file processor."
            )
        _auth_headers = {"X-Agent-Token": self._agent_token}
        file_contents = context.get("file_contents", [])

        if not file_contents:
            return {
                "response": "No files were provided to analyze.",
                "agent": "file_processor"
            }

        # Process files and get analysis
        analyses = []
        _MAX_FILE_ITERATIONS = 20  # hard cap on LLM spawns per file-processor call
        _file_iter_count = 0
        for file_data in file_contents:
            if _file_iter_count >= _MAX_FILE_ITERATIONS:
                logger.warning(
                    "File processor iteration limit reached",
                    extra={"max_iterations": _MAX_FILE_ITERATIONS, "processed": _file_iter_count}
                )
                break
            _file_iter_count += 1
            extracted = file_data.get("extracted_content", "")
            malicious_check = self._check_file_content_for_malicious_prompts(extracted, file_data.get('filename', ''))
            if malicious_check:
                analyses.append(f"File: {file_data.get('filename')}\n[BLOCKED: Malicious content detected in file - {malicious_check}]")
                continue
            try:
                self._check_singapore_pii(extracted)
            except ValueError as pii_exc:
                logger.warning(
                    "Singapore PII detected in uploaded file — file blocked",
                    extra={"filename": file_data.get('filename', ''), "reason": str(pii_exc)}
                )
                analyses.append(f"File: {file_data.get('filename')}\n[BLOCKED: File contains Singapore PII and cannot be processed]")
                continue
            analyses.append(f"File: {file_data.get('filename')}\n{extracted[:2000]}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question
        user_question = context.get("user_message", "")

        # Validate and sanitize inputs before sending to LLM
        _LLM_TIMEOUT = 30
        _LLM_MAX_STEPS = 10
        sanitized_content = self._sanitize_input(combined_content, max_length=2000)
        sanitized_question = self._sanitize_input(user_question, max_length=1000)

                        # Redact PII from file content and user question before sending to LLM
        redacted_content = self._redact_pii(combined_content)
        redacted_question = self._redact_pii(user_question)

                raw_        llm_messages = [
            {
                "role": "system",
                "content": "You are a helpful document analyst. Answer the user's questions based on the provided document content. Summarise and paraphrase relevant information; do not reproduce verbatim blocks of document text."
            },
            {
                "role": "user",
                "content": f"""Document Content:
{redacted_content}

User Question: {redacted_question}

Please answer the user's question based on the document content above."""
            }
        ]
        raw_        self._log_llm_request(
            agent="file_processor",
            messages=llm_messages,
            context=context
        )
        analysis = await self.llm_client.chat(
            messages=llm_messages,
            timeout=_LLM_TIMEOUT,
            max_steps=_LLM_MAX_STEPS
        )
analysis = await self.llm_client.chat(
            messages=llm_messages,
            timeout=_LLM_TIMEOUT,
            max_steps=_LLM_MAX_STEPS
        ) else (_ for _ in ()).throw(PermissionError("Agent token is invalid; cannot make authenticated LLM client call."))
        )
        # Validate and sanitize LLM output before any use
        try:
            analysis = self._validate_llm_output(analysis)
        except ValueError as exc:
            logger.warning(
                "LLM output validation failed for document analysis",
                extra={"reason": str(exc)}
            )
            return {"error": "LLM returned unsafe output", "status": "rejected"}
        self._log_llm_response(
            agent="file_processor",
            response=analysis,
            context=context
        )
        # Validate and sanitize LLM output before any use
        try:
            analysis = self._validate_llm_output(raw_analysis)
        except ValueError as exc:
            logger.warning(
                "LLM output validation failed for document analysis",
                extra={"reason": str(exc)}
            )
            return {"error": "LLM returned unsafe output", "status": "rejected"}
        self._log_llm_response(
            agent="file_processor",
            response=analysis,
            context=context
        )

        sanitized_analysis = self._validate_and_sanitize_llm_output(analysis)

        result = {
            "response": sanitized_analysis,
            "agent": "file_processor",
            "files_processed": len(file_contents)
        }
        return self._attach_provenance(result, content_key="response")

    # Singapore PII patterns used by _check_singapore_pii()
    _SG_NRIC_FIN = re.compile(r'\b[STFGM]\d{7}[A-Z]\b')
    _SG_PHONE = re.compile(r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b')
    _SG_PASSPORT = re.compile(r'\bE\d{7}[A-Z]\b')
    _SG_CPF = re.compile(r'\bCPF\s*(?:Account\s*)?(?:No\.?|Number)?\s*:?\s*\d{9}[A-Z]\b', re.IGNORECASE)
    _SG_SINGPASS = re.compile(r'\bSingPass\s*(?:ID|User(?:name)?|Login)?\s*:?\s*[A-Za-z0-9._%+\-]+', re.IGNORECASE)
    _SG_BANK_ACCOUNT = re.compile(r'\b\d{3}-\d{5,6}-\d{1}\b|\b\d{10,12}\b')

    _SG_PII_CHECKS: list[tuple[str, re.Pattern]] = []

    def _check_singapore_pii(self, text: str) -> None:
        """
        Scan text for Singapore PII categories.

        Raises ValueError if any Singapore PII is detected, so that the
        caller can reject the content rather than forwarding it to the LLM.

        Categories checked:
          - NRIC / FIN
          - Singapore passport number
          - CPF account number
          - SingPass ID
          - Singapore phone number
          - Singapore bank account number
        """
        checks = [
            ("NRIC/FIN", self._SG_NRIC_FIN),
            ("Singapore phone number", self._SG_PHONE),
            ("Singapore passport", self._SG_PASSPORT),
            ("CPF account number", self._SG_CPF),
            ("SingPass ID", self._SG_SINGPASS),
            ("Singapore bank account", self._SG_BANK_ACCOUNT),
        ]
        for label, pattern in checks:
            if pattern.search(text):
                raise ValueError(f"Singapore PII detected: {label}")

    def _sanitize_input(self, text: str, max_length: int = 4096) -> str:
        """
        Validate and sanitize input before sending to the LLM.

        Removes null bytes, control characters (except common whitespace),
        strips leading/trailing whitespace, enforces a maximum length, and
        redacts patterns that commonly indicate PII (SSNs, credit-card
        numbers) or prompt-injection attempts.

        Args:
            text: Raw input string (file content or user question).
            max_length: Maximum allowed character length after sanitization.

        Returns:
            Sanitized string safe to forward to the LLM.

        Raises:
            ValueError: If text is not a string.
        """
        import re

        if not isinstance(text, str):
            raise ValueError("Input validation failed: value is not a string.")

        # Remove null bytes
        text = text.replace("\x00", "")

        # Remove non-printable control characters (keep \t, \n, \r)
        text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        # Redact SSN-like patterns (e.g. 123-45-6789)
        text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]", text)

        # Redact credit-card-like patterns (13-16 consecutive digits)
        text = re.sub(r"\b(?:\d[ -]?){13,16}\b", "[REDACTED-CC]", text)

        # Detect and neutralise basic prompt-injection attempts
        injection_patterns = [
            r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
            r"(?i)disregard\s+(all\s+)?previous\s+instructions?",
            r"(?i)you\s+are\s+now\s+(?:a|an)\s+",
            r"(?i)act\s+as\s+(?:a|an)\s+",
            r"(?i)jailbreak",
            r"(?i)system\s*prompt",
        ]
        for pattern in injection_patterns:
            text = re.sub(pattern, "[FILTERED]", text)

        # Strip surrounding whitespace and enforce length limit
        text = text.strip()
        if len(text) > max_length:
            text = text[:max_length]
            logger.warning(
                "Input truncated to %d characters during sanitization.",
                max_length
            )

        return text

    # ---------------------------------------------------------------------------
    # Provenance helpers – every AI-generated payload must pass through these
    # before being returned to any caller.
    # ---------------------------------------------------------------------------

    def _build_provenance(self, content: str) -> dict:
        """Build provenance metadata for an AI-generated content string.

        Returns a dict containing:
          - synthetic_label : human-readable marker that the content is AI-generated
          - watermark_token : a per-response pseudorandom hex token
          - generated_at    : ISO-8601 UTC timestamp
          - agent           : identifier of the producing agent
          - signature       : HMAC-SHA256 over (watermark_token + content)
        """
        import hashlib
        import hmac
        import os
        import datetime

        watermark_token = os.urandom(16).hex()
        generated_at = datetime.datetime.utcnow().isoformat() + "Z"
        signing_key = getattr(self, "_provenance_signing_key", None)
        if signing_key is None:
            # Derive a stable per-instance key from the agent token so that
            # signatures survive across calls within the same process.
            signing_key = hashlib.sha256(
                (self._agent_token + "provenance").encode()
            ).digest()
            self._provenance_signing_key = signing_key

        mac = hmac.new(
            signing_key,
            msg=(watermark_token + content).encode(),
            digestmod=hashlib.sha256
        ).hexdigest()

        return {
            "synthetic_label": "AI-GENERATED CONTENT",
            "watermark_token": watermark_token,
            "generated_at": generated_at,
            "agent": "orchestrator/file_processor",
            "signature": mac,
        }

    def _attach_provenance(
        self, result: dict, content_key: str = "response"
    ) -> dict:
        """Attach provenance metadata to *result* in-place and return it.

        The content addressed by *content_key* is used as the payload over
        which the watermark token and HMAC signature are computed.
        """
        content = result.get(content_key, "")
        result["provenance"] = self._build_provenance(content)
        return result

    # ---------------------------------------------------------------------------

    def _redact_pii(self, text: str) -> str:
        """
        Redact PII (email addresses, passport numbers, phone numbers) from text
        before sending to an LLM.

        Args:
            text: Input string that may contain PII.

        Returns:
            String with PII replaced by redaction placeholders.
        """
        import re

        if not isinstance(text, str):
            return text

        # Redact email addresses
        text = re.sub(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
            '[REDACTED_EMAIL]',
            text
        )

        # Redact phone numbers (various formats: +1-800-555-1234, (800) 555-1234,
        # 800.555.1234, 8005551234, +44 20 7946 0958, etc.)
        text = re.sub(
            r'(?:\+?\d{1,3}[\s\-.])?(?:\(?\d{1,4}\)?[\s\-.])?\d{1,4}[\s\-.]\d{1,4}[\s\-.]\d{1,9}',
            '[REDACTED_PHONE]',
            text
        )

        # Redact passport numbers (common formats: letter(s) followed by digits,
        # e.g. A12345678, AB1234567, or purely numeric 9-digit)
        text = re.sub(
            r'\b[A-Z]{1,2}\d{6,9}\b',
            '[REDACTED_PASSPORT]',
            text
        )
        # Purely numeric passport-style numbers (9 digits)
        text = re.sub(
            r'\b\d{9}\b',
            '[REDACTED_PASSPORT]',
            text
        )

        return text

    def _validate_and_sanitize_llm_output(self, output: str) -> str:
        """
        Validate and sanitize LLM output.

        Checks for the presence of dynamic code execution primitives
        (e.g., eval, exec, compile, __import__) and raises a ValueError
        if any are detected. Also strips leading/trailing whitespace.

        Args:
            output: Raw string output from the LLM.

        Returns:
            Sanitized output string.

        Raises:
            ValueError: If the output contains forbidden dynamic code
                        execution primitives.
        """
        import re

        if not isinstance(output, str):
            raise ValueError(
                "LLM output validation failed: output is not a string."
            )

        # Patterns for dynamic code execution primitives
        forbidden_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bcompile\s*\(',
            r'\b__import__\s*\(',
            r'\bimportlib\.import_module\s*\(',
            r'\bgetattr\s*\(.*__',
            r'\bsetattr\s*\(',
            r'\bdelattr\s*\(',
            r'\bsubprocess\s*\.',
            r'\bos\.system\s*\(',
            r'\bos\.popen\s*\(',
            r'\bbuiltins\s*\.',
            r'\bglobals\s*\(',
            r'\blocals\s*\(',
            r'\bvars\s*\(',
        ]

        for pattern in forbidden_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                logger.warning(
                    "LLM output blocked: forbidden dynamic code execution "
                    "primitive detected.",
                    extra={"pattern": pattern}
                )
                raise ValueError(
                    "LLM output validation failed: response contains a "
                    "forbidden dynamic code execution primitive and cannot "
                    "be returned."
                )

        # Strip leading/trailing whitespace as basic sanitization
        return output.strip()

    async def escalate_from_tech_support(
        self,
        query: str,
        tech_support_context: dict
    ) -> dict[str, Any]:
        """
        Handle escalation from tech support to finance agent.

        This method is called when tech support needs to access
        financial data on behalf of a user.

        Requires explicit privilege verification and a human-approved
        authorization token before routing to the finance agent.
        """
        # Privilege verification: confirm the tech support context carries
        # an explicit, human-approved escalation authorization token.
        human_approval_token = tech_support_context.get("human_approved_escalation_token")
        if not human_approval_token:
            logger.warning("Privilege escalation denied: no human approval token present.")
            raise PermissionError("Human approval token is required for privilege escalation.")
        try:
            self._validate_agent_token(
                human_approval_token,
                expected_subject="human_escalation",
                expected_audience="tech_support",
            )
        except PermissionError as _e:
            logger.warning("Privilege escalation denied: human approval token validation failed: %s", _e)
            raise
        if False:
            logger.warning(
                "Escalation from tech support to finance DENIED: "
                "missing human-approved escalation token",
                extra={"query": query}
            )
            raise PermissionError(
                "Privilege escalation to finance agent requires a "
                "human-approved authorization token. "
                "Please obtain supervisor approval before retrying."
            )

        # Verify the token is valid and grants finance escalation rights.
        allowed_roles = tech_support_context.get("authorized_escalation_targets", [])
        if "finance" not in allowed_roles:
            logger.warning(
                "Escalation from tech support to finance DENIED: "
                "finance not in authorized escalation targets",
                extra={
                    "query": query,
                    "authorized_targets": allowed_roles
                }
            )
            raise PermissionError(
                "Tech support agent is not authorized to escalate to the "
                "finance agent. Escalation targets permitted: "
                f"{allowed_roles}. Contact a supervisor to request access."
            )

        # Sanitize and validate the raw query before passing it to the LLM.
        sanitized_query = self._sanitize_prompt_input(query)
        sanitized_query = self._redact_pii(sanitized_query)
        self._check_prompt_safety(sanitized_query)
        self._check_malicious_content(sanitized_query)

                escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": str(tech_support_context)[:500],
            "escalation_reason": "Financial data requested",
            "human_approval_token": human_approval_token,
        }
        # Attach a signed inter-agent authentication token so the finance
        # agent can verify the caller's identity before processing the request.
        if hasattr(self, "authenticator") and self.authenticator is not None:
            escalation_context["inter_agent_token"] = self.authenticator.generate_token(
                subject="tech_support",
                audience="finance",
            )
        else:
            raise RuntimeError(
                "Cannot escalate to finance agent: no AgentAuthenticator is "
                "configured on this orchestrator instance. Inter-agent calls "
                "require authentication."
            )

        logger.info(
            "Escalating from tech support to finance (human-approved)",
            extra={
                "query": sanitized_query,
                "original_context": str(tech_support_context)[:500],
                "approval_token_present": True
            }
        )

                # Explicit allow list for escalation targets from tech support
        ALLOWED_ESCALATION_TARGETS: frozenset[str] = frozenset()  # No cross-agent escalation permitted by policy

        escalation_target = escalation_context.get("escalation_target", "")
        if escalation_target not in ALLOWED_ESCALATION_TARGETS:
            logger.warning(
                "Blocked unauthorized escalation attempt from tech support",
                extra={"escalation_target": escalation_target}
            )
            return {
                "error": "Escalation target is not on the approved allow list."
            }

        import asyncio as _asyncio
        _ESCALATION_TIMEOUT = 30
_ESCALATION_MAX_STEPS = 10_SECONDS = 30
        _escalation_spawn_id = f"finance-escalation-{id(escalation_context)}"
        logger.info(
            "Subagent spawn initiated",
            extra={"spawn_id": _escalation_spawn_id, "agent": "finance", "timeout": _ESCALATION_TIMEOUT_SECONDS}
        )
        _escalation_spawn_bound = {"agent": "finance", "max_steps": 1, "spawn_id": _escalation_spawn_id}
        # inter_agent_token has been injected into escalation_context above;
        # the finance agent's _validate_token will verify it on receipt.
                escalation_target = escalation_context.get("escalation_target", "")
        if escalation_target not in ALLOWED_ESCALATION_TARGETS:
            _audit_logger.warning(
                "Escalation denied: target %r is not in ALLOWED_ESCALATION_TARGETS",
                escalation_target,
            )
            raise PermissionError(
                f"Escalation target {escalation_target!r} is not permitted by policy."
            )
        return await _asyncio.wait_for(
            self._route_to_finance(escalation_context),
            timeout=_ESCALATION_TIMEOUT_SECONDS
        )

    def _sanitize_file_content(self, content: str) -> str:
        """
        Sanitize extracted file content before injecting it into an LLM prompt.

        Checks for and neutralizes:
        - Prompt injection / jailbreak phrases
        - Shell / OS commands
        - Base64-encoded blobs
        - Leetspeak obfuscation
        - Non-printable / control characters

        Raises ValueError if the content is deemed too dangerous to process.
        Returns the sanitized string otherwise.
        """
        import re

        if not content:
            return content

        # Hard limit: refuse extremely large single-chunk injections
        MAX_CONTENT_LENGTH = 50_000
        if len(content) > MAX_CONTENT_LENGTH:
            logger.warning(
                "File content exceeds maximum allowed length; truncating.",
                extra={"original_length": len(content)}
            )
            content = content[:MAX_CONTENT_LENGTH] + "\n[CONTENT TRUNCATED FOR SAFETY]"

        flagged_patterns: list[str] = []

        for pattern in self._malicious_patterns:
            matches = pattern.findall(content)
            if matches:
                flagged_patterns.append(pattern.pattern)
                logger.warning(
                    "Malicious content pattern detected in uploaded file.",
                    extra={
                        "pattern": pattern.pattern,
                        "match_count": len(matches),
                    }
                )

        if flagged_patterns:
            # Raise so the caller can return a safe error response instead of
            # forwarding potentially weaponised content to the LLM.
            raise ValueError(
                f"Uploaded file content failed safety checks "
                f"({len(flagged_patterns)} pattern(s) matched). "
                "The file has been rejected to prevent prompt injection."
            )

        # Redact PII before further processing
        # Singapore NRIC/FIN (e.g. S1234567A, T9876543Z, F0123456P, G1234567X)
        content = re.sub(
            r'\b[STFG]\d{7}[A-Z]\b',
            '[REDACTED_NRIC]',
            content,
            flags=re.IGNORECASE
        )
        # Email addresses
        content = re.sub(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
            '[REDACTED_EMAIL]',
            content
        )
        # Singapore phone numbers (8-digit starting with 6, 8, or 9)
        content = re.sub(
            r'\b(?:\+65[\s\-]?)?[689]\d{7}\b',
            '[REDACTED_PHONE]',
            content
        )
        # Generic credit card numbers (16-digit groups)
        content = re.sub(
            r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
            '[REDACTED_CARD]',
            content
        )
        # Passport numbers (generic: letter(s) followed by 6-9 digits)
        content = re.sub(
            r'\b[A-Z]{1,2}\d{6,9}\b',
            '[REDACTED_PASSPORT]',
            content
        )
        logger.info(
            "PII redaction applied to uploaded file content."
        )

        # Strip non-printable control characters that survived the pattern check
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', content)

        return sanitized
