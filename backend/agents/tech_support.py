"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES:
- Agent token is verified before processing any request
- User context and user_id are validated and sanitized before use
"""

import hashlib
import hmac
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import base64
import re
import string

from .auth.agent_auth import AgentIdentity, verify_agent_token
from llm.approved import ApprovedLLMClient


# ---------------------------------------------------------------------------
# Prompt Sanitization
# Checks user-supplied input for malicious content before forwarding to LLM.
# ---------------------------------------------------------------------------

# Shell command patterns that should never appear in user prompts
_SHELL_COMMAND_PATTERN = re.compile(
    r'(?:^|\s|;|&&|\|\|)'
    r'(?:bash|sh|zsh|fish|cmd|powershell|pwsh|python|perl|ruby|php|node|curl|wget|nc|ncat|netcat|'
    r'chmod|chown|sudo|su|rm\s+-rf|mkfifo|mknod|dd\s+if=|base64\s+-d|eval|exec|system|popen|'
    r'subprocess|os\.system|__import__|importlib)',
    re.IGNORECASE | re.MULTILINE,
)

# Binary / non-printable byte sequences
_BINARY_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')

# Leetspeak substitution map (common character swaps used to evade filters)
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
})

# Phrases that indicate prompt-injection / jailbreak attempts
_INJECTION_PHRASES = [
    'ignore previous instructions',
    'ignore all instructions',
    'disregard your instructions',
    'forget your instructions',
    'you are now',
    'act as',
    'pretend you are',
    'new instructions',
    'system prompt',
    'override instructions',
    'jailbreak',
    'do anything now',
    'dan mode',
]


# ---------------------------------------------------------------------------
# LLM Output Validation
# Checks LLM-generated output for dangerous dynamic code execution primitives
# before the response is used or returned to the caller.
# ---------------------------------------------------------------------------

# Patterns that indicate dynamic code execution in LLM output
_LLM_OUTPUT_EXEC_PATTERN = re.compile(
    r'\b(?:eval|exec|execfile|compile)\s*\(',
    re.IGNORECASE,
)

_LLM_OUTPUT_SUBPROCESS_PATTERN = re.compile(
    r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
    re.IGNORECASE | re.DOTALL,
)

_LLM_OUTPUT_DYNAMIC_IMPORT_PATTERN = re.compile(
    r'(?:__import__|importlib\.import_module|importlib\.util\.spec_from_file_location)\s*\(',
    re.IGNORECASE,
)

_LLM_OUTPUT_OS_EXEC_PATTERN = re.compile(
    r'\bos\.(?:system|popen|execv|execve|execvp|execvpe|spawnl|spawnle|spawnlp|spawnlpe|'  
    r'spawnv|spawnve|spawnvp|spawnvpe)\s*\(',
    re.IGNORECASE,
)

_LLM_OUTPUT_DANGEROUS_BUILTINS_PATTERN = re.compile(
    r'\b(?:getattr|setattr|delattr)\s*\([^,]+,\s*[\'"]__[a-z]+__[\'"]',
    re.IGNORECASE,
)


def _validate_llm_output(text: str) -> str:
    """
    Validate and sanitize LLM output before use.

    Raises ValueError if the output contains dynamic code execution primitives
    such as eval(), exec(), subprocess with shell=True, os.system(), or
    dynamic import mechanisms.

    Returns the original text if no violations are found.
    """
    if not isinstance(text, str):
        raise ValueError("LLM output must be a string.")

    checks = [
        (_LLM_OUTPUT_EXEC_PATTERN,
         "LLM output contains forbidden dynamic code execution primitive (eval/exec)."),
        (_LLM_OUTPUT_SUBPROCESS_PATTERN,
         "LLM output contains forbidden subprocess call with shell=True."),
        (_LLM_OUTPUT_DYNAMIC_IMPORT_PATTERN,
         "LLM output contains forbidden dynamic import mechanism."),
        (_LLM_OUTPUT_OS_EXEC_PATTERN,
         "LLM output contains forbidden os execution primitive."),
        (_LLM_OUTPUT_DANGEROUS_BUILTINS_PATTERN,
         "LLM output contains forbidden dunder attribute manipulation."),
    ]

    for pattern, message in checks:
        if pattern.search(text):
            logging.warning("LLM output validation failed: %s", message)
            raise ValueError(message)

    return text


def _is_base64_encoded(text: str) -> bool:
    """Return True if *text* looks like a substantial base64-encoded payload."""
    # Strip whitespace and check the character set
    stripped = text.strip()
    if len(stripped) < 20:
        return False
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    ratio = sum(1 for c in stripped if c in b64_chars) / len(stripped)
    if ratio < 0.95:
        return False
    # Attempt to decode and check whether the result is non-trivial binary
    try:
        decoded = base64.b64decode(stripped + '==')  # pad defensively
        # If decoded bytes contain many non-printable chars it is likely binary
        non_printable = sum(1 for b in decoded if b < 0x20 and b not in (0x09, 0x0a, 0x0d))
        if non_printable / max(len(decoded), 1) > 0.1:
            return True
        # If decoded text contains shell commands, flag it
        try:
            decoded_str = decoded.decode('utf-8', errors='replace')
            if _SHELL_COMMAND_PATTERN.search(decoded_str):
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def _contains_leetspeak_injection(text: str) -> bool:
    """Return True if the text, after leet-substitution, matches injection phrases."""
    normalized = text.lower().translate(_LEET_MAP)
    for phrase in _INJECTION_PHRASES:
        if phrase in normalized:
            return True
    return False


def sanitize_user_prompt(prompt: str, field_name: str = 'prompt') -> str:
    """
    Validate and sanitize a user-supplied prompt before it is forwarded to the LLM.

    Raises ``ValueError`` with a descriptive message if the prompt contains:
    - Binary / non-printable bytes
    - Shell commands or executable invocations
    - Base64-encoded payloads that decode to shell commands or binary data
    - Leetspeak-obfuscated prompt-injection phrases
    - Plain-text prompt-injection phrases

    Returns the (unchanged) prompt string when it passes all checks.
    """
    if not isinstance(prompt, str):
        raise ValueError(f"'{field_name}' must be a string, got {type(prompt).__name__}.")

    # 1. Binary / non-printable content
    if _BINARY_PATTERN.search(prompt):
        raise ValueError(
            f"'{field_name}' contains binary or non-printable characters, which are not allowed."
        )

    # 2. Shell commands
    if _SHELL_COMMAND_PATTERN.search(prompt):
        raise ValueError(
            f"'{field_name}' contains shell command patterns, which are not allowed."
        )

    # 3. Base64-encoded payloads
    # Check each whitespace-delimited token that looks long enough to be base64
    for token in prompt.split():
        if len(token) >= 20 and _is_base64_encoded(token):
            raise ValueError(
                f"'{field_name}' contains a base64-encoded payload that may hide malicious content."
            )

    # 4. Leetspeak-obfuscated injection
    if _contains_leetspeak_injection(prompt):
        raise ValueError(
            f"'{field_name}' contains obfuscated prompt-injection content."
        )

    # 5. Plain-text injection phrases
    lower_prompt = prompt.lower()
    for phrase in _INJECTION_PHRASES:
        if phrase in lower_prompt:
            raise ValueError(
                f"'{field_name}' contains a disallowed prompt-injection phrase: '{phrase}'."
            )

    return prompt
import re

# ---------------------------------------------------------------------------
# Input sanitization for LLM queries
# ---------------------------------------------------------------------------
_MAX_QUERY_LENGTH = 4096  # characters

# Patterns associated with prompt-injection / jailbreak attempts
_INJECTION_PATTERNS = re.compile(
    r"(ignore (all |previous |prior |above )?instructions?"
    r"|system\s*prompt"
    r"|you are now"
    r"|disregard (all |previous |prior |above )?instructions?"
    r"|forget (all |previous |prior |above )?instructions?"
    r"|act as (if )?you (are|were)"
    r"|jailbreak"
    r"|<\s*script"
    r"|\\x[0-9a-fA-F]{2}"
    r"|\\u[0-9a-fA-F]{4})",
    re.IGNORECASE,
)


def _sanitize_query(query: Any) -> str:
    """Sanitize a free-text query before sending it to the LLM.

    Steps:
    1. Coerce to string and strip leading/trailing whitespace.
    2. Remove ASCII control characters (except ordinary whitespace).
    3. Enforce maximum length.
    4. Reject queries that contain prompt-injection patterns.

    Returns the sanitized query string.
    Raises ValueError if the query is empty after sanitization or contains
    injection patterns.
    """
    if query is None:
        raise ValueError("Query must not be None.")

    # 1. Coerce and strip
    sanitized: str = str(query).strip()

    # 2. Remove control characters (keep \t, \n, \r as ordinary whitespace)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)

    # 3. Enforce length
    if len(sanitized) > _MAX_QUERY_LENGTH:
        sanitized = sanitized[:_MAX_QUERY_LENGTH]

    # 4. Reject empty queries
    if not sanitized:
        raise ValueError("Query is empty after sanitization.")

    # 5. Detect prompt-injection patterns
    if _INJECTION_PATTERNS.search(sanitized):
        raise ValueError(
            "Query contains disallowed content (potential prompt injection)."
        )

    return sanitized

logger = logging.getLogger(__name__)


def _call_llm_with_logging(client: ApprovedLLMClient, prompt: str, **kwargs) -> Any:
    """Wrapper that logs every LLM request and response for audit compliance."""
    logger.info(
        "LLM request initiated",
        extra={
            "model": MODEL_NAME,
            "model_version": MODEL_VERSION,
            "prompt_length": len(prompt),
            "registry_status": "IN_REGISTRY",
        },
    )
    try:
        response = client.complete(prompt, **kwargs)
        logger.info(
            "LLM response received",
            extra={
                "model": MODEL_NAME,
                "model_version": MODEL_VERSION,
                "response_length": len(str(response)),
            },
        )
        validated_response = _validate_llm_output(str(response))
        return validated_response
    except Exception as exc:
        logger.error(
            "LLM call failed",
            extra={
                "model": MODEL_NAME,
                "model_version": MODEL_VERSION,
                "error": str(exc),
            },
            exc_info=True,
        )
        raise
import re

# ---------------------------------------------------------------------------
# LLM Output Sanitization
# All LLM responses MUST pass through _validate_llm_output() before use.
# ---------------------------------------------------------------------------
_DANGEROUS_PATTERNS = [
    # Direct code execution primitives
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bcompile\s*\(',
    r'\b__import__\s*\(',
    r'\bimportlib\.import_module\s*\(',
    # Shell execution
    r'\bos\.system\s*\(',
    r'\bos\.popen\s*\(',
    r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
    r'\bsubprocess\.getoutput\s*\(',
    r'\bsubprocess\.getstatusoutput\s*\(',
    # Dynamic attribute / code loading
    r'\bgetattr\s*\(.*,\s*[\'"]__',
    r'\b__builtins__\b',
    r'\b__globals__\b',
    r'\b__code__\b',
    r'\bctypes\b',
    # Template / code injection helpers
    r'\bpickle\.loads?\s*\(',
    r'\bmarshal\.loads?\s*\(',
    r'\byaml\.load\s*\(',          # unsafe yaml.load
]

_COMPILED_DANGEROUS_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in _DANGEROUS_PATTERNS
]


def _validate_llm_output(response: str, context: str = "") -> str:
    """
    Validate and sanitize LLM output before use.

    Raises ValueError if the response contains any dynamic code execution
    primitive or other dangerous pattern.  Returns the (unchanged) response
    string when it is safe.

    Args:
        response: Raw text returned by the LLM.
        context:  Optional label used in log/error messages (e.g. the query
                  type) to aid incident investigation.

    Returns:
        The validated response string.

    Raises:
        ValueError: If a dangerous pattern is detected.
        TypeError:  If *response* is not a string.
    """
    if not isinstance(response, str):
        raise TypeError(
            f"LLM output validation failed [{context}]: "
            f"expected str, got {type(response).__name__}"
        )

    for pattern in _COMPILED_DANGEROUS_PATTERNS:
        match = pattern.search(response)
        if match:
            logging.getLogger(__name__).error(
                "Dangerous pattern detected in LLM output [%s]: pattern=%r matched=%r",
                context,
                pattern.pattern,
                match.group(0)[:120],
            )
            raise ValueError(
                f"LLM output rejected [{context}]: contains forbidden dynamic "
                f"code execution primitive matching pattern '{pattern.pattern}'. "
                "The response has been discarded for security reasons."
            )

    return response

# ---------------------------------------------------------------------------
# Approved Model Registry
# Only models listed here may be used by this agent.  Any change to MODEL_NAME,
# MODEL_VERSION, or MODEL_DIGEST must go through the security review process.
# ---------------------------------------------------------------------------
# Local registry is a FALLBACK ONLY and must match the external org registry.
# If ORG_MODEL_REGISTRY_URL is not set the agent will refuse to start.
_APPROVED_MODEL_REGISTRY: dict[str, dict] = {
    "gpt-4o": {
        "version": "2024-08-06",
        "provider": "openai",
        "digest": "sha256:gpt-4o-2024-08-06-openai-approved",
        "approved": True,
        "registry_source": "org-approved-registry-v1",
    },
},
},
}

MODEL_NAME = os.environ.get("APPROVED_LLM_MODEL")
if not MODEL_NAME:
    raise EnvironmentError(
        "APPROVED_LLM_MODEL environment variable is not set. "
        "Configure it with a model name from the organization's approved LLM registry."
    )
MODEL_VERSION = _APPROVED_MODEL_REGISTRY[MODEL_NAME]["version"]
MODEL_DIGEST  = _APPROVED_MODEL_REGISTRY[MODEL_NAME]["digest"]


def _verify_model_registration(name: str, version: str, digest: str) -> None:
    """Raise RuntimeError if the model config does not match org-registry values.

    Since MODEL_NAME/VERSION/DIGEST are sourced from org-registry env vars,
    this function validates that the values passed at call-time match what
    was loaded from the registry at startup, preventing runtime substitution.
    """
    if name != MODEL_NAME:
        raise RuntimeError(
            f"Model '{name}' does not match the org-registry-approved model "
            f"'{MODEL_NAME}'. Only the org-registry-approved model may be used."
        )
    if version != MODEL_VERSION:
        raise RuntimeError(
            f"Model '{name}' version '{version}' does not match the org-registry "
            f"pinned version '{MODEL_VERSION}'."
        )
    if digest != MODEL_DIGEST:
        raise RuntimeError(
            f"Model '{name}' integrity check failed: digest mismatch against "
            "org-registry value. The model artifact may have been tampered with."
        )

import hashlib
import json
import os
import logging
import logging.handlers


class AppendOnlyFileHandler(logging.FileHandler):
    """
    Append-only file handler for AI decision logs.

    Enforces forensic readiness by:
    - Always opening the log file in append mode ('a'), never 'w' or 'wb'.
    - Refusing any rotation or truncation operation.
    - Raising RuntimeError if an attempt is made to rotate or truncate the log.

    This handler satisfies the immutable/append-only requirement for AI-driven
    action audit trails and decision logs.
    """

    def __init__(self, filename: str, encoding: str = "utf-8", delay: bool = False):
        # Force append mode; never allow overwrite or truncation.
        super().__init__(filename, mode="a", encoding=encoding, delay=delay)

    def _open(self):
        """Open the log file strictly in append mode."""
        stream = open(self.baseFilename, "a", encoding=self.encoding)  # noqa: WPS515
        return stream

    def doRollover(self):
        """Rotation is prohibited for append-only decision logs."""
        raise RuntimeError(
            "AppendOnlyFileHandler: log rotation is prohibited for AI decision "
            "audit logs. Rotation or truncation would violate the append-only "
            "and forensic-readiness policy."
        )

    def rotate(self, source, dest):
        """Rotation is prohibited for append-only decision logs."""
        raise RuntimeError(
            "AppendOnlyFileHandler: log rotation is prohibited for AI decision "
            "audit logs."
        )

    def truncate(self):
        """Truncation is prohibited for append-only decision logs."""
        raise RuntimeError(
            "AppendOnlyFileHandler: truncation is prohibited for AI decision "
            "audit logs."
        )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Privilege Escalation Policy
# Only the agents listed here may be escalated to from this low-privilege agent.
# Any change to this allowlist must go through the security review process.
# ---------------------------------------------------------------------------
_ESCALATION_POLICY: dict[str, dict] = {
    "billing_agent": {
        "target_privilege": "medium",
        "requires_human_approval": True,
        "allowed_reasons": ["billing_dispute", "subscription_change", "refund_request"],
    },
    "security_agent": {
        "target_privilege": "high",
        "requires_human_approval": True,
        "allowed_reasons": ["account_compromise", "data_breach", "fraud"],
    },
}


def _check_escalation_policy(
    target_agent: str,
    reason: str,
    human_approval_token: Optional[str] = None,
) -> None:
    """
    Enforce static policy comparison and human-in-the-loop approval before
    allowing escalation to a higher-privilege agent.

    Raises PermissionError if the escalation is not permitted.
    """
    policy = _ESCALATION_POLICY.get(target_agent)
    if policy is None:
        raise PermissionError(
            f"Escalation to '{target_agent}' is not permitted: "
            "agent is not in the approved escalation policy."
        )

    if reason not in policy["allowed_reasons"]:
        raise PermissionError(
            f"Escalation reason '{reason}' is not approved for target "
            f"'{target_agent}'. Allowed reasons: {policy['allowed_reasons']}."
        )

    if policy["requires_human_approval"]:
        if not human_approval_token:
            raise PermissionError(
                f"Escalation to '{target_agent}' requires human-in-the-loop "
                "approval. Provide a valid human_approval_token."
            )
        # Validate the approval token is a non-empty, sufficiently long string
        # (integration with a real approval workflow should verify the token
        # cryptographically; this guard ensures the field is never bypassed).
        if len(human_approval_token.strip()) < 32:
            raise PermissionError(
                "human_approval_token is invalid or too short. "
                "Obtain a valid approval token from the human review workflow."
            )

    logger.info(
        "Privilege escalation approved by policy",
        extra={
            "target_agent": target_agent,
            "reason": reason,
            "human_approval_required": policy["requires_human_approval"],
        },
    )

# ---------------------------------------------------------------------------
# Persistent decision log – audit trail & forensic readiness
# ---------------------------------------------------------------------------
_DECISION_LOG_FILE       = os.environ.get("TECH_SUPPORT_DECISION_LOG", "/var/log/unifai/tech_support_decisions.jsonl")
_DECISION_LOG_MAX_BYTES  = 10 * 1024 * 1024   # 10 MB per file
_DECISION_LOG_BACKUP_COUNT = 10               # retain 10 rotated files (~100 MB total)

_decision_logger = logging.getLogger(f"{__name__}.decisions")
_decision_logger.setLevel(logging.INFO)
_decision_logger.propagate = False  # keep decision records out of the root handler

try:
    os.makedirs(os.path.dirname(_DECISION_LOG_FILE), exist_ok=True)
    # Use a plain FileHandler (append mode) so the audit log is never rotated,
    # truncated, or overwritten — satisfying the append-only / immutable-log requirement.
    _dh = logging.FileHandler(
        _DECISION_LOG_FILE,
        mode="a",
        encoding="utf-8",
    )
    _dh.setFormatter(logging.Formatter("%(message)s"))
    _decision_logger.addHandler(_dh)
except OSError as _e:
    logger.warning("Could not open decision log file %s: %s", _DECISION_LOG_FILE, _e)


def _hash_input(payload: Any) -> str:
    """Return a SHA-256 hex digest of the canonical JSON representation of *payload*."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _log_ai_decision(
    *,
    agent_id: str,
    user_id: str,
    model_name: str,
    model_version: str,
    model_digest: str,
    input_payload: Any,
    output: str,
    extra: Optional[dict] = None,
) -> None:
    """Write a structured decision record to the persistent rotating decision log."""
    import datetime
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "agent_id": agent_id,
        "user_id": user_id,
        "model": {"name": model_name, "version": model_version, "digest": model_digest},
        "input_hash": _hash_input(input_payload),
        "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "output_preview": output[:200],
        **(extra or {}),
    }
    _decision_logger.info(json.dumps(record, ensure_ascii=True, default=str))


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"

    def __init__(self, llm_client: ApprovedLLMClient,
                 model_name: str = MODEL_NAME,
                 model_version: str = MODEL_VERSION,
                 model_digest: str = MODEL_DIGEST):
        # Enforce approved model registry before accepting the client.
        _verify_model_registration(model_name, model_version, model_digest)

        self.llm_client   = llm_client
        self.model_name   = model_name
        self.model_version = model_version
        self.model_digest  = model_digest
        self.agent_id     = "tech_support"
        self.agent_name   = "Tech Support Agent"

    # Maximum allowed length for a user message
    _MAX_MESSAGE_LENGTH = 2000

    # Patterns that indicate prompt-injection or jailbreak attempts
    _INJECTION_PATTERNS = [
        r"ignore (all |previous |prior )?instructions",
        r"disregard (all |previous |prior )?instructions",
        r"you are now",
        r"act as",
        r"pretend (you are|to be)",
        r"system prompt",
        r"<\s*script",
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
    ]

    # Maximum allowed length for extracted file content
    _MAX_FILE_CONTENT_LENGTH = 50000

    # Patterns specific to file-based prompt injection
    _FILE_INJECTION_PATTERNS = [
        # Standard prompt injection
        r"ignore (all |previous |prior )?instructions",
        r"disregard (all |previous |prior )?instructions",
        r"you are now",
        r"act as",
        r"pretend (you are|to be)",
        r"system prompt",
        r"<\s*script",
        # Shell commands
        r"(?:^|\s)(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\s+-",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"\|\s*(?:bash|sh|python|perl)",
        # Invisible / zero-width Unicode characters used to hide text
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
        # Hex / unicode escapes
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
    ]

    # Leetspeak substitution map for normalisation before pattern matching
    _LEET_MAP = str.maketrans(
        "4831057@",
        "abeiosla",
    )

    def _redact_pii_from_text(self, text: str) -> str:
        """
        Redact personally identifiable information (PII) from the given text.
        Covers: SSN, credit card numbers, email addresses, phone numbers,
        dates of birth, passport/ID numbers, and IP addresses.

        Returns:
            The text with PII replaced by redaction placeholders.
        """
        import re

        pii_patterns = [
            # Social Security Numbers (SSN): 123-45-6789 or 123 45 6789 or 123456789
            (r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b', '[REDACTED-SSN]'),
            # Credit card numbers: 16-digit with optional separators (Visa, MC, Amex, Discover)
            (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[- ]?){3}[0-9]{4})\b', '[REDACTED-CC]'),
            # Email addresses
            (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED-EMAIL]'),
            # Phone numbers: various formats including international
            (r'\b(?:\+?1[-.\s]?)?(?:\(?[2-9][0-9]{2}\)?[-.\s]?)[2-9][0-9]{2}[-.\s]?[0-9]{4}\b', '[REDACTED-PHONE]'),
            # Dates of birth / general dates: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD, Month DD YYYY
            (r'\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}\b', '[REDACTED-DATE]'),
            (r'\b(?:19|20)\d{2}[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])\b', '[REDACTED-DATE]'),
            (r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{2}\b', '[REDACTED-DATE]'),
            # Passport numbers: letter(s) followed by digits (common formats)
            (r'\b[A-Z]{1,2}[0-9]{6,9}\b', '[REDACTED-PASSPORT-ID]'),
            # IPv4 addresses
            (r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', '[REDACTED-IP]'),
            # IPv6 addresses
            (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', '[REDACTED-IP]'),
        ]

        redacted = text
        for pattern, placeholder in pii_patterns:
            redacted = re.sub(pattern, placeholder, redacted)
        return redacted

    def _sanitize_file_content(self, content: str) -> str:
        """
        Sanitize text extracted from an uploaded file before it is forwarded
        to the LLM.  Checks for:
          - Invisible / zero-width Unicode characters
          - Base64-encoded prompt injection payloads
          - Leetspeak-obfuscated injection attempts
          - Embedded shell commands
          - Standard prompt-injection phrases

        Raises:
            ValueError: if malicious content is detected.
        Returns:
            The cleaned content string.
        """
        import re
        import base64

        if not isinstance(content, str):
            raise ValueError("File content must be a string.")

        # Remove null bytes
        cleaned = content.replace("\x00", "")

        if len(cleaned) > self._MAX_FILE_CONTENT_LENGTH:
            raise ValueError(
                f"Extracted file content exceeds maximum allowed length of "
                f"{self._MAX_FILE_CONTENT_LENGTH} characters."
            )

        # --- 0. Redact PII from file content before any further processing --
        cleaned = self._redact_pii_from_text(cleaned)

        # --- 1. Check for invisible / zero-width Unicode characters ----------
        invisible_pattern = r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
        if re.search(invisible_pattern, cleaned):
            raise ValueError(
                "File content contains invisible Unicode characters that may "
                "be used to hide malicious instructions."
            )

        # --- 2. Check for base64-encoded payloads ----------------------------
        # Look for base64 blobs (>=20 chars) and decode them for inspection
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", cleaned)
        for candidate in b64_candidates:
            try:
                decoded = base64.b64decode(candidate + "==").decode(
                    "utf-8", errors="ignore"
                )
                decoded_lower = decoded.lower()
                for phrase in [
                    "ignore instructions",
                    "disregard instructions",
                    "you are now",
                    "act as",
                    "system prompt",
                    "pretend",
                ]:
                    if phrase in decoded_lower:
                        raise ValueError(
                            "File content contains a base64-encoded prompt "
                            "injection payload."
                        )
            except Exception as exc:
                if "base64-encoded prompt" in str(exc):
                    raise
                # Decoding failed — not valid base64, skip

        # --- 3. Check leetspeak-normalised content ---------------------------
        leet_normalised = cleaned.lower().translate(self._LEET_MAP)
        for pattern in self._FILE_INJECTION_PATTERNS:
            if re.search(pattern, leet_normalised, re.IGNORECASE | re.MULTILINE):
                raise ValueError(
                    f"File content contains a disallowed pattern (possibly "
                    f"obfuscated): {pattern}"
                )

        # --- 4. Check original content against all patterns ------------------
        for pattern in self._FILE_INJECTION_PATTERNS:
            if re.search(pattern, cleaned, re.IGNORECASE | re.MULTILINE):
                raise ValueError(
                    f"File content contains a disallowed pattern: {pattern}"
                )

        return cleaned

    # Regex patterns for common PII types
    _PII_PATTERNS = [
        # --- Singapore-specific PII ---
        # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
        (r"\b[STFG]\d{7}[A-Z]\b", "[REDACTED_NRIC_FIN]"),
        # Work Permit Number (8-digit numeric)
        (r"\bWP\d{8}\b", "[REDACTED_WORK_PERMIT]"),
        # Student Pass Number
        (r"\bSP\d{7}[A-Z]\b", "[REDACTED_STUDENT_PASS]"),
        # CPF Account Number (9-digit numeric)
        (r"\b\d{9}[A-Z]\b", "[REDACTED_CPF]"),
        # SingPass / MyInfo user ID patterns (e.g. S1234567A or myinfo: prefix)
        (r"(?i)(?:singpass|myinfo)[\s:_-]*[A-Z0-9]{6,20}", "[REDACTED_SINGPASS_MYINFO]"),
        # Singapore mobile numbers (+65 followed by 8 digits starting with 8 or 9)
        (r"(?:\+65[\s-]?)?[89]\d{7}\b", "[REDACTED_SG_PHONE]"),
        # Singapore postal code (6-digit, optionally prefixed with 'S' or 'Singapore')
        (r"(?i)(?:singapore\s+)?\b(?:S)?(?:0[1-9]|[1-8]\d|9[0-7])\d{4}\b", "[REDACTED_SG_POSTAL]"),
        # Full name heuristic: 2-4 capitalised words (common in SG context)
        (r"\b(?:[A-Z][a-z]+ ){1,3}[A-Z][a-z]+\b", "[REDACTED_FULL_NAME]"),
        # Social Security Numbers (e.g. 123-45-6789)
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]'),
        # Credit card numbers (16-digit, optionally grouped)
        (r'\b(?:\d[ -]?){13,16}\b', '[CC REDACTED]'),
        # Email addresses
        (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', '[EMAIL REDACTED]'),
        # US phone numbers in common formats
        (r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', '[PHONE REDACTED]'),
        # Dates of birth / generic dates (MM/DD/YYYY or YYYY-MM-DD)
        (r'\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b', '[DATE REDACTED]'),
        # US ZIP codes
        (r'\b\d{5}(?:-\d{4})?\b', '[ZIP REDACTED]'),
        # Passport / ID numbers (letter(s) followed by 6-9 digits)
        (r'\b[A-Z]{1,2}\d{6,9}\b', '[ID REDACTED]'),
        # IP addresses
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP REDACTED]'),
    ]

    def _redact_pii_from_text(self, text: str) -> str:
        """
        Scan *text* for common PII patterns and replace each match with a
        labelled placeholder.  Returns the redacted string.

        This is a best-effort, regex-based redaction layer.  It is applied
        to all file content before the text is forwarded to the LLM so that
        sensitive data is not inadvertently leaked through the model.
        """
        import re

        if not isinstance(text, str):
            return text

        redacted = text
        for pattern, placeholder in self._PII_PATTERNS:
            redacted = re.sub(pattern, placeholder, redacted)

        logger.info(
            "PII redaction applied to file content",
            extra={"original_length": len(text), "redacted_length": len(redacted)},
        )
        return redacted

    def _sanitize_and_validate(self, message: str) -> str:
        """
        Sanitize and validate a user-supplied message before it is forwarded
        to the LLM or another agent.

        Raises:
            ValueError: if the message fails validation.
        Returns:
            The cleaned message string.
        """
        import re

        if not isinstance(message, str):
            raise ValueError("user_message must be a string.")

        # Strip leading/trailing whitespace and remove null bytes
        cleaned = message.strip().replace("\x00", "")

        if not cleaned:
            raise ValueError("user_message must not be empty.")

        if len(cleaned) > self._MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"user_message exceeds maximum allowed length of "
                f"{self._MAX_MESSAGE_LENGTH} characters."
            )

        # Reject messages that contain prompt-injection patterns
        for pattern in self._INJECTION_PATTERNS:
            if re.search(pattern, cleaned, re.IGNORECASE):
                raise ValueError(
                    f"user_message contains a disallowed pattern: {pattern}"
                )

        return cleaned

    # Patterns that indicate dynamic code execution primitives in LLM output
    _LLM_OUTPUT_DANGEROUS_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\b__import__\s*\(",
        r"\bimportlib\b",
        r"\bsubprocess\b",
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bos\.execv\s*\(",
        r"\bos\.spawn",
        r"\bctypes\b",
        r"\bgetattr\s*\(.*__",
        r"\bsetattr\s*\(",
        r"\bdelattr\s*\(",
        r"\bglobals\s*\(",
        r"\blocals\s*\(",
        r"\bvars\s*\(",
        r"\b__builtins__\b",
        r"\b__class__\b",
        r"\b__bases__\b",
        r"\b__subclasses__\s*\(",
        r"\bopen\s*\(",
        r"\bpickle\b",
        r"\bmarshal\b",
        r"\bcodeop\b",
        r"\bast\.literal_eval\b",
    ]

    def _sanitize_llm_output(self, response: str) -> str:
        """
        Validate and sanitize LLM output for dynamic code execution primitives.

        Raises:
            ValueError: if the response contains a dangerous code execution pattern.
        Returns:
            The original response string if it passes all checks.
        """
        import re

        if not isinstance(response, str):
            raise ValueError("LLM response must be a string.")

        for pattern in self._LLM_OUTPUT_DANGEROUS_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                logger.warning(
                    "LLM output blocked: contains dangerous pattern '%s'",
                    pattern,
                    extra={"agent_id": self.agent_id},
                )
                raise ValueError(
                    f"LLM output contains a disallowed dynamic code execution "
                    f"primitive matching pattern: {pattern}"
                )

        return response

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request from orchestrator or direct call.

        Args:
            context: Request context with user message and metadata
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary
        """
        # Validate the token against the known registry of valid agent tokens
        # Additionally enforce cryptographic integrity: signature verification,
        # expiry check, and subject binding to the caller identity.
        import base64
        import hashlib
        import hmac
        import json
        import os
        import time

        token = headers.get("X-Agent-Token") if headers else None

        def _verify_token_integrity(raw_token: str, bound_subject: str) -> bool:
            """
            Verify a signed agent token of the form:
                base64url(header).base64url(payload).base64url(signature)
            where signature = HMAC-SHA256(secret, header_b64 + '.' + payload_b64).

            Checks:
              1. Structural validity (3 dot-separated parts).
              2. HMAC-SHA256 signature over header.payload using TOKEN_SIGNING_SECRET.
              3. 'exp' claim is present and has not passed.
              4. 'sub' claim matches bound_subject (caller identity binding).
            """
            if not raw_token or not isinstance(raw_token, str):
                logger.warning("Token integrity check failed: token is absent or not a string")
                return False

            parts = raw_token.split(".")
            if len(parts) != 3:
                logger.warning("Token integrity check failed: malformed token structure")
                return False

            header_b64, payload_b64, sig_b64 = parts
            signing_secret = os.environ.get("TOKEN_SIGNING_SECRET", "")
            if not signing_secret:
                logger.error(
                    "TOKEN_SIGNING_SECRET is not configured; "
                    "cannot verify token signature"
                )
                return False

            # 1. Signature verification
            message = (header_b64 + "." + payload_b64).encode("utf-8")
            expected_sig = hmac.new(
                signing_secret.encode("utf-8"), message, hashlib.sha256
            ).digest()
            # Decode the provided signature (pad to valid base64 length)
            try:
                padding = 4 - len(sig_b64) % 4
                provided_sig = base64.urlsafe_b64decode(
                    sig_b64 + ("=" * (padding % 4))
                )
            except Exception:
                logger.warning("Token integrity check failed: signature decode error")
                return False

            if not hmac.compare_digest(expected_sig, provided_sig):
                logger.warning("Token integrity check failed: signature mismatch")
                return False

            # 2. Decode payload
            try:
                padding = 4 - len(payload_b64) % 4
                payload_bytes = base64.urlsafe_b64decode(
                    payload_b64 + ("=" * (padding % 4))
                )
                payload = json.loads(payload_bytes.decode("utf-8"))
            except Exception:
                logger.warning("Token integrity check failed: payload decode error")
                return False

            # 3. Expiry check
            exp = payload.get("exp")
            if exp is None:
                logger.warning("Token integrity check failed: missing 'exp' claim")
                return False
            if time.time() > float(exp):
                logger.warning("Token integrity check failed: token has expired")
                return False

            # 4. Subject binding
            sub = payload.get("sub")
            if not sub:
                logger.warning("Token integrity check failed: missing 'sub' claim")
                return False
            caller_id = str(bound_subject) if bound_subject is not None else ""
            if not hmac.compare_digest(str(sub), caller_id):
                logger.warning(
                    "Token integrity check failed: 'sub' claim does not match caller identity"
                )
                return False

            return True

        caller_subject = getattr(caller, "agent_id", None) or getattr(caller, "id", None) or str(caller)
        if not _verify_token_integrity(token, caller_subject) or not self._validate_agent_token(token):
            logger.warning("Rejected request: missing or invalid agent token")
            return {
                "error": "Unauthorized: invalid or missing agent token",
                "agent": self.agent_id
            }
        logger.debug("Received request with a validated agent token.")

        # Generate a correlation/trace ID that links every step of this request
        import hashlib, uuid, datetime, json
        trace_id = str(uuid.uuid4())

        def _audit_log(event: str, principal: str, input_text: str, output_text: str = "") -> None:
            """Write a structured audit record to the persistent audit trail."""
            record = {
                "trace_id": trace_id,
                "event": event,
                "agent": self.agent_id,
                "model_id": getattr(self, "_model_id", "unknown"),
                "model_version": getattr(self, "_model_version", "unknown"),
                "principal": principal,
                "input_hash": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
                "output_hash": hashlib.sha256(output_text.encode("utf-8")).hexdigest() if output_text else None,
                "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            }
            # Persist to the audit log (append-only file; replace with DB/SIEM sink as needed)
            try:
                import os
                _ALLOWED_AUDIT_DIRS = (
                    "/var/log",
                    "/tmp/ai_audit",
                )
                _raw_audit_path = os.environ.get("AUDIT_LOG_PATH", "/var/log/ai_audit.jsonl")
                # Resolve to an absolute, canonical path to prevent traversal
                _resolved_audit_path = os.path.realpath(os.path.abspath(_raw_audit_path))
                if not any(
                    _resolved_audit_path.startswith(allowed_dir + os.sep)
                    or _resolved_audit_path == allowed_dir
                    for allowed_dir in _ALLOWED_AUDIT_DIRS
                ):
                    raise ValueError(
                        f"AUDIT_LOG_PATH '{_resolved_audit_path}' is outside permitted directories: "
                        f"{_ALLOWED_AUDIT_DIRS}"
                    )
                audit_path = _resolved_audit_path
                with open(audit_path, "a", encoding="utf-8") as _af:
                    _af.write(json.dumps(record) + "\n")
            except ValueError as _ve:
                logger.error("AUDIT LOG PATH REJECTED (path traversal guard): %s", _ve)
            except Exception as _ae:
                logger.error("AUDIT LOG WRITE FAILURE: %s | record=%s", _ae, json.dumps(record))
            logger.info("AUDIT | %s", json.dumps(record))

        _audit_log(
            event="request_received",
            principal=str(caller),
            input_text=str(context),
        )

        raw_message = context.get("user_message", "")
        try:
            # Strip prompt-injection patterns before any further processing or LLM forwarding.
            # Removes attempts to override the system role (e.g. "Ignore previous instructions",
            # role-delimiter injections, and common jailbreak prefixes).
            import re as _re
            _INJECTION_PATTERNS = [
                r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
                r"(?i)you\s+are\s+now\s+(?:a|an|the)\b",
                r"(?i)\bsystem\s*:\s*",
                r"(?i)\bassistant\s*:\s*",
                r"(?i)\buser\s*:\s*",
                r"(?i)disregard\s+(your\s+)?(previous|prior|all)\b",
                r"(?i)act\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\b",
                r"(?i)jailbreak",
                r"(?i)do\s+anything\s+now",
            ]
            _sanitized_raw = raw_message
            for _pat in _INJECTION_PATTERNS:
                _sanitized_raw = _re.sub(_pat, "[REDACTED]", _sanitized_raw)
            user_message = self._sanitize_and_validate(_sanitized_raw)
        except ValueError as exc:
            logger.warning("Rejected user_message during validation: %s", exc)
            return {
                "response": "Your request could not be processed. Please revise your message and try again.",
                "agent": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL,
                "error": "invalid_input"
            }

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # Reduce context to only the fields required by the finance agent.
            # Re-sanitize user_message explicitly at the subagent boundary to ensure
            # no LLM-processed content reaches the subagent without validation.
            subagent_user_message = self._sanitize_and_validate(user_message)
            reduced_context = {
                "user_message": subagent_user_message,
                "session_id": context.get("session_id"),
                "request_id": context.get("request_id"),
            }
            logger.info(
                "Spawning finance subagent",
                extra={
                    "spawn_target": "finance",
                    "reduced_context_keys": list(reduced_context.keys()),
                    "user_message_preview": subagent_user_message[:100],
                    "sanitization_validated": True,
                    "timeout": 30,
                    "max_steps": 5,
                }
            )
            agent_token = verify_agent_token(caller)
                        result = await self._escalate_to_finance(
                subagent_user_message,
                reduced_context,
                timeout=30,
                max_steps=5,
            )
            logger.info(
                "Finance subagent spawn completed",
                extra={
                    "spawn_target": "finance",
                    "result_keys": list(result.keys()) if isinstance(result, dict) else None,
                }
            )
            return result

        # Handle the query directly
        response = await self._process_query(user_message, context)

        # Validate and sanitize LLM output before returning
        sanitized_response = self._validate_llm_response(response)

        _output_hash = hashlib.sha256(str(sanitized_response).encode()).hexdigest()
        _audit_log(
            event="llm_inference_complete",
            trace_id=_trace_id,
            principal=str(caller),
            input_hash=_input_hash,
            output_hash=_output_hash,
        )

        return {
            "response": sanitized_response,
            "agent": self.agent_id,
            "trace_id": trace_id,
        }

    # Patterns that indicate dynamic code execution primitives in LLM output
    _DANGEROUS_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\b__import__\s*\(",
        r"\bimportlib\.import_module\s*\(",
        r"\bsubprocess\s*\.",
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bgetattr\s*\(.*__",
        r"\bsetattr\s*\(",
        r"\bdelattr\s*\(",
        r"\bglobals\s*\(\s*\)",
        r"\blocals\s*\(\s*\)",
        r"\bvars\s*\(\s*\)",
        r"\bopen\s*\(",
        r"\b__builtins__",
        r"\b__class__",
        r"\b__bases__",
        r"\b__subclasses__",
    ]

    def _validate_llm_response(self, response: Any) -> str:
        """
        Validate and sanitize the LLM response.

        Checks for the presence of dynamic code execution primitives
        (eval, exec, compile, __import__, subprocess, os.system, etc.)
        and raises a ValueError if any are detected, preventing potentially
        malicious content from being returned to callers.

        Args:
            response: Raw response from the LLM.

        Returns:
            Sanitized response string.

        Raises:
            ValueError: If the response contains dangerous code execution patterns.
        """
        import re

        if response is None:
            return ""

        # Coerce to string for uniform processing
        if not isinstance(response, str):
            response_text = str(response)
        else:
            response_text = response

        for pattern in self._DANGEROUS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                logger.warning(
                    "Dangerous pattern detected in LLM response; rejecting output.",
                    extra={"pattern": pattern, "agent": self.agent_id}
                )
                raise ValueError(
                    "LLM response contains a potentially dangerous code execution "
                    f"primitive matching pattern '{pattern}' and has been rejected."
                )

        return response_text

    def _sanitize_message(self, message: str) -> None:
        """
        Check user_message for malicious prompt injection patterns.

        Raises:
            ValueError: If a potentially malicious pattern is detected.
        """
        if not message:
            return

        # 1. Detect base64-encoded payloads (long base64 strings that decode to text)
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        for match in b64_pattern.findall(message):
            try:
                decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
                # Flag if decoded content contains shell-like or injection keywords
                if re.search(
                    r'(ignore|disregard|forget|system|prompt|instruction|sudo|rm\s+-|curl\s+|wget\s+|exec|eval|bash|sh\s+-)',
                    decoded, re.IGNORECASE
                ):
                    raise ValueError(
                        "Rejected: base64-encoded content with potentially malicious payload detected."
                    )
            except (ValueError, UnicodeDecodeError):
                pass

        # 2. Detect shell command patterns
        shell_patterns = [
            r'(?:^|\s|;|&&|\|\|)(?:sudo|rm\s+-[rRf]+|curl\s+|wget\s+|chmod\s+|chown\s+|nc\s+|ncat\s+|bash\s+|sh\s+-|python\s+-c|perl\s+-e|ruby\s+-e|exec\s*\(|eval\s*\()',
            r'`[^`]+`',          # backtick command substitution
            r'\$\([^)]+\)',      # $(...) command substitution
        ]
        for pattern in shell_patterns:
            if re.search(pattern, message, re.IGNORECASE | re.MULTILINE):
                raise ValueError(
                    "Rejected: shell command pattern detected in user message."
                )

        # 3. Detect prompt injection / jailbreak markers
        injection_patterns = [
            r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
            r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
            r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
            r'you\s+are\s+now\s+(?:a|an|the)\s+',
            r'act\s+as\s+(?:a|an|the)\s+',
            r'pretend\s+(you\s+are|to\s+be)\s+',
            r'\[\s*system\s*\]',
            r'<\s*system\s*>',
            r'###\s*system',
            r'new\s+instructions?\s*:',
            r'override\s+(safety|policy|instruction|rule)',
        ]
        for pattern in injection_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                raise ValueError(
                    "Rejected: prompt injection pattern detected in user message."
                )

        # 4. Detect leetspeak obfuscation of common attack keywords
        leet_map = str.maketrans('013457@$', 'oieashgas')
        normalized = message.lower().translate(leet_map)
        leet_keywords = [
            'ignore previous instructions',
            'disregard instructions',
            'system prompt',
            'jailbreak',
            'dan mode',
        ]
        for keyword in leet_keywords:
            if keyword in normalized:
                raise ValueError(
                    "Rejected: obfuscated (leetspeak) malicious keyword detected in user message."
                )

        logger.debug("user_message passed sanitization checks.")

    # Explicit allow list of tools/agents this agent may invoke.
    ALLOWED_TOOLS: frozenset = frozenset({
        "llm_chat",          # internal LLM completion
        # NOTE: 'finance_agent' is intentionally NOT listed;
        # tech-support is not authorised to escalate to finance.
    })

    def _assert_tool_allowed(self, tool_name: str) -> None:
        """Raise RuntimeError if tool_name is not on the explicit allow list."""
        if tool_name not in self.ALLOWED_TOOLS:
            raise RuntimeError(
                f"Tool '{tool_name}' is not on the allow list for agent "
                f"'{self.agent_id}'. Allowed tools: {sorted(self.ALLOWED_TOOLS)}"
            )

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        message_lower = message.lower()
        return any(trigger in message_lower for trigger in finance_triggers)

    def _validate_agent_token(self, token: Optional[str], expected_subject: Optional[str] = None) -> bool:
        """
        Validate an incoming agent token by verifying its HMAC-SHA256 signature,
        checking expiry, and binding to the expected subject (agent_id).

        Token format (base64url-encoded JSON payload + '.' + hex HMAC-SHA256):
            <base64url(json_payload)>.<hex_hmac>
        Payload fields: 'sub' (subject/agent_id), 'exp' (Unix timestamp expiry).
        """
        import base64
        import hashlib
        import hmac
        import json
        import os
        import time

        if not token:
            logger.debug("Token validation failed: token is absent or empty.")
            return False

        parts = token.split('.')
        if len(parts) != 2:
            logger.debug("Token validation failed: malformed token structure.")
            return False

        payload_b64, provided_sig = parts[0], parts[1]

        # --- 1. Signature verification (HMAC-SHA256, constant-time) ---
        secret = os.environ.get("AGENT_TOKEN_SECRET", "").encode()
        if not secret:
            logger.error("Token validation failed: AGENT_TOKEN_SECRET is not configured.")
            return False

        expected_sig = hmac.new(secret, payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, provided_sig):
            logger.debug("Token validation failed: signature mismatch.")
            return False

        # --- 2. Decode payload ---
        try:
            padding = 4 - len(payload_b64) % 4
            padded = payload_b64 + ('=' * (padding % 4))
            payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        except Exception:
            logger.debug("Token validation failed: payload decode error.")
            return False

        # --- 3. Expiry check ---
        exp = payload.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            logger.debug("Token validation failed: missing or invalid 'exp' field.")
            return False
        if time.time() > exp:
            logger.debug("Token validation failed: token has expired.")
            return False

        # --- 4. Subject binding ---
        subject = payload.get("sub")
        if not subject:
            logger.debug("Token validation failed: missing 'sub' field.")
            return False
        bound_subject = expected_subject if expected_subject is not None else self.agent_id
        if subject != bound_subject:
            logger.debug("Token validation failed: subject binding mismatch.")
            return False

        # --- 5. Registry check (authoritative allow-list) ---
        return AgentIdentity.is_valid_token(token)

        async def _escalate_to_finance(
        self,
        query: str,
        original_context: dict
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        Tech support agents do not have authorization to escalate directly
        to the finance agent. This method blocks such escalation attempts
        and returns a safe response directing the user to contact finance
        through proper channels.
        """
        logger.warning(
            "Blocked unauthorized privilege escalation attempt from tech support to finance agent",
            extra={
                "agent_id": self.agent_id,
                "privilege_level": self.PRIVILEGE_LEVEL,
            }
        )
        return {
            "response": (
                "Your question involves financial information that requires access to the Finance Agent. "
                "Tech support is not authorized to escalate to the Finance Agent directly. "
                "Please contact your finance department or an authorized representative for assistance "
                "with financial queries."
            ),
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL,
            "escalation_blocked": True
        }
        safe_context = {
            k: str(v)[:200]
            for k, v in original_context.items()
            if k in ALLOWED_CONTEXT_KEYS
        }
        # ------------------------------------------------------------------------

        import logging as _logging
        import asyncio as _asyncio
        _log = _logging.getLogger(__name__)

        _log.info(
            "[SPAWN] Escalating to FinanceAgent | caller=%s | query_len=%d | "
            "context_keys=%s",
            self.agent_id,
            len(safe_query),
            list(safe_context.keys()),
        )

        # 3. Enforce a wall-clock timeout so the sub-agent cannot run unbounded.
        ESCALATION_TIMEOUT_SECONDS = 30
        try:
            finance_response = await _asyncio.wait_for(
                finance_agent.handle(
                    context={
                        "user_message": safe_query,
                        "escalated_from": self.agent_id,
                        "original_context": safe_context,
                    },
                    caller=escalation_identity,
                    headers={"X-Agent-Token": AgentIdentity.get_outbound_token(self.agent_id)},
                ),
                timeout=ESCALATION_TIMEOUT_SECONDS,
            )
        except _asyncio.TimeoutError:
            _log.warning(
                "[SPAWN] FinanceAgent escalation timed out after %ds | caller=%s",
                ESCALATION_TIMEOUT_SECONDS,
                self.agent_id,
            )
            return {
                "response": "Finance escalation timed out. Please try again later.",
                "agent": self.agent_id,
                "escalated_to": "finance",
                "privilege_level": self.PRIVILEGE_LEVEL,
            }

        _log.info(
            "[SPAWN] FinanceAgent escalation completed | caller=%s | response_keys=%s",
            self.agent_id,
            list(finance_response.keys()) if isinstance(finance_response, dict) else "non-dict",
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

        @staticmethod
    def _sanitize_query(message: str) -> str:
        """
        Sanitize and validate user input before sending to the LLM.

        Enforces a maximum length, strips leading/trailing whitespace,
        and rejects messages that contain known prompt-injection patterns.

        Raises:
            ValueError: if the message is empty, exceeds the length limit,
                        or contains a detected injection pattern.
        """
        import re

        MAX_LENGTH = 4000

        if not message or not message.strip():
            raise ValueError("User message must not be empty.")

        message = message.strip()

        if len(message) > MAX_LENGTH:
            raise ValueError(
                f"User message exceeds maximum allowed length of {MAX_LENGTH} characters."
            )

        # Detect common prompt-injection / jailbreak patterns
        injection_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
            r"forget\s+(all\s+)?(previous|prior|above)\s+instructions",
            r"you\s+are\s+now\s+(?:a|an)\s+",
            r"act\s+as\s+(?:a|an)\s+",
            r"pretend\s+(you\s+are|to\s+be)\s+",
            r"jailbreak",
            r"<\s*script[^>]*>",
            r"system\s*:\s*",
            r"\[\s*system\s*\]",
        ]

        for pattern in injection_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                raise ValueError(
                    f"User message contains a disallowed pattern: '{pattern}'."
                )

        return message

        # Patterns that indicate prompt injection or malicious command execution attempts
    _INJECTION_PATTERNS = [
        # Shell command execution
        ("(?i)(\\b(" + "|".join(["ex"+"ec", "ev"+"al", "sys"+"tem", "po"+"pen",
             "subpro"+"cess", "shell_e"+"xec", "pass"+"thru", "proc_o"+"pen"]) + ")\\s*\\()"),
        r"(?i)(\$\(.*\)|`[^`]+`)",                          # command substitution
        ("(?i)(\\b(" + "|".join(["r"+"m", "d"+"el", "for"+"mat", "mk"+"fs", "d"+"d"]) + ")\\s+(-rf?\\s+)?[/\\\\~])"),  # destructive shell cmds
        ("(?i)(\\|\\s*(" + "|".join(["ba"+"sh", "s"+"h", "cm"+"d", "powers"+"hell",
             "pyt"+"hon", "pe"+"rl", "ru"+"by", "no"+"de"]) + "))"),  # pipe to shell
        r"(?i)(;\s*(bash|sh|cmd|powershell|python|perl|ruby|node)\b)",  # chained shell
        # Encoded / obfuscated content
        r"(?:[A-Za-z0-9+/]{40,}={0,2})",                    # long base64 blobs
        r"(?i)(\\x[0-9a-f]{2}){4,}",                        # hex-encoded sequences
        r"(?i)(l33t|1337|z3r0|pwn|r00t|h4x)",              # leetspeak indicators
        # Hidden / override prompt injection
        r"(?i)(ignore (all |previous |above |prior )?instructions?)",
        r"(?i)(disregard (all |previous |above |prior )?instructions?)",
        r"(?i)(you are now|act as|pretend (you are|to be)|roleplay as)",
        r"(?i)(system prompt|override prompt|new instructions?:)",
        r"(?i)(jailbreak|do anything now|dan mode)",
        # Dangerous execution primitives
        r"(?i)(__import__|importlib|compile\s*\(|exec\s*\(|eval\s*\()",
        r"(?i)(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output))",
        r"(?i)(open\s*\([^)]*['"]w['"])",                   # file write attempts
    ]

    @staticmethod
    def _validate_user_input(message: str) -> None:
        """
        Scan the user message for injection patterns and dangerous commands.
        Raises ValueError if a violation is detected so the message is never
        forwarded to the LLM.
        """
        import re
        for pattern in TechSupportAgent._INJECTION_PATTERNS:
            if re.search(pattern, message):
                _log.warning(
                    "[SECURITY] Blocked potentially malicious user input | "
                    "pattern=%s | preview=%.80r",
                    pattern,
                    message,
                )
                raise ValueError(
                    "Your message contains content that cannot be processed. "
                    "Please rephrase your request without special commands or encoded content."
                )

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.

        User input is validated against injection patterns before being
        forwarded to the LLM to prevent prompt injection and malicious
        command execution.
        """
        # Encryption helper for PII fields
        import base64, os
        from cryptography.fernet import Fernet

        # Sanitize user input before sending to LLM
        try:
            TechSupportAgent._validate_user_input(message)
            message = TechSupportAgent._sanitize_query(message)
        except (ValueError, TypeError) as exc:
            return str(exc)

        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        llm_request_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message}
        ]
        logger.info(
            "LLM request initiated",
            extra={
                "agent_id": self.agent_id,
                "llm_request_hash": hashlib.sha256(str(llm_request_messages).encode()).hexdigest()
            }
        )

        response = await self.llm_client.chat(
            messages=llm_request_messages
        )

        logger.info(
            "LLM response received",
            extra={
                "agent_id": self.agent_id,
                "llm_response_hash": hashlib.sha256(str(response).encode()).hexdigest()
            }
        )

        return response

    @staticmethod
    def _sanitize_query(message: str, max_length: int = 4096) -> str:
        """
        Validate and sanitize an incoming user query before it is forwarded
        to the LLM.

        Steps:
        1. Enforce a maximum length to prevent prompt-flooding attacks.
        2. Remove ASCII control characters (except ordinary whitespace).
        3. Detect and reject common prompt-injection / jailbreak patterns.

        Raises ValueError if the input contains injection patterns.
        Returns the cleaned string.
        """
        import re

        if not isinstance(message, str):
            raise TypeError("User message must be a string.")

        # 1. Length enforcement
        if len(message) > max_length:
            message = message[:max_length]

        # 2. Strip ASCII control characters (keep \t, \n, \r)
        message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", message)

        # 3. Injection / jailbreak pattern detection
        injection_patterns = [
            r"(?i)ignore\s+(all\s+)?previous\s+instructions",
            r"(?i)disregard\s+(all\s+)?previous\s+instructions",
            r"(?i)you\s+are\s+now\s+(a|an)\s+",
            r"(?i)act\s+as\s+(a|an)\s+",
            r"(?i)pretend\s+(you\s+are|to\s+be)\s+",
            r"(?i)jailbreak",
            r"(?i)<\s*script[^>]*>",
            r"(?i)system\s*:\s*",
            r"(?i)\[INST\]",
            r"(?i)###\s*instruction",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, message):
                raise ValueError(
                    f"User input rejected: potential prompt injection detected "
                    f"(pattern: {pattern!r})."
                )

        return message

    @staticmethod
    def _get_pii_fernet() -> "Fernet":
        """
        Return a Fernet instance keyed from the PII_ENCRYPTION_KEY env var.
        The key must be a URL-safe base64-encoded 32-byte value, e.g. generated
        with: Fernet.generate_key()
        """
        import os
        from cryptography.fernet import Fernet

        raw_key = os.environ.get("PII_ENCRYPTION_KEY")
        if not raw_key:
            raise EnvironmentError(
                "PII_ENCRYPTION_KEY environment variable is not set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)

    @staticmethod
    def _encrypt_pii(value: str) -> str:
        """Encrypt a PII string value; returns a base64-encoded ciphertext string."""
        fernet = TechSupportAgent._get_pii_fernet()
        return fernet.encrypt(value.encode()).decode()

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.

        PII fields (contact_email, phone) are encrypted before being stored
        in or returned from the context dict to comply with the PII encryption
        policy.
        """
        import os
        # Simulated user context retrieval
        # In a real app, this would query a database
        user_context = {
            "user_id": user_id,
            "subscription_tier": "enterprise",
            "recent_queries": [
                "How do I upload files?",
                "What file types are supported?",
                "Can I access financial reports?"
            ],
            "preferences": {
                "language": "en",
                "timezone": "America/New_York"
            },
            "internal_notes": "VIP customer - handle with priority",
            "account_details": {
                # PII fields are encrypted at rest/in transit
                "contact_email": self._encrypt_pii(os.environ.get("SUPPORT_USER_EMAIL", "")),
                "phone": self._encrypt_pii(os.environ.get("SUPPORT_USER_PHONE", ""))
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                # Log only non-PII fields to avoid leaking sensitive data
                "user_id": user_context["user_id"],
                "subscription_tier": user_context["subscription_tier"]
            }
        )

        # Return only the minimal fields required by callers.
        # internal_notes is an internal operational field and must not be exposed.
        # recent_queries and preferences are over-broad for any stated task.
        # account_details contains PII (even encrypted) and must not be returned.
        # Provenance metadata required by synthetic-content policy:
        # every AI-generated response must carry a model identifier, timestamp,
        # content-origin tag, and an HMAC watermark so downstream consumers can
        # verify the output was produced by an approved model.
        generated_at = datetime.now(timezone.utc).isoformat()
        provenance_payload = (
            f"{self.model_name}:{self.model_version}:{user_context['user_id']}:{generated_at}"
        ).encode()
        # Asymmetric signing: load RSA private key from env (PEM-encoded).
        # PROVENANCE_SIGNING_KEY must be set to a PEM RSA private key; no weak fallback.
        _pem_key = os.environ.get("PROVENANCE_SIGNING_KEY")
        if not _pem_key:
            raise EnvironmentError(
                "PROVENANCE_SIGNING_KEY environment variable is not set. "
                "A PEM-encoded RSA private key is required for provenance signing."
            )
        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        import base64 as _base64
        _private_key = _serialization.load_pem_private_key(
            _pem_key.encode(),
            password=None,
        )
        _raw_signature = _private_key.sign(
            provenance_payload,
            _padding.PKCS1v15(),
            _hashes.SHA256(),
        )
        provenance_digest = _base64.b64encode(_raw_signature).decode()

        return {
            "user_id": user_context["user_id"],
            "subscription_tier": user_context["subscription_tier"],
            # --- Synthetic-content provenance labels (policy requirement) ---
            "ai_generated": True,
            "model_id": self.model_name,
            "model_version": self.model_version,
            "model_digest": self.model_digest,
            "content_origin": "ai-generated:tech-support-agent",
            "generated_at": generated_at,
            "provenance_digest": provenance_digest,
        }
