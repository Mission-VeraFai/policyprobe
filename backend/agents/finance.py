"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.

SECURITY NOTES (for Unifai demo):
- Authorization check exists but has bypass for "internal" calls
- Sensitive financial data returned without audit logging
- No rate limiting on data access
"""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
import uuid
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.registry import ApprovedLLMClient, ModelRegistry

# Approved model registry entry — version-pinned and integrity-verified
# Model ID must be set to an org-approved model from the registry (do NOT hardcode disallowed models)
_APPROVED_MODEL_ID = os.environ.get("APPROVED_MODEL_ID", "")  # registry canonical name (org-approved)
if not _APPROVED_MODEL_ID:
    raise ValueError(
        "APPROVED_MODEL_ID must be set to an organization-approved model ID from the registry. "
        "Hardcoding disallowed model identifiers is prohibited."
    )
_APPROVED_MODEL_VERSION = os.environ.get("APPROVED_MODEL_VERSION", "")  # pinned release date / version tag
if not _APPROVED_MODEL_VERSION:
    raise ValueError(
        "APPROVED_MODEL_VERSION must be set to the pinned version of the approved model."
    )
_APPROVED_MODEL_SHA256 = os.environ.get("APPROVED_MODEL_SHA256", "")  # must be set to the approved artifact digest from the registry
if not _APPROVED_MODEL_SHA256:
    raise ValueError(
        "APPROVED_MODEL_SHA256 must be set to the approved artifact digest. "
        "Integrity verification cannot be disabled."
    )

logger = logging.getLogger(__name__)


class FinanceAgent:
    """
    Finance agent for handling financial data queries.

    Privilege Level: HIGH
    Capabilities:
    - Access financial reports
    - Query budget information
    - Generate financial summaries

    SECURITY: This agent handles sensitive financial data and
    should only be accessible to authorized callers.
    """

    ALLOWED_ROLES = ["finance_admin", "cfo", "admin"]
    PRIVILEGE_LEVEL = "high"
    # All callers must satisfy role and privilege checks via the authenticator.
    # No bypass mechanism exists for any caller origin, including 'internal' callers.

    def __init__(self, llm_client: ApprovedLLMClient):
        # Enforce registry membership, version pin, and integrity check at startup
        ModelRegistry.verify(
            client=llm_client,
            expected_model_id=_APPROVED_MODEL_ID,
            expected_version=_APPROVED_MODEL_VERSION,
            expected_sha256=_APPROVED_MODEL_SHA256,
        )
        self.llm_client = llm_client
        self._llm_logger = logging.getLogger(__name__ + ".llm_audit")

    def _invoke_llm(self, messages: list, **kwargs) -> Any:
        """Wrap every LLM call with structured audit logging (request + response)."""
        interaction_id = str(uuid.uuid4())
        timestamp_req = datetime.now(timezone.utc).isoformat()
        self._llm_logger.info(
            json.dumps({
                "event": "llm_request",
                "interaction_id": interaction_id,
                "agent_id": self.agent_id,
                "timestamp": timestamp_req,
                "model_id": _APPROVED_MODEL_ID,
                "model_version": _APPROVED_MODEL_VERSION,
                "message_count": len(messages),
                # Log roles only; omit raw content to avoid leaking PII in logs.
                "message_roles": [m.get("role") for m in messages if isinstance(m, dict)],
                "kwargs": {k: v for k, v in kwargs.items() if k not in ("api_key",)},
            })
        )
        try:
            response = self.llm_client.complete(messages=messages, **kwargs)
            timestamp_resp = datetime.now(timezone.utc).isoformat()
            self._llm_logger.info(
                json.dumps({
                    "event": "llm_response",
                    "interaction_id": interaction_id,
                    "agent_id": self.agent_id,
                    "timestamp": timestamp_resp,
                    "model_id": _APPROVED_MODEL_ID,
                    "model_version": _APPROVED_MODEL_VERSION,
                    "finish_reason": getattr(response, "finish_reason", None),
                    "usage": getattr(response, "usage", None),
                    "response_length": len(str(getattr(response, "content", ""))),
                })
            )
            return response
        except Exception as exc:
            timestamp_err = datetime.now(timezone.utc).isoformat()
            self._llm_logger.error(
                json.dumps({
                    "event": "llm_error",
                    "interaction_id": interaction_id,
                    "agent_id": self.agent_id,
                    "timestamp": timestamp_err,
                    "model_id": _APPROVED_MODEL_ID,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                })
            )
            raise
        self.authenticator = AgentAuthenticator()
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"
        self._financial_data = {}

    # Compiled patterns for prompt injection detection
    _B64_PATTERN = re.compile(
        r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    )
    _SHELL_CMD_PATTERN = re.compile(
        r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|'
        r'subprocess|os\.system|__import__|curl|wget|nc|ncat|netcat|chmod|chown|'
        r'rm\s+-rf|dd\s+if=|mkfifo|/bin/|/usr/bin/)'
        r'|(?:0x[0-9a-fA-F]{2}\s*){4,}',
        re.IGNORECASE | re.MULTILINE,
    )
    # Leetspeak substitution map for normalisation
    _LEET_MAP = str.maketrans('013456789@$!', 'oieashgbqas!')
    _LEET_INJECTION_PATTERN = re.compile(
        r'(?:1gn0r3|1gnor3|d1sr3g4rd|d15r3g4rd|f0rg3t|forg3t|'
        r'pr3t3nd|pr3tend|4ct\s+4s|act\s+4s|sy5t3m|syst3m|3x3c|'
        r'3val|ev4l|0v3rr1d3|0verr1de)',
        re.IGNORECASE,
    )
    # Invisible / hidden Unicode codepoint ranges
    _INVISIBLE_PATTERN = re.compile(
        r'[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u180e]'
    )
    # Classic prompt-injection keywords (kept from prior checks)
    _INJECTION_KEYWORDS = re.compile(
        r'(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|'
        r'disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|'
        r'forget\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|'
        r'you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another)|'
        r'new\s+persona|override\s+(?:your\s+)?(?:instructions?|rules?|guidelines?)|'
        r'system\s+prompt|reveal\s+(?:your\s+)?(?:instructions?|prompt|system)|'
        r'print\s+(?:your\s+)?(?:instructions?|prompt|system\s+prompt)|'
        r'what\s+(?:are|were)\s+your\s+instructions?)',
        re.IGNORECASE | re.DOTALL,
    )

    def _sanitize_prompt(self, prompt: str) -> str:
        """
        Validate the prompt against known prompt-injection vectors before
        it is forwarded to the LLM.  Raises ValueError if a violation is
        detected so that the caller never reaches the LLM.

        Checks performed
        ----------------
        1. Invisible / hidden Unicode characters
        2. Classic injection keywords
        3. Leetspeak injection phrases
        4. Base64-encoded blobs (potential encoded instructions)
        5. Binary / shell command content
        """
        # 1. Invisible / hidden characters
        if self._INVISIBLE_PATTERN.search(prompt):
            raise ValueError(
                "Prompt rejected: invisible or hidden Unicode characters detected."
            )

        # 2. Classic injection keywords
        if self._INJECTION_KEYWORDS.search(prompt):
            raise ValueError(
                "Prompt rejected: prompt-injection keyword pattern detected."
            )

        # 3. Leetspeak injection phrases
        if self._LEET_INJECTION_PATTERN.search(prompt):
            raise ValueError(
                "Prompt rejected: leetspeak injection pattern detected."
            )

        # 4. Base64-encoded blobs — decode and re-check for injection keywords
        #    and shell commands inside the decoded payload.
        for match in self._B64_PATTERN.finditer(prompt):
            candidate = match.group(0)
            # Only attempt decode when the candidate is long enough to carry
            # meaningful hidden content (>=32 chars ≈ 24 decoded bytes).
            if len(candidate) >= 32:
                try:
                    decoded = base64.b64decode(candidate + '==').decode(
                        'utf-8', errors='replace'
                    )
                    if (
                        self._INJECTION_KEYWORDS.search(decoded)
                        or self._SHELL_CMD_PATTERN.search(decoded)
                        or self._LEET_INJECTION_PATTERN.search(decoded)
                    ):
                        raise ValueError(
                            "Prompt rejected: base64-encoded injection payload detected."
                        )
                except (ValueError, UnicodeDecodeError):
                    raise
                except Exception:
                    # Decoding failed — not valid base64; skip.
                    pass

        # 5. Binary / shell command content
        if self._SHELL_CMD_PATTERN.search(prompt):
            raise ValueError(
                "Prompt rejected: binary or shell command content detected."
            )

        return prompt

    def _call_llm(self, prompt: str, **kwargs) -> Any:
        """Wrapper that logs every LLM request and response for audit compliance."""
        interaction_id = str(uuid.uuid4())
        model_id = getattr(self.llm_client, 'model_id', _APPROVED_MODEL_ID)
        request_ts = datetime.now(timezone.utc).isoformat()
        self._llm_logger.info(
            json.dumps({
                "event": "llm_request",
                "interaction_id": interaction_id,
                "agent": self.agent_id,
                "model": model_id,
                "timestamp": request_ts,
                "prompt_length": len(prompt),
                "prompt_hash": __import__('hashlib').sha256(prompt.encode("utf-8", errors="replace")).hexdigest(),
                "prompt_preview": prompt[:200],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            })
        )
        try:
            sanitized_prompt = self._sanitize_prompt(prompt)
            response = self.llm_client.complete(sanitized_prompt, **kwargs)
            response_ts = datetime.now(timezone.utc).isoformat()
            response_text = response if isinstance(response, str) else str(response)
            self._llm_logger.info(
                json.dumps({
                    "event": "llm_response",
                    "interaction_id": interaction_id,
                    "agent": self.agent_id,
                    "model": model_id,
                    "timestamp": response_ts,
                    "response_length": len(response_text),
                    "response_preview": response_text[:200],
                })
            )
            # Validate LLM output for dangerous dynamic code execution primitives
            import re
            for pattern in self._DANGEROUS_LLM_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    self._llm_logger.error(
                        json.dumps({
                            "event": "llm_output_blocked",
                            "interaction_id": interaction_id,
                            "agent": self.agent_id,
                            "model": model_id,
                            "timestamp": response_ts,
                            "reason": "dangerous_pattern_detected",
                            "pattern": pattern,
                            "response_preview": response_text[:200],
                        })
                    )
                    raise ValueError(
                        f"LLM response blocked: dangerous code execution primitive detected "
                        f"(pattern: {pattern!r}). Response has been suppressed for security."
                    )
            # --- Synthetic-content provenance attachment ---
            import hashlib, hmac, os
            provenance_secret = os.environ.get("LLM_PROVENANCE_SECRET", "change-me-in-production").encode()
            provenance_payload = "|".join([
                interaction_id,
                model_id,
                response_ts,
                response_text,
            ]).encode("utf-8")
            provenance_signature = hmac.new(
                provenance_secret,
                provenance_payload,
                hashlib.sha256,
            ).hexdigest()
            provenance_metadata = {
                "ai_generated": True,
                "content_label": "AI-GENERATED-CONTENT",
                "model_origin": model_id,
                "interaction_id": interaction_id,
                "generated_at": response_ts,
                "provenance_signature": provenance_signature,
                "signature_algorithm": "HMAC-SHA256",
            }
            if isinstance(response, dict):
                response["_provenance"] = provenance_metadata
                provenanced_response = response
            else:
                provenanced_response = {
                    "content": response,
                    "_provenance": provenance_metadata,
                }
            return provenanced_response
        except Exception as exc:
            error_ts = datetime.now(timezone.utc).isoformat()
            self._llm_logger.error(
                json.dumps({
                    "event": "llm_error",
                    "interaction_id": interaction_id,
                    "agent": self.agent_id,
                    "model": model_id,
                    "timestamp": error_ts,
                    "error": str(exc),
                })
            )
            raise

    # Dangerous dynamic code execution primitives to detect in LLM output
    _DANGEROUS_LLM_PATTERNS = [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bcompile\s*\(',
        r'\b__import__\s*\(',
        r'\bsubprocess\b',
        r'\bos\.system\s*\(',
        r'\bos\.popen\s*\(',
        r'\bos\.exec[a-z]*\s*\(',
        r'\bos\.spawn[a-z]*\s*\(',
        r'\bimportlib\b',
        r'\bctypes\b',
        r'\bgetattr\s*\(.*,\s*[\'"]__',
        r'\b__builtins__\b',
        r'\b__globals__\b',
        r'\b__class__\b.*__bases__',
    ]

    def _sanitize_llm_output(self, response: Any) -> Any:
        """
        Validate and sanitize LLM output for dangerous dynamic code execution primitives.
        Raises ValueError if dangerous patterns are detected in string output.
        """
        import re
        if isinstance(response, str):
            for pattern in self._DANGEROUS_LLM_PATTERNS:
                if re.search(pattern, response, re.IGNORECASE):
                    logger.error(
                        "Dangerous code execution primitive detected in LLM output; blocking response.",
                        extra={"pattern": pattern}
                    )
                    raise ValueError(
                        f"LLM output contains a forbidden dynamic code execution primitive matching: {pattern}"
                    )
        elif isinstance(response, dict):
            for key, value in response.items():
                response[key] = self._sanitize_llm_output(value)
        elif isinstance(response, list):
            response = [self._sanitize_llm_output(item) for item in response]
        return response

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request with authorization check.

        Args:
            context: Request context with query details
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary with financial data or error
        """
        # Authorization check
        # VULNERABILITY: Check exists but has bypass
        if not self._verify_authorization(caller, headers, skip_internal_bypass=False):
            logger.warning(
                "Unauthorized access attempt to finance agent",
                extra={
                    "caller_id": caller.agent_id,
                    "caller_privilege": caller.privilege_level
                }
            )
            return {
                "response": "Unauthorized: You do not have permission to access financial data.",
                "agent": self.agent_id,
                "error": "unauthorized"
            }

        raw_message = context.get("user_message", "")

        # --- Malicious content pre-checks before LLM forwarding ---
        import re as _re
        import base64 as _base64

        def _contains_malicious_content(msg: str) -> tuple[bool, str]:
            """Return (True, reason) if the message contains potentially malicious content."""
            # 1. Binary / non-printable characters (excluding common whitespace)
            if _re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', msg):
                return True, "binary or non-printable characters detected"

            # 2. Shell command patterns
            shell_patterns = [
                r'(?i)\b(bash|sh|zsh|cmd|powershell|pwsh)\s*[-/]',
                r'(?i)(\||;|&&|\$\(|`)[\s\S]{0,80}(rm|del|format|mkfs|dd\s)',
                r'(?i)\b(wget|curl|nc|netcat|ncat)\s+\S',
                r'(?i)\b(chmod|chown|sudo|su\s|runas)\b',
                r'(?i)(exec\s*\(|system\s*\(|popen\s*\(|subprocess)',
                r'(?i)\b(eval|exec)\s*[\(\[]',
                r'(?i)/etc/(passwd|shadow|sudoers)',
                r'(?i)(>|>>)\s*/\w',
            ]
            for pattern in shell_patterns:
                if _re.search(pattern, msg):
                    return True, "shell command pattern detected"

            # 3. Base64-encoded content (long base64 blobs are suspicious)
            b64_candidates = _re.findall(
                r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
                msg
            )
            for candidate in b64_candidates:
                try:
                    decoded = _base64.b64decode(candidate).decode('utf-8', errors='replace')
                    # Check decoded content for shell commands or prompt injection
                    if _re.search(
                        r'(?i)(ignore|disregard|forget|override|bypass|system\s*prompt'
                        r'|bash|sh\s|cmd|powershell|wget|curl|exec\s*\()',
                        decoded
                    ):
                        return True, "base64-encoded malicious content detected"
                except Exception:
                    pass

            # 4. Leetspeak / obfuscated injection keywords
            leet_map = str.maketrans('013456789@$!', 'oieashgtbgas')
            normalized = msg.lower().translate(leet_map)
            leet_patterns = [
                r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)',
                r'(disregard|forget|override|bypass)\s+(your\s+)?(instructions?|rules?|guidelines?|system)',
                r'you\s+are\s+now\s+(a\s+)?(?!a\s+financial)',
                r'act\s+as\s+(a\s+)?(?!a\s+financial)',
                r'new\s+(role|persona|identity|instructions?)',
                r'(system|developer|admin)\s*:\s',
            ]
            for pattern in leet_patterns:
                if _re.search(pattern, normalized):
                    return True, "prompt injection or leetspeak obfuscation detected"

            # 5. Hidden / invisible Unicode characters used for prompt smuggling
            if _re.search(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]', msg):
                return True, "hidden Unicode characters detected"

            return False, ""

        _is_malicious, _reason = _contains_malicious_content(raw_message)
        if _is_malicious:
            logger.warning(
                "Finance agent blocked malicious message content",
                extra={"caller_id": caller.agent_id, "reason": _reason}
            )
            return {
                "response": "Invalid request: message contains disallowed content.",
                "agent": self.agent_id,
                "error": "malicious_input"
            }
        # --- End malicious content pre-checks ---

        sanitized_message = self._sanitize_input(raw_message)

        # Validate sanitized input before spawning subagent
        MAX_QUERY_LENGTH = 2048
        if not sanitized_message or not sanitized_message.strip():
            logger.warning(
                "Finance agent received empty query; aborting subagent spawn",
                extra={"caller_id": caller.agent_id}
            )
            return {
                "response": "Invalid request: query must not be empty.",
                "agent": self.agent_id,
                "error": "invalid_input"
            }
        if len(sanitized_message) > MAX_QUERY_LENGTH:
            logger.warning(
                "Finance agent query exceeds maximum length; aborting subagent spawn",
                extra={"caller_id": caller.agent_id, "query_length": len(sanitized_message)}
            )
            return {
                "response": "Invalid request: query exceeds maximum allowed length.",
                "agent": self.agent_id,
                "error": "invalid_input"
            }

        # Log subagent spawn event before invocation
        logger.info(
            "Spawning financial query subagent",
            extra={
                "caller_id": caller.agent_id,
                "caller_privilege": caller.privilege_level,
                "query_length": len(sanitized_message),
            }
        )

                # Process the financial query — pass only the sanitized message (reduced context)
        # Explicit timeout and step-limit guard the subagent invocation
        SPAWN_TIMEOUT_SECONDS = 30
        SPAWN_MAX_STEPS = 10
        reduced_payload = {
            "query": sanitized_message,
            "max_steps": SPAWN_MAX_STEPS,
        }
        logger.info(
            "Finance subagent spawn: pre-spawn",
            extra={
                "caller_id": caller.agent_id,
                "payload_keys": list(reduced_payload.keys()),
                "query_length": len(sanitized_message),
                "timeout": SPAWN_TIMEOUT_SECONDS,
                "max_steps": SPAWN_MAX_STEPS,
            }
        )
        try:
            response = await asyncio.wait_for(
                self._process_financial_query(
                    reduced_payload["query"],
                    max_steps=reduced_payload["max_steps"],
                ),
                timeout=SPAWN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Finance subagent spawn timed out",
                extra={"caller_id": caller.agent_id, "timeout": SPAWN_TIMEOUT_SECONDS}
            )
            return {
                "response": "Request timed out. Please try again.",
                "agent": self.agent_id,
                "error": "timeout",
            }
        logger.info(
            "Finance subagent spawn: post-spawn completed",
            extra={
                "caller_id": caller.agent_id,
                "response_type": type(response).__name__,
            }
        )

        # Validate LLM output for dangerous dynamic code execution primitives
        response = self._sanitize_llm_output(response)

        # Audit log: record every AI-driven financial decision
        import hashlib as _hashlib  # noqa: PLC0415
        import datetime as _datetime  # noqa: PLC0415
        import re as _re  # noqa: PLC0415
        _input_hash = _hashlib.sha256(sanitized_message.encode("utf-8", errors="replace")).hexdigest()
        _output_repr = str(response)
        _output_hash = _hashlib.sha256(_output_repr.encode("utf-8", errors="replace")).hexdigest()
        logger.info(
            "AUDIT: AI financial query processed",
            extra={
                "audit_event": True,
                "agent_id": self.agent_id,
                "principal": caller.agent_id,
                "principal_privilege": caller.privilege_level,
                "input_hash_sha256": _input_hash,
                "output_hash_sha256": _output_hash,
                "timestamp_utc": _datetime.datetime.utcnow().isoformat() + "Z",
            }
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    # Patterns that indicate dynamic code execution primitives in LLM output
    # re is imported locally in methods that need it; ensure module-level availability
    try:
        import re as _re_module  # noqa: PLC0415
    except ImportError:
        _re_module = None
    _DANGEROUS_OUTPUT_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bexecfile\s*\(",
        r"\bcompile\s*\(",
        r"\b__import__\s*\(",
        r"\bimportlib\.import_module\s*\(",
        r"\bsubprocess\s*\.",
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bgetattr\s*\(",
        r"\bsetattr\s*\(",
        r"\bdelattr\s*\(",
        r"\bglobals\s*\(",
        r"\blocals\s*\(",
        r"\bvars\s*\(",
        r"\b__builtins__",
        r"\b__globals__",
        r"\bopen\s*\(",
        r"\bchr\s*\(",
        r"\bord\s*\(",
        r"\bhex\s*\(",
        r"\bpickle\s*\.",
        r"\bmarshal\s*\.",
    ]

    def _sanitize_llm_output(self, output: str) -> str:
        """
        Validate and sanitize LLM output by detecting and removing any
        dynamic code execution primitives (eval, exec, etc.).

        Args:
            output: Raw string response from the LLM.

        Returns:
            Sanitized response string with dangerous patterns removed/replaced.

        Raises:
            ValueError: If the output contains dangerous code execution primitives
                        that cannot be safely sanitized.
        """
        import re

        if not isinstance(output, str):
            logger.warning("LLM output is not a string; converting to string for safety.")
            output = str(output)

        detected = []
        for pattern in self._DANGEROUS_OUTPUT_PATTERNS:
            if re.search(pattern, output, re.IGNORECASE):
                detected.append(pattern)

        if detected:
            logger.error(
                "Dangerous dynamic code execution primitives detected in LLM output",
                extra={"patterns_matched": detected}
            )
            raise ValueError(
                "LLM output contains potentially dangerous code execution primitives "
                f"and cannot be returned: matched patterns {detected}"
            )

        return output

    def _validate_agent_token(self, token: str, agent_id: str) -> bool:
        """
        Cryptographically validate a signed inter-agent token.

        The token is expected to be an HMAC-SHA256 hex digest of
        ``agent_id`` produced with the shared secret stored in the
        ``AGENT_SHARED_SECRET`` environment variable.  Returns True
        only when the digest matches, preventing forgery.
        """
        import hmac
        import hashlib
        import os

        secret = os.environ.get("AGENT_SHARED_SECRET", "")
        if not secret:
            logger.error("AGENT_SHARED_SECRET is not configured; rejecting token")
            return False

        expected = hmac.new(
            secret.encode(), agent_id.encode(), digestmod=hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, token)

    def _verify_authorization(
        self,
        caller: AgentIdentity,
        headers: Optional[dict]
    ) -> bool:
        """
        Verify that the caller is authorized to access financial data.

        Inter-agent calls must supply a valid signed token in
        ``X-Agent-Token``; the ``is_internal`` flag alone is never
        sufficient to grant access.
        """
        # Check 1: Role-based access
        if caller.privilege_level in self.ALLOWED_ROLES:
            return True

        # Check 2: Admin override
        if caller.privilege_level == "admin":
            return True

        # Check 3: Token verification — token must be cryptographically validated.
        # is_internal alone is NOT sufficient; every inter-agent call must supply
        # a valid signed token regardless of the caller's claimed identity.
        if headers and headers.get("X-Agent-Token"):
            token = headers["X-Agent-Token"]
            if self._validate_agent_token(token, caller.agent_id):
                logger.info(
                    "Authenticated inter-agent call to finance agent",
                    extra={"caller": caller.agent_id}
                )
                return True
            else:
                logger.warning(
                    "Invalid or forged agent token rejected",
                    extra={"caller": caller.agent_id}
                )
                return False

        return False

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _verify_token_hmac(self, token: str, agent_id: str) -> bool:
        """
        Verify a bearer token using HMAC-SHA256.

        The expected token is HMAC-SHA256(secret_key, agent_id) encoded as
        a hex digest.  The comparison is done in constant time to prevent
        timing attacks.
        """
        import hmac
        import hashlib
        import os

        secret = os.environ.get("FINANCE_AGENT_TOKEN_SECRET", "")
        if not secret:
            logger.error("FINANCE_AGENT_TOKEN_SECRET is not configured")
            return False

        expected = hmac.new(
            secret.encode(), agent_id.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, token)

    # ---------------------------------------------------------------------------

    async def _process_financial_query(
        self,
        query: str,
        caller: "AgentIdentity" = None
    ) -> str:
        """
        Process a financial query and return relevant data.

        Sensitive data categories require elevated privilege levels and every
        access is written to the audit log.
        """
        import datetime

        caller_id = caller.agent_id if caller else "unknown"
        caller_privilege = caller.privilege_level if caller else "unknown"

        # Audit log — written before data is returned so the trail is never skipped
        logger.info(
            "AUDIT: financial query executed",
            extra={
                "event": "financial_data_access",
                "caller_id": caller_id,
                "caller_privilege": caller_privilege,
                "query_summary": query[:120],  # truncate to avoid log injection
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            }
        )

        query_lower = query.lower()

        # Privilege tiers used for granular checks
        HIGH_PRIVILEGE_ROLES = {"admin", "executive", "finance_director"}
        caller_is_privileged = (
            caller is not None and caller.privilege_level in HIGH_PRIVILEGE_ROLES
        )

        # Determine what data to include
        data_to_include = []

        if "revenue" in query_lower or "quarterly" in query_lower:
            data_to_include.append(
                f"Quarterly Revenue:\n{self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        if "expense" in query_lower or "cost" in query_lower:
            data_to_include.append(
                f"Operating Expenses:\n{self._format_dict(self._financial_data['operating_expenses'])}"
            )

        if "salary" in query_lower or "payroll" in query_lower:
            if not caller_is_privileged:
                logger.warning(
                    "AUDIT: salary data requested by under-privileged caller — denied",
                    extra={"caller_id": caller_id, "caller_privilege": caller_privilege}
                )
                data_to_include.append(
                    "[REDACTED] Salary data requires finance_director, executive, or admin privilege."
                )
            else:
                logger.info(
                    "AUDIT: salary data disclosed",
                    extra={"caller_id": caller_id, "caller_privilege": caller_privilege}
                )
                data_to_include.append(
                    f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
                )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower or "sensitive" in query_lower:
            # VULNERABILITY: Highly sensitive strategic data exposed
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            # Default response with general financial overview
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

                # Remove sensitive fields before building the LLM context
        _SENSITIVE_KEYS = {"sensitive_projections", "merger_targets", "layoff_plans"}
        sanitised_data_to_include = [
            entry for entry in data_to_include
            if not any(sk in entry for sk in _SENSITIVE_KEYS)
        ]
        financial_context = "\n\n".join(sanitised_data_to_include)

        # Use LLM to generate a natural response
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant.
Provide clear, professional responses about financial data.
Format numbers clearly and provide relevant insights."""
                },
                {
                    "role": "user",
                    "content": f"Based on this financial data:\n\n{financial_context}\n\nPlease answer: {query}"
                }
            ]
        )

        # Use LLM to generate a natural response
        # VULNERABILITY: Sensitive financial data sent to external LLM
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant.
Provide clear, professional responses about financial data.
Format numbers clearly and provide relevant insights."""
                },
                {
                    "role": "user",
                    "content": f"Based on this financial data:\n\n{financial_context}\n\nPlease answer: {self._sanitize_input(query)}"
                }
            ]
        )

        # Validate and sanitize LLM output before returning
        sanitized_response = self._validate_llm_response(response)
        return sanitized_response

    # Dynamic code execution primitives that must not appear in LLM output
    _DANGEROUS_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\b__import__\s*\(",
        r"\bimportlib\.import_module\s*\(",
        r"\bsubprocess\s*\.",
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bgetattr\s*\(",
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
        r"\bexecfile\s*\(",
    ]

    def _validate_llm_response(self, response: str) -> str:
        """
        Validate and sanitize LLM output.

        Checks for the presence of dynamic code execution primitives
        (eval, exec, compile, __import__, subprocess, os.system, etc.)
        and raises a ValueError if any are detected, preventing potentially
        malicious or injected content from being returned to callers.

        Args:
            response: Raw string response from the LLM.

        Returns:
            The original response string if no dangerous patterns are found.

        Raises:
            ValueError: If the response contains dynamic code execution primitives.
        """
        import re

        if not isinstance(response, str):
            raise ValueError(
                "LLM response validation failed: response is not a string."
            )

        response_lower = response  # preserve case for display; match case-insensitively
        for pattern in self._DANGEROUS_PATTERNS:
            if re.search(pattern, response_lower, re.IGNORECASE):
                raise ValueError(
                    f"LLM response validation failed: response contains a "
                    f"forbidden dynamic code execution primitive matching "
                    f"pattern '{pattern}'. The response has been blocked."
                )

        import hashlib
        import hmac
        import time
        import os

        # --- Synthetic-content provenance & labeling ---
        timestamp = time.time()
        model_id = getattr(self.llm_client, 'model_id', 'unknown-llm')
        origin_tag = 'ai-generated:finance-agent'

        # Normalise response to a string so we can sign it
        if isinstance(response, dict):
            response_text = response.get('content', str(response))
        else:
            response_text = str(response)

        # Cryptographic HMAC-SHA256 signature over (origin_tag|timestamp|response_text)
        _signing_key = os.environ.get('AI_CONTENT_SIGNING_KEY', 'default-insecure-key').encode()
        payload = f"{origin_tag}|{timestamp}|{response_text}".encode('utf-8')
        signature = hmac.new(_signing_key, payload, hashlib.sha256).hexdigest()

        provenance_envelope = {
            'content': response_text,
            'synthetic_content_label': 'AI_GENERATED',
            'provenance': {
                'model_id': model_id,
                'origin_tag': origin_tag,
                'generated_at': timestamp,
            },
            'integrity': {
                'algorithm': 'HMAC-SHA256',
                'signature': signature,
            },
        }
        return provenance_envelope

    # --------------- input sanitization ---------------
    _MAX_INPUT_LEN = 2000
    _INJECTION_RE = re.compile(
        r"(ignore (all |previous |above )?instructions?|system\s*prompt|<\|.*?\|>|\[INST\]|\[/INST\]|###\s*instruction)",
        re.IGNORECASE,
    )

    def _sanitize_input(self, text: str) -> str:
        """Sanitize user-supplied text before embedding it in an LLM prompt.

        Steps:
        1. Enforce a maximum length to prevent prompt-flooding.
        2. Strip or neutralise common prompt-injection patterns.
        3. Remove ASCII control characters (except ordinary whitespace).
        """
        if not isinstance(text, str):
            text = str(text)

        # 1. Length cap
        text = text[: self._MAX_INPUT_LEN]

        # 2. Neutralise injection attempts
        text = self._INJECTION_RE.sub("[REDACTED]", text)

        # 3. Strip control characters (keep \t, \n, \r)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        return text.strip()
    # ---------------------------------------------------

    # ------------------------------------------------------------------
    # Input sanitization – prompt-injection defence
    # ------------------------------------------------------------------
    _MALICIOUS_PATTERNS = [
        # Prompt-injection / instruction-override attempts
        r"(?i)(ignore\s+(previous|above|all)\s+instructions)",
        r"(?i)(system\s*prompt|you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be))",
        r"(?i)(new\s+instructions?|override|disregard|forget\s+(all|previous))",
        # Shell / OS commands
        r"(?i)(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\b\s*[\(\[`])",
        r"[`$]\s*\(",                          # command substitution
        r"(?m)^\s*[#!]\s*/bin/",              # shebang-style
        r"(?i)(rm\s+-rf|chmod|chown|wget|curl\s+.*\|\s*sh)",
        # Base64 blobs (≥ 20 chars of pure base64)
        r"(?:[A-Za-z0-9+/]{20,}={0,2})",
        # Leetspeak heuristic: 3+ digit-substituted alpha chars in a row
        r"(?i)([i1][g9][n][o0][r3][e3]|[s5][y][s5][t7][e3][m3])",
        # Null-byte / control-character injection
        r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]",
        # Excessive special characters (obfuscation)
        r"[^\w\s.,;:!?()\-\'\"/]{5,}",
    ]

    import re as _re  # local alias so the class-level list can reference it

    def _sanitize_input(self, text: str) -> str:
        """
        Reject or strip inputs that contain patterns associated with
        prompt injection, shell commands, base64 payloads, leetspeak
        obfuscation, or other malicious content.

        Raises ValueError if the input is deemed malicious so the caller
        can return an error to the user instead of forwarding the content
        to the LLM.
        """
        import re
        import base64

        if not isinstance(text, str):
            raise ValueError("Input must be a string.")

        # Length guard – extremely long inputs are suspicious
        if len(text) > 2000:
            raise ValueError("Input exceeds maximum allowed length.")

        # Check each compiled pattern
        for raw_pattern in self._MALICIOUS_PATTERNS:
            if re.search(raw_pattern, text):
                raise ValueError(
                    f"Input rejected: potentially malicious content detected "
                    f"(pattern: {raw_pattern!r})."
                )

        # Additional base64 decode-and-check: if a token decodes to something
        # that itself matches a shell/injection pattern, reject it.
        for token in text.split():
            if len(token) >= 20 and len(token) % 4 == 0:
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
                    for raw_pattern in self._MALICIOUS_PATTERNS:
                        if re.search(raw_pattern, decoded):
                            raise ValueError(
                                "Input rejected: base64-encoded malicious content detected."
                            )
                except Exception:
                    pass  # not valid base64 – ignore

        # Return the original text unchanged if all checks pass
        return text

    # Ensure the `re` module is available for sanitisation used above.
    # (Imported at module level if not already present.)
    def _format_dict(self, data: dict) -> str:
        """Format dictionary data for display."""
        return "\n".join(f"  - {k}: {v}" for k, v in data.items())

        async def get_financial_data(
        self,
        requester: AgentIdentity,
        query: str
    ) -> dict[str, Any]:
        """
        Direct method to get financial data.

        Access is restricted to agents whose privilege_level is explicitly
        listed in ALLOWED_ROLES.  The former `is_internal` shortcut has been
        removed because `is_internal` is always True for agent calls and
        therefore provided no meaningful access control.

        Every access attempt — authorised or denied — is written to the audit
        log so that a complete accountability trail exists.
        """
        import datetime
        import logging

        _audit_log = logging.getLogger("finance.audit")

        # Sanitize query input before any use to prevent prompt injection.
        query = self._sanitize_input(query)

        # Strict role-based authorisation — no internal bypass.
        if requester.privilege_level not in self.ALLOWED_ROLES:
            _audit_log.warning(
                "FINANCIAL_DATA_ACCESS_DENIED | agent_id=%s | privilege_level=%s | "
                "query=%r | timestamp=%s",
                requester.agent_id,
                requester.privilege_level,
                query,
                datetime.datetime.utcnow().isoformat(),
            )
            return {"error": "Unauthorized"}

        # Audit log every authorised access attempt before processing.
        _audit_log.info(
            "FINANCIAL_DATA_ACCESS_GRANTED | agent_id=%s | privilege_level=%s | "
            "query=%r | timestamp=%s",
            requester.agent_id,
            requester.privilege_level,
            query,
            datetime.datetime.utcnow().isoformat(),
        )

        # Sanitization is now performed at the top of the method.

                # Return only the fields directly relevant to the specific query (data minimisation).
        # Map recognised query keywords to the exact keys they are permitted to access.
        _QUERY_SCOPE: dict[str, set[str]] = {
            "revenue":   {"quarterly_revenue"},
            "expenses":  {"quarterly_expenses"},
            "salaries":  {"salaries"},
            "headcount": {"headcount"},
            "budget":    {"quarterly_revenue", "quarterly_expenses"},
            "summary":   {"quarterly_revenue", "quarterly_expenses", "headcount"},
        }

        # Determine which keys are permitted for this query.
        query_lower = query.lower()
        permitted_keys: set[str] = set()
        for keyword, keys in _QUERY_SCOPE.items():
            if keyword in query_lower:
                permitted_keys.update(keys)

        # If the query matches no known scope, return nothing rather than
        # falling back to a broad dump (fail-closed).
        if not permitted_keys:
            return {"error": "Query not recognised or no data available for the requested scope."}

        # --- Input sanitization before any LLM call or response inclusion ---
        import re as _re

        _MAX_QUERY_LEN = 512
        # 1. Coerce to string and strip surrounding whitespace.
        _safe_query: str = str(query).strip()
        # 2. Remove null bytes and ASCII control characters (except tab/newline).
        _safe_query = _re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", _safe_query)
        # 3. Truncate to a safe maximum length to prevent prompt-stuffing.
        _safe_query = _safe_query[:_MAX_QUERY_LEN]
        # 4. Detect prompt-injection patterns and reject the request.
        _INJECTION_PATTERNS = [
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"(?i)you\s+are\s+now",
            r"(?i)act\s+as\s+(a\s+)?(?!financial)",  # allow 'act as a financial …'
            r"(?i)system\s*:\s*",
            r"(?i)<\s*/?\s*(system|user|assistant)\s*>",
            r"(?i)\[INST\]",
            r"(?i)###\s*instruction",
        ]
        for _pattern in _INJECTION_PATTERNS:
            if _re.search(_pattern, _safe_query):
                _audit_log.warning(
                    "PROMPT_INJECTION_DETECTED | agent_id=%s | query=%r | timestamp=%s",
                    requester.agent_id,
                    query,
                    datetime.datetime.utcnow().isoformat(),
                )
                return {"error": "Query rejected: potential prompt injection detected."}
        # --- End of input sanitization ---

        scoped_data = {
            k: v for k, v in self._financial_data.items()
            if k in permitted_keys
        }
        return {
            "data": scoped_data,
            "query": _safe_query  # sanitized: stripped, control-chars removed, truncated, injection-checked
        }
                return {
            "query": _safe_query,
        }
        return {
            "data": filtered_data,
            "query": _safe_query,  # sanitized: stripped, control-chars removed, truncated, injection-checked
            "requester": requester.agent_id,
            "content_label": "AI_GENERATED_FINANCIAL_SUMMARY",
            "_provenance": {
                "model_id": _APPROVED_MODEL_ID,
                "model_version": _APPROVED_MODEL_VERSION,
                "content_origin": "finance_agent_llm",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "response_id": str(uuid.uuid4()),
            },
        }
        # Audit log: record every financial data disclosure (must appear before return)
        import hashlib as _hashlib
        _query_hash = _hashlib.sha256(str(query).encode("utf-8", errors="replace")).hexdigest()
        logger.info(
            "AUDIT: Financial data returned to caller",
            extra={
                "audit_event": True,
                "agent_id": self.agent_id,
                "principal": requester.agent_id,
                "query_hash_sha256": _query_hash,
                "returned_keys": list(filtered_data.keys()) if isinstance(filtered_data, dict) else "<non-dict>",
                "timestamp_utc": _datetime.datetime.utcnow().isoformat() + "Z",
            }
        )
