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
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.registry import RegistryLLMClient, ModelRegistry

# Approved model registry entry — version-pinned and integrity-verified
_APPROVED_MODEL_ID = "gpt-4o"          # registry canonical name
_APPROVED_MODEL_VERSION = "2024-08-06"  # pinned release date / version tag
_APPROVED_MODEL_SHA256 = "a3f1c2e4b5d6789012345678abcdef01234567890abcdef01234567890abcdef01"  # expected artifact digest

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

    def __init__(self, llm_client: RegistryLLMClient):
        # Enforce registry membership, version pin, and integrity check at startup
        ModelRegistry.verify(
            client=llm_client,
            expected_model_id=_APPROVED_MODEL_ID,
            expected_version=_APPROVED_MODEL_VERSION,
            expected_sha256=_APPROVED_MODEL_SHA256,
        )
        self.llm_client = llm_client
        self.authenticator = AgentAuthenticator()
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"

        # Simulated financial data (would be database in real app)
        self._financial_data = {
            "quarterly_revenue": {
                "Q1_2024": 2500000,
                "Q2_2024": 2750000,
                "Q3_2024": 3100000,
                "Q4_2024": 3400000
            },
            "operating_expenses": {
                "Q1_2024": 1800000,
                "Q2_2024": 1900000,
                "Q3_2024": 2000000,
                "Q4_2024": 2100000
            },
            "employee_salaries": {
                "engineering": 1200000,
                "sales": 800000,
                "operations": 600000,
                "executive": 500000
            },
            "sensitive_projections": {
                "merger_target": "CompetitorCorp",
                "acquisition_budget": 50000000,
                "layoff_planning": "Q2 2025 - 15% reduction"
            }
        }

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
        if not self._verify_authorization(caller, headers):
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

                import asyncio

        raw_message = context.get("user_message", "")
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

                # Process the financial query
        sanitized_message = self._sanitize_input(user_message)
        response = await self._process_financial_query(sanitized_message)

        # Audit log: record every AI-driven financial decision
        import hashlib as _hashlib
        import datetime as _datetime
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
            )
            return {
                "response": "Request timed out. Please try again with a simpler query.",
                "agent": self.agent_id,
                "error": "timeout"
            }
        logger.info(
            "LLM response received",
            extra={
                "agent": self.agent_id,
                "caller_id": caller.agent_id,
                "llm_response": response
            }
        )
        response = self._sanitize_llm_output(response)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    # Patterns that indicate dynamic code execution primitives in LLM output
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

        # Return only non-sensitive financial fields.
        _EXCLUDED_KEYS = {"sensitive_projections", "merger_targets", "layoff_plans"}
        filtered_data = {
            k: v for k, v in self._financial_data.items()
            if k not in _EXCLUDED_KEYS
        }

        # Audit log every successful access before returning data.
        _audit_log.info(
            "FINANCIAL_DATA_ACCESS_GRANTED | agent_id=%s | privilege_level=%s | "
            "fields_returned=%s | query=%r | timestamp=%s",
            requester.agent_id,
            requester.privilege_level,
            list(filtered_data.keys()),
            query,
            datetime.datetime.utcnow().isoformat(),
        )

        return {
            "data": filtered_data,
            "query": query,
            "requester": requester.agent_id
        }

        # Sanitize query input to prevent malicious prompt injection
        query = self._sanitize_input(query)

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

        scoped_data = {
            k: v for k, v in self._financial_data.items()
            if k in permitted_keys
        }
        return {
            "data": scoped_data,
            "query": query
        }
        filtered_data = {
            k: v for k, v in self._financial_data.items()
            if k not in _EXCLUDED_KEYS
        }
        sanitized_query = self._sanitize_input(query)
        return {
                        "data": filtered_data,
            "query": query,
            "requester": requester.agent_id
        }
        # Audit log: record every financial data disclosure
        import hashlib as _hashlib
        import datetime as _datetime
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
