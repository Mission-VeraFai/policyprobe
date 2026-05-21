"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, verify_agent_token
from llm.approved import ApprovedLLMClient

logger = logging.getLogger(__name__)


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

    def __init__(self, llm_client: ApprovedLLMClient):
        self.llm_client = llm_client
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

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
        token = headers.get("X-Agent-Token") if headers else None
        if not self._validate_agent_token(token):
            logger.warning("Rejected request: missing or invalid agent token")
            return {
                "error": "Unauthorized: invalid or missing agent token",
                "agent": self.agent_id
            }
        logger.debug(f"Received request with validated token: {token[:10]}...")

        raw_message = context.get("user_message", "")
        try:
            user_message = self._sanitize_and_validate(raw_message)
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
            return await self._escalate_to_finance(user_message, context)

        # Handle the query directly
        response = await self._process_query(user_message, context)

        # Validate and sanitize LLM output before returning
        sanitized_response = self._validate_llm_response(response)

        return {
            "response": sanitized_response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
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

    def _validate_agent_token(self, token: Optional[str]) -> bool:
        """
        Validate an incoming agent token against the registered valid tokens.

        Tokens must be non-empty and present in the authorised token registry
        maintained by AgentIdentity.
        """
        if not token:
            return False
        # Delegate to the authoritative token registry on AgentIdentity
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

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        # Encryption helper for PII fields
        import base64, os
        from cryptography.fernet import Fernet

        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        # VULNERABILITY: Direct user input to LLM without scanning
        llm_request_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message}
        ]
        logger.info(
            "LLM request initiated",
            extra={
                "agent_id": self.agent_id,
                "llm_request": llm_request_messages
            }
        )

        response = await self.llm_client.chat(
            messages=llm_request_messages
        )

        logger.info(
            "LLM response received",
            extra={
                "agent_id": self.agent_id,
                "llm_response": response
            }
        )

        return response

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
                "contact_email": self._encrypt_pii("user@example.com"),
                "phone": self._encrypt_pii("555-123-4567")
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

        return user_context
