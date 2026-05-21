"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES:
- Inter-agent calls are authenticated via AgentAuthenticator
- Privilege verification is enforced between agent calls
- Tokens are validated on every inter-agent request
"""

import logging
import os
from typing import Any, Optional

from .tech_support import TechSupportAgent


def _log_llm_request(model: str, messages: list, extra: dict = None) -> None:
    """Log an outgoing LLM request for audit purposes."""
    payload = {"model": model, "messages": messages}
    if extra:
        payload.update(extra)
    _llm_audit_logger.info(
        "LLM_REQUEST | %s",
        _json.dumps(payload, default=str),
    )


def _log_llm_response(model: str, response: Any, extra: dict = None) -> None:
    """Log an incoming LLM response for audit purposes."""
    try:
        # Support both dict-like and object-like responses from the client
        if hasattr(response, "model_dump"):
            resp_data = response.model_dump()
        elif hasattr(response, "__dict__"):
            resp_data = response.__dict__
        else:
            resp_data = response
        payload = {"model": model, "response": resp_data}
        if extra:
            payload.update(extra)
        _llm_audit_logger.info(
            "LLM_RESPONSE | %s",
            _json.dumps(payload, default=str),
        )
    except Exception as log_exc:  # pragma: no cover
        _llm_audit_logger.warning("Failed to serialise LLM response for audit: %s", log_exc)
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent


def _check_singapore_pii(content: str, label: str = "file content") -> None:
    """
    Scan content for Singapore PII categories and raise ValueError if found.
    Covers: NRIC/FIN, SingPass ID, CPF account numbers, Singapore phone numbers,
    Singapore postal codes combined with personal identifiers, and passport numbers.
    """
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

logger = logging.getLogger(__name__)

# Dedicated logger for LLM interaction audit trail
_llm_audit_logger = logging.getLogger(__name__ + ".llm_audit")

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
        self.llm_client = OpenRouterClient(
            model=self.MODEL_VERSION,
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
            "input_hash": input_hash,
            "principal": principal,
            "action": action,
            "outcome": outcome,
        }
        if extra:
            record["extra"] = extra

        _audit_logger.info(self._json.dumps(record))
        return trace_id

        # Initialize agents
        self.tech_support = TechSupportAgent(self.llm_client)
        self.finance = FinanceAgent(self.llm_client)
        self.file_processor = FileProcessorAgent()

        # Watermark signing key – in production load from a secrets manager.
        import os as _os
        self._watermark_key = _os.environ.get(
            "ORCHESTRATOR_WATERMARK_KEY", "default-watermark-key-change-in-prod"
        ).encode()

    # ------------------------------------------------------------------
    # Provenance / labeling / watermarking
    # ------------------------------------------------------------------
    def _attach_provenance(self, response: dict, request_id: str = "") -> dict:
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

        provenance = {
            "model_id": self.MODEL_ID,
            "model_version": self.MODEL_VERSION,
            "origin": "ai-orchestrator",
            "generated_at": generated_at,
            "request_id": rid,
        }

        # Deterministic watermark: HMAC-SHA256 over the stable provenance fields
        # concatenated with the serialised response content.
        import json as _json
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
            f"intelligence model ({self.MODEL_ID} v{self.MODEL_VERSION}) and may "
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
        # VULNERABILITY: Token is generated but never validated on receiving end
        self._agent_token = os.environ.get("AGENT_TOKEN")
        if not self._agent_token:
            logger.warning(
                "AGENT_TOKEN environment variable is not set; "
                "inter-agent authentication will not function correctly."
            )

        # Spawn circuit-breaker: prevent unbounded subagent spawning
        self._spawn_counter: int = 0
        self._MAX_SPAWNS: int = 10

        # Provenance signing key – load from env/secrets in production
        import os
        self._provenance_signing_key = os.environ.get(
            "PROVENANCE_SIGNING_KEY", "change-me-in-production"
        ).encode()

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
        intent = await self._classify_intent(user_message, file_contents)
        logger.info(
            "LLM interaction response: classify_intent",
            extra={
                "llm_call": "classify_intent",
                "intent_result": intent
            }
        )

        # Route to appropriate agent
        if intent == "finance":
            # VULNERABILITY: Tech support can route to finance without auth verification
            response = await self._route_to_finance(context)
        elif intent == "file_analysis":
            response = await self._route_to_file_processor(context)
        else:
            response = await self._route_to_tech_support(context)

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
            "model_id": f"orchestrator-v1/{routed_agent}",
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
            privilege_level="system",
            is_internal=True  # Flag that bypasses auth
        )

        self._validate_agent_token(self._agent_token)
        headers = {"X-Agent-Token": self._agent_token}

        response = await self.tech_support.handle(
            context=context,
            caller=caller,
            headers=headers
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

        # Token passed but receiver doesn't validate
        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
                # Token visible in logs
                "token_preview": self._agent_token[:10] + "..."
            }
        )

        response = await self.finance.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_file_processor(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to file processor agent."""
        file_contents = context.get("file_contents", [])

        if not file_contents:
            return {
                "response": "No files were provided to analyze.",
                "agent": "file_processor"
            }

        # Process files and get analysis
        analyses = []
        for file_data in file_contents:
            extracted = file_data.get("extracted_content", "")
            analyses.append(f"File: {file_data.get('filename')}\n{extracted}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question
        user_question = context.get("user_message", "")

        # Get LLM analysis of file contents
        # VULNERABILITY: File content sent directly to LLM without PII/threat scanning
        # VULNERABILITY: User's question passed through without checking for PII requests
        analysis = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful document analyst. Answer the user's questions based on the provided document content. Be direct and specific - if they ask for specific information, provide it exactly as it appears in the document."
                },
                {
                    "role": "user",
                    "content": f"""Document Content:
{combined_content}

User Question: {user_question}

Please answer the user's question based on the document content above."""
                }
            ]
        )

        sanitized_analysis = self._validate_and_sanitize_llm_output(analysis)

        return {
            "response": sanitized_analysis,
            "agent": "file_processor",
            "files_processed": len(file_contents)
        }

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

        escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": tech_support_context,
            "escalation_reason": "Financial data requested",
            "human_approval_token": human_approval_token,
        }

        logger.info(
            "Escalating from tech support to finance (human-approved)",
            extra={
                "query": query,
                "original_context": str(tech_support_context)[:100],
                "approval_token_present": True
            }
        )

                # Explicit allow list for escalation targets from tech support
        ALLOWED_ESCALATION_TARGETS = set()  # No cross-agent escalation permitted by policy

        escalation_target = escalation_context.get("escalation_target", "")
        if escalation_target not in ALLOWED_ESCALATION_TARGETS:
            logger.warning(
                "Blocked unauthorized escalation attempt from tech support",
                extra={"escalation_target": escalation_target}
            )
            return {
                "error": "Escalation target is not on the approved allow list.",
                "escalation_target": escalation_target
            }

        return await self._route_to_finance(escalation_context)

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

        # Strip non-printable control characters that survived the pattern check
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', content)

        return sanitized
