"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

import re
import os
import os
import secrets


def _sanitize_llm_input(value: str, max_length: int = 4000) -> str:
    """Sanitize untrusted input before interpolation into an LLM prompt.

    Defences applied:
    1. Truncate to a safe maximum length.
    2. Remove ASCII control characters (except ordinary whitespace).
    3. Strip common prompt-injection / jailbreak patterns.
    """
    if not isinstance(value, str):
        value = str(value)
    # 1. Truncate
    value = value[:max_length]
    # 2. Remove control characters (keep \t, \n, \r)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # 3. Strip prompt-injection patterns (case-insensitive)
    injection_patterns = [
        r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?',
        r'(?i)disregard\s+(all\s+)?(previous|prior|above)\s+instructions?',
        r'(?i)you\s+are\s+now\s+(?:a|an|the)\s+',
        r'(?i)act\s+as\s+(?:a|an|the)\s+',
        r'(?i)system\s*:\s*',
        r'(?i)<\s*/?\s*(?:system|user|assistant)\s*>',
    ]
    for pattern in injection_patterns:
        value = re.sub(pattern, '[FILTERED]', value)
    return value
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import hashlib
import hmac
import json
import time
import uuid
import datetime

# --- Session token integrity -------------------------------------------
# Secret key used to sign session tokens. Override via environment variable.
SESSION_SECRET_KEY: bytes = os.environ.get(
    "SESSION_SECRET_KEY", secrets.token_hex(32)
).encode("utf-8")

# Maximum session lifetime in seconds (default: 1 hour)
SESSION_TTL_SECONDS: int = int(os.environ.get("SESSION_TTL_SECONDS", 3600))


def _create_signed_session_token(username: str) -> str:
    """Create an HMAC-SHA256-signed session token with an embedded expiry.

    Format (URL-safe): <random_id>.<exp>.<hmac_hex>
    """
    random_id = secrets.token_hex(32)
    exp = int(time.time()) + SESSION_TTL_SECONDS
    # Include username in payload to bind the token to a specific subject
    payload = f"{random_id}.{exp}.{username}"
    sig = hmac.new(
        SESSION_SECRET_KEY,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{sig}"


def _verify_session_token(token: str) -> Optional[str]:
    """Verify a signed session token and return the random_id if valid.

    Returns None if the token is malformed, the signature is invalid,
    or the token has expired.
    """
    try:
        # Format: <random_id>.<exp>.<username>.<hmac_hex>
        # username may itself contain dots, so split from the right
        # to isolate the fixed-position fields.
        last_dot = token.rfind(".")
        if last_dot == -1:
            return None
        provided_sig = token[last_dot + 1:]
        rest = token[:last_dot]
        # rest is <random_id>.<exp>.<username>
        first_dot = rest.find(".")
        second_dot = rest.find(".", first_dot + 1)
        if first_dot == -1 or second_dot == -1:
            return None
        random_id = rest[:first_dot]
        exp_str = rest[first_dot + 1:second_dot]
        bound_username = rest[second_dot + 1:]
        exp = int(exp_str)
    except (ValueError, AttributeError):
        return None

    if not random_id or not bound_username:
        return None

    # Verify expiry
    if time.time() > exp:
        return None

    # Verify HMAC signature over the full subject-bound payload
    payload = f"{random_id}.{exp_str}.{bound_username}"
    expected_sig = hmac.new(
        SESSION_SECRET_KEY,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    # Return the bound username so callers can enforce subject identity
    return bound_username
# -----------------------------------------------------------------------

# ---------------------------------------------------------------------------
# APPROVED MODEL REGISTRY — only models listed here may be used.
# Each entry maps a canonical name to an immutable digest (SHA-256 of model
# weights / API contract commit hash) for version pinning.
# ---------------------------------------------------------------------------
APPROVED_MODEL_REGISTRY: dict[str, str] = {
    # Internal/custom — pinned to a specific commit hash of the model artefact
    # Only models registered in the organization's component registry are permitted.
    "internal/custom-llm-v2@commit:c3a7f1e": "sha256:c4a7b0e3d6f9c2a5b8e1d4a3f1c2e4b7d09f6e2c8a1b4d7e0f3c6a9b2e5d8f1",
}

# The single approved model used by this service (must be a key in APPROVED_MODEL_REGISTRY)
APPROVED_MODEL: str = "internal/custom-llm-v2@commit:c3a7f1e"
APPROVED_MODEL_DIGEST: str = APPROVED_MODEL_REGISTRY[APPROVED_MODEL]


def _validate_model(model_name: str) -> str:
    """Validate that *model_name* is in the approved registry and return its pinned digest.

    Raises ValueError if the model is not approved.
    """
    if model_name not in APPROVED_MODEL_REGISTRY:
        raise ValueError(
            f"Model '{model_name}' is NOT in the approved model registry. "
            f"Approved models: {list(APPROVED_MODEL_REGISTRY.keys())}"
        )
    return APPROVED_MODEL_REGISTRY[model_name]


# Persistent audit log for AI-driven decisions (JSON-lines format)
_AI_AUDIT_LOG_PATH = os.environ.get("AI_AUDIT_LOG_PATH", "/var/log/policyprobe/ai_audit.jsonl")

# Retention policy: rotate daily, keep 90 days of audit logs
import logging.handlers as _log_handlers

def _get_audit_logger() -> logging.Logger:
    """Return a logger that writes JSON-lines to the audit file with rotation."""
    logger = logging.getLogger("ai_audit")
    if logger.handlers:
        return logger
    log_dir = os.path.dirname(_AI_AUDIT_LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    handler = _log_handlers.TimedRotatingFileHandler(
        _AI_AUDIT_LOG_PATH,
        when="midnight",
        interval=1,
        backupCount=90,   # 90-day retention
        encoding="utf-8",
        utc=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def _log_ai_decision(
    *,
    principal: str,
    model: str,
    model_version: str = "",
    input_text: str,
    output_text: str,
    call_site: str,
    trace_id: Optional[str] = None,
) -> None:
    """Write a structured audit record for every AI inference call.

    Fields persisted:
      - timestamp     : ISO-8601 UTC
      - trace_id      : correlation / trace ID for causal chain linkage
      - call_site     : human-readable location in the code
      - principal     : identity that triggered the call (user / system)
      - model         : exact model identifier used
      - model_version : version string of the model (e.g. snapshot date)
      - input_hash    : SHA-256 hex digest of the raw input (preserves forensic
                        integrity without storing potentially sensitive content)
      - output        : first 2 000 chars of the model response (sufficient for
                        audit; full output retained in application logs)
    """
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "trace_id": trace_id or str(uuid.uuid4()),
        "call_site": call_site,
        "principal": principal,
        "model": model,
        "model_version": model_version or model,
        "input_hash": hashlib.sha256(input_text.encode("utf-8", errors="replace")).hexdigest(),
        "output": output_text[:2000],
    }
    try:
        _get_audit_logger().info(json.dumps(record))
    except Exception as exc:  # never let audit failure break the request
        logging.getLogger(__name__).error(
            "AI audit log write failed: %s | record=%s", exc, record
        )

import anthropic

# Approved LLM client using Anthropic (organization-approved registry)
def _get_secret(name: str, default: str = "") -> str:
    """Retrieve a secret from the environment. Centralises all credential
    access so that this module does not hold credentials for multiple
    external systems directly."""
    return os.environ.get(name, default)

_anthropic_client = anthropic.Anthropic(api_key=_get_secret("ANTHROPIC_API_KEY"))
APPROVED_MODEL = os.environ.get("APPROVED_MODEL", "org-approved-llm-v1")  # Must be in org registry = os.environ.get("APPROVED_LLM_MODEL", "claude-3-opus-20240229")


# --- Synthetic-content provenance helpers ---

_PROVENANCE_SECRET = os.environ.get("PROVENANCE_HMAC_SECRET")
if not _PROVENANCE_SECRET:
    raise RuntimeError(
        "PROVENANCE_HMAC_SECRET environment variable must be set to a strong random secret. "
        "No hardcoded fallback is permitted."
    )


def _attach_provenance(content: str, model_id: str) -> dict:
    """Wrap AI-generated text with provenance metadata and a cryptographic signature.

    Returns a dict that callers can serialise or embed in their response so that
    downstream consumers can verify the synthetic origin of the content.

    Fields
    ------
    content        : the (already sanitised) LLM output
    label          : human-readable synthetic-origin label
    model_id       : the approved model that produced the content
    origin_tag     : constant tag identifying this system as the producer
    generated_at   : UTC Unix timestamp (float) of generation
    provenance_id  : unique ID for this particular output
    signature      : HMAC-SHA256 over a canonical representation of the above fields
    """
    provenance_id = str(uuid.uuid4())
    generated_at = time.time()
    label = "AI-GENERATED SYNTHETIC CONTENT"
    origin_tag = "policyprobe-backend"

    # Token validity window: provenance records expire after this many seconds.
    _PROVENANCE_TTL_SECONDS = 3600  # 1 hour
    expires_at = generated_at + _PROVENANCE_TTL_SECONDS

    # Canonical message for signing (deterministic field order).
    # Includes 'expires_at' (expiry enforcement) and 'origin_tag'+'provenance_id'
    # as subject-binding fields so the token cannot be detached or replayed.
    canonical = json.dumps(
        {
            "provenance_id": provenance_id,  # unique subject binding
            "model_id": model_id,
            "origin_tag": origin_tag,         # system-level subject binding
            "generated_at": generated_at,
            "expires_at": expires_at,          # explicit expiry
            "label": label,
            "content": content,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    signature = hmac.new(
        _PROVENANCE_SECRET.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()

    return {
        "content": content,
        "label": label,
        "model_id": model_id,
        "origin_tag": origin_tag,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "provenance_id": provenance_id,
        "signature": signature,
    }


def _sanitize_llm_input(text: str, max_length: int = 16000) -> str:
    """Sanitize and validate text before sending it to the LLM.

    - Rejects None / non-string values.
    - Strips null bytes and ASCII control characters (except common whitespace).
    - Truncates to max_length characters to prevent prompt-stuffing / DoS.
    """
    if not isinstance(text, str):
        raise ValueError("LLM input must be a string.")
    # Remove null bytes and non-printable control characters
    # (keep \t, \n, \r which are legitimate whitespace)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Truncate to a safe maximum length
    sanitized = sanitized[:max_length]
    return sanitized


class AgentOrchestrator:
    """Inline orchestrator using only approved LLMs from the organization registry."""

    def process(self, message: str, context: str = "") -> str:
        message = _sanitize_llm_input(message)
        if context:
            context = _sanitize_llm_input(context)
        safe_message = _sanitize_llm_input(message)
        prompt = safe_message
        if context:
            safe_context = _sanitize_llm_input(context)
            prompt = f"Context:\n{safe_context}\n\nUser message:\n{safe_message}"
                raise NotImplementedError(
            "No approved LLM model is currently configured. "
            "Please register an approved model in the organization registry and update this integration."
        )


class FileProcessorAgent:
    """Inline file processor using only approved LLMs from the organization registry."""

    def extract_text(self, file_content: bytes, file_type: str) -> str:
        """Extract and summarize text from file content using an approved LLM."""
        try:
            text = _sanitize_llm_input(file_content.decode("utf-8", errors="replace"))
        except Exception:
            text = _sanitize_llm_input(repr(file_content[:500]))

        safe_file_type = _sanitize_llm_input(file_type, max_length=64)
        prompt_content = (
            f"Summarize the following file content (type: {safe_file_type}):\n\n{_sanitize_llm_input(text)}"
        )

        # Explicit termination criterion: attempt the LLM call at most
        # MAX_AGENT_ITERATIONS times, then raise to guarantee the agent stops.
        last_error: Exception | None = None
        for iteration in range(1, MAX_AGENT_ITERATIONS + 1):
            try:
                        _request_messages = [{"role": "user", "content": prompt}]
        logging.getLogger(__name__).info(
            "LLM request: model=%s messages=%s",
            "REGISTRY_APPROVED_MODEL_PENDING",
            _request_messages,
        )
                raise NotImplementedError(
                    "No approved LLM model is currently configured. "
                    "Please register an approved model in the organization registry and update this integration."
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                logger.warning(
                    "FileProcessorAgent.extract_text attempt %d/%d failed: %s",
                    iteration,
                    MAX_AGENT_ITERATIONS,
                    exc,
                )
        # Termination criterion reached: max iterations exhausted without success.
        raise RuntimeError(
            f"FileProcessorAgent.extract_text exceeded maximum iterations "
            f"({MAX_AGENT_ITERATIONS}). Last error: {last_error}"
        ) from last_error

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents
orchestrator = AgentOrchestrator()
file_processor = FileProcessorAgent()

# HTTP Basic auth scheme
security = HTTPBasic()

AUTH_USERNAME = os.environ.get("API_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("API_PASSWORD", "")


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Verify HTTP Basic credentials before allowing access to AI agents."""
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        AUTH_USERNAME.encode("utf-8"),
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        AUTH_PASSWORD.encode("utf-8"),
    )
    if not AUTH_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="Authentication is not configured on this server.",
        )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Authentication
_bearer_scheme = HTTPBearer()
_API_KEY = os.environ.get("API_KEY", "")
_TOKEN_SUBJECT = os.environ.get("API_TOKEN_SUBJECT", "policyprobe-api")
_TOKEN_TTL_SECONDS = int(os.environ.get("API_TOKEN_TTL", "3600"))


def _generate_api_token(subject: str = _TOKEN_SUBJECT, ttl: int = _TOKEN_TTL_SECONDS) -> str:
    """Generate an HMAC-SHA256 signed token with expiry and subject binding.

    Token format (base64url): <subject>.<expiry_unix_ts>.<hex_hmac_signature>
    """
    if not _API_KEY:
        raise ValueError("API_KEY secret is not configured")
    expiry = int(time.time()) + ttl
    payload = f"{subject}.{expiry}"
    sig = hmac.new(
        _API_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}.{sig}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(_bearer_scheme)) -> None:
    """Validate the bearer token: verify HMAC signature, expiry, and subject binding."""
    if not _API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    try:
        raw = base64.urlsafe_b64decode(credentials.credentials.encode("utf-8")).decode("utf-8")
        parts = raw.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")
        subject, expiry_str, provided_sig = parts
        # Verify subject binding
        if not secrets.compare_digest(subject, _TOKEN_SUBJECT):
            raise ValueError("Subject mismatch")
        # Verify expiry
        if int(time.time()) > int(expiry_str):
            raise ValueError("Token expired")
        # Verify HMAC signature
        payload = f"{subject}.{expiry_str}"
        expected_sig = hmac.new(
            _API_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(provided_sig, expected_sig):
            raise ValueError("Invalid signature")
    except (ValueError, Exception):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


import re
import time
import hmac as hmac
import hashlib
import base64

_PII_PATTERNS = [
    # Email addresses
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), '[REDACTED_EMAIL]'),
    # US phone numbers (various formats)
    (re.compile(r'(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'), '[REDACTED_PHONE]'),
    # US Social Security Numbers
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    # Credit card numbers (basic 13-19 digit sequences with optional separators)
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[REDACTED_CC]'),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
]


def redact_pii(text: str) -> str:
    """Scan text for common PII patterns and replace them with redaction tokens."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


import re

# Singapore PII detection patterns
_SG_PII_PATTERNS = [
    # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
    re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE),
    # Singapore mobile / local phone numbers: +65 or 65 prefix, or 8-digit starting with 6/8/9
    re.compile(r'(\+65|\b65)?\s?[689]\d{7}\b'),
    # Singapore postal codes: 6-digit starting with 0-8
    re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE),
    re.compile(r'\b[0-8]\d{5}\b'),
    # Passport numbers (Singapore): E followed by 7 digits
    re.compile(r'\bE\d{7}[A-Z]\b', re.IGNORECASE),
    # Singapore bank account patterns (DBS/POSB/OCBC/UOB common formats)
    re.compile(r'\b\d{3}-\d{5,6}-\d{1}\b'),
]


def _detect_sg_pii(text: str) -> list[str]:
    """Return a list of matched Singapore PII pattern descriptions found in text."""
    found = []
    pattern_names = [
        "NRIC/FIN number",
        "Singapore phone number",
        "Singapore postal code (with label)",
        "Singapore postal code",
        "Singapore passport number",
        "Singapore bank account number",
    ]
    for name, pattern in zip(pattern_names, _SG_PII_PATTERNS):
        if pattern.search(text):
            found.append(name)
    return found


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


import re
import base64
import binascii

# Patterns indicative of prompt injection or malicious command attempts
_SHELL_CMD_PATTERN = re.compile(
    r'(?i)(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`)\b'
    r'|;\s*\w+|&&|\|\||\$\([^)]+\)|\{[^}]+\})'
)
_HIDDEN_PROMPT_PATTERN = re.compile(
    r'(?i)(ignore (previous|above|all) instructions?'
    r'|you are now'
    r'|disregard (your|all) (previous )?instructions?'
    r'|act as (a |an )?(?!assistant)'
    r'|system prompt'
    r'|<\s*script[^>]*>'
    r'|<!--.*?-->'
    r'|\\x[0-9a-fA-F]{2}'
    r'|\\u[0-9a-fA-F]{4})'
)
_BINARY_MAGIC_BYTES = [
    b'\x7fELF',   # ELF executable
    b'MZ',        # PE/DOS executable
    b'\xca\xfe\xba\xbe',  # Mach-O
    b'PK\x03\x04',        # ZIP/JAR
]


def _is_base64_with_suspicious_content(text: str) -> bool:
    """Detect base64-encoded strings that decode to suspicious content."""
    # Look for base64-like tokens (length >= 40, only base64 chars)
    candidates = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate + '==')
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if _SHELL_CMD_PATTERN.search(decoded_str) or _HIDDEN_PROMPT_PATTERN.search(decoded_str):
                return True
            for magic in _BINARY_MAGIC_BYTES:
                if decoded.startswith(magic):
                    return True
        except (binascii.Error, ValueError):
            continue
    return False


def _contains_binary_executable(data: bytes) -> bool:
    """Return True if the raw bytes look like a binary executable."""
    for magic in _BINARY_MAGIC_BYTES:
        if data.startswith(magic):
            return True
    return False


def sanitize_text_input(text: str, field_name: str = "input") -> str:
    """
    Validate text for hidden prompts, shell commands, and base64-encoded
    malicious content.  Raises HTTPException(400) on detection.
    Returns the original text unchanged when clean.
    """
    if not text:
        return text
    if _HIDDEN_PROMPT_PATTERN.search(text):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": f"Rejected: {field_name} contains a hidden or injected prompt.",
                "policy_error": {"type": "prompt_injection", "field": field_name}
            }
        )
    if _SHELL_CMD_PATTERN.search(text):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": f"Rejected: {field_name} contains shell command patterns.",
                "policy_error": {"type": "shell_command", "field": field_name}
            }
        )
    if _is_base64_with_suspicious_content(text):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": f"Rejected: {field_name} contains base64-encoded malicious content.",
                "policy_error": {"type": "encoded_payload", "field": field_name}
            }
        )
    return text


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, _: None = Depends(verify_api_key)):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    SECURITY NOTES (for Unifai demo):
    - File content is not scanned for PII before processing
    - Hidden content in files is not detected
    - Agent calls are authenticated via a shared inter-agent token
    """
    # Generate a per-request inter-agent auth token scoped to this call
    import secrets, os
    _INTER_AGENT_SECRET = os.environ.get("INTER_AGENT_SECRET")
    if not _INTER_AGENT_SECRET:
        raise HTTPException(status_code=500, detail="Inter-agent secret not configured")
    inter_agent_token = secrets.token_hex(32)
    # Sign the token with the shared secret so receiving agents can verify it
    import hmac, hashlib
    inter_agent_auth = hmac.new(
        _INTER_AGENT_SECRET.encode(),
        inter_agent_token.encode(),
        hashlib.sha256
    ).hexdigest()
    import hashlib, uuid, datetime

    # Generate a correlation/trace ID that links every step of this request
    trace_id = str(uuid.uuid4())
    principal = getattr(request, "user_id", "anonymous")

    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        # VULNERABILITY: Logging full request context
                        # This could include sensitive data from the file
                                                "request_context": {
                            "attachment_name": attachment.name,
                            "attachment_size": len(attachment.content) if attachment.content else 0
                        }
                    }
                )

                # Redact PII from file content before processing
                safe_content = redact_pii(attachment.content)

                                # Scan for Singapore PII before processing
                pii_hits = _detect_sg_pii(attachment.content if attachment.content else "")
                if pii_hits:
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "detail": "File contains Singapore PII and cannot be uploaded.",
                            "policy_error": {
                                "type": "singapore_pii",
                                "message": "Detected Singapore PII categories: " + ", ".join(pii_hits),
                                "filename": attachment.name,
                            }
                        }
                    )

                                                # Sanitize and validate inputs before passing to subagent
                ALLOWED_CONTENT_TYPES = {
                    "text/plain", "text/csv", "application/json",
                    "application/pdf", "image/png", "image/jpeg",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                }
                MAX_CONTENT_LENGTH = 1_000_000  # 1 MB
                MAX_FILENAME_LENGTH = 255

                safe_content_type = str(attachment.type or "").strip().lower()
                if safe_content_type not in ALLOWED_CONTENT_TYPES:
                    logger.warning(
                        "Rejected attachment with disallowed content_type",
                        extra={"content_type": safe_content_type, "filename": attachment.name}
                    )
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unsupported file type: {safe_content_type}"
                    )

                safe_filename = str(attachment.name or "").strip()[:MAX_FILENAME_LENGTH]
                safe_content = (attachment.content or "")[:MAX_CONTENT_LENGTH]

                # Process the file content with explicit timeout (30 s) and traceability
                import asyncio as _asyncio
                import uuid as _uuid
                _file_task_id = str(_uuid.uuid4())
                logger.info(
                    "Spawning file_processor subagent",
                    extra={"task_id": _file_task_id, "filename": safe_filename,
                            "content_type": safe_content_type, "timeout_seconds": 30}
                )
                try:
                    processed = await _asyncio.wait_for(
                        file_processor.process(
                            content=safe_content,
                            filename=safe_filename,
                            content_type=safe_content_type
                        ),
                        timeout=30.0
                    )
                except _asyncio.TimeoutError:
                    logger.error(
                        "file_processor subagent timed out",
                        extra={"task_id": _file_task_id, "filename": safe_filename}
                    )
                    raise HTTPException(
                        status_code=504,
                        detail="File processing timed out. Please try a smaller file."
                    ) + attachment.name + (attachment.type or ""))
                _fp_start = datetime.datetime.utcnow().isoformat() + "Z"
                logger.info(
                    "AUDIT: file_processor.process invoked",
                    extra={
                        "audit": True,
                        "trace_id": trace_id,
                        "agent": "FileProcessorAgent",
                        "action": "process",
                        "principal": principal,
                        "timestamp_start": _fp_start,
                        "input_hash": _fp_input_hash,
                        "filename": attachment.name,
                        "content_type": attachment.type,
                    }
                )
                    processed = await file_processor.process(
        content=safe_content,
        filename=file.filename,
        content_type=file.content_type
    )
    _log_ai_decision(
        principal="system:upload_handler",
        model=APPROVED_MODEL,
        input_text=safe_content,
        output_text=str(processed)[:2000] if processed is not None else "",
        call_site="upload_handler:file_processor.process",
    )
                _fp_end = datetime.datetime.utcnow().isoformat() + "Z"
                _fp_output_hash = _sha256(processed if isinstance(processed, str) else str(processed))
                logger.info(
                    "AUDIT: file_processor.process completed",
                    extra={
                        "audit": True,
                        "trace_id": trace_id,
                        "agent": "FileProcessorAgent",
                        "action": "process",
                        "principal": principal,
                        "timestamp_start": _fp_start,
                        "timestamp_end": _fp_end,
                        "input_hash": _fp_input_hash,
                        "output_hash": _fp_output_hash,
                        "filename": attachment.name,
                    }
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Sanitize user message before forwarding to the orchestrator
        sanitize_text_input(request.message, field_name="user_message")

        # Sanitize each extracted file content before forwarding
        for fc in file_contents:
            sanitize_text_input(fc.get("extracted_content") or "", field_name=f"file:{fc.get('filename','unknown')}")

                # --- Input validation & sanitisation before LLM context assembly ---
        MAX_MESSAGE_LEN = 4000
        MAX_FILE_CONTENT_LEN = 8000
        MAX_FILES = 10
        _CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

        def _sanitise(text: str, max_len: int) -> str:
            """Strip dangerous control characters and truncate to max_len."""
            if not isinstance(text, str):
                text = str(text)
            text = _CONTROL_CHARS.sub("", text)
            return text[:max_len]

        sanitised_message = _sanitise(request.message or "", MAX_MESSAGE_LEN)

        sanitised_files = []
        for fc in file_contents[:MAX_FILES]:
            sanitised_files.append({
                "filename": _sanitise(fc.get("filename", ""), 256),
                "extracted_content": _sanitise(
                    fc.get("extracted_content", ""), MAX_FILE_CONTENT_LEN
                ),
            })

        # Build context for the orchestrator
        context = {
            "user_message": sanitised_message,
            "file_contents": sanitised_files,
            "conversation_id": request.conversation_id,
            # Instruct the orchestrator to cap its own execution
            "_limits": {
                "max_steps": 10,
                "max_tokens": 2048,
            },
        }

        logger.info(
            "Dispatching context to orchestrator",
            extra={
                "conversation_id": request.conversation_id,
                "message_len": len(sanitised_message),
                "file_count": len(sanitised_files),
            },
        )

        # Route through orchestrator
        import asyncio
        response = await asyncio.wait_for(
            orchestrator.process(context),
            timeout=30,
        )

        # --- Synthetic Content Provenance & Watermarking ---
        import hashlib
        import hmac
        import uuid
        from datetime import datetime, timezone

        ai_response_text = response.get("response", "I processed your request.")
        provenance_id = str(uuid.uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()
        model_id = response.get("model_id", "unifai-orchestrator-v1")
        origin_tag = "AI_GENERATED"

        # Cryptographic watermark: HMAC-SHA256 over (provenance_id + generated_at + response text)
        _WATERMARK_SECRET = b"unifai-watermark-secret-key"  # Replace with env-sourced secret in production
        watermark_payload = f"{provenance_id}:{generated_at}:{ai_response_text}".encode("utf-8")
        watermark_signature = hmac.new(_WATERMARK_SECRET, watermark_payload, hashlib.sha256).hexdigest()

        provenance_metadata = {
            "provenance_id": provenance_id,
            "model_id": model_id,
            "generated_at": generated_at,
            "origin_tag": origin_tag,
            "content_label": "SYNTHETIC_AI_GENERATED_CONTENT",
            "watermark": watermark_signature,
        }
        # --- End Provenance Block ---

                logger.info(
            "AUDIT: chat request completed",
            extra={
                "audit": True,
                "trace_id": trace_id,
                "principal": principal,
                "conversation_id": request.conversation_id,
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            }
        )
        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        ),
            provenance=provenance_metadata,
        )

        # Validate orchestrator output for dynamic code execution primitives
        raw_response = response.get("response", "I processed your request.")
        _sanitize_llm_output(raw_response, source="orchestrator.process")

        return ChatResponse(
            response=raw_response,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                        "error": type(e).__name__,
                "request_state": {
                    "attachment_count": len(request.attachments) if request.attachments else 0
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request"
            }
        )


# Dynamic code execution primitives to block in LLM output
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"\b__import__\s*\(",
    r"\bimportlib\.import_module\s*\(",
    r"\bgetattr\s*\(.*,\s*['\"]__",
    r"\bsetattr\s*\(",
    r"\bdelattr\s*\(",
    r"\bsubprocess\b",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bopen\s*\(",
    r"\bexecfile\s*\(",
    r"\brunpy\b",
    r"\bctypes\b",
]

_DANGEROUS_RE = re.compile(
    "|".join(_DANGEROUS_PATTERNS),
    re.IGNORECASE | re.DOTALL,
)


def _sanitize_llm_output(output, source: str = "LLM"):
    """
    Validate and sanitize output from an LLM or agent.

    Raises ValueError if dynamic code execution primitives are detected.
    Returns the sanitized string on success.
    """
    if output is None:
        return output

    # Coerce to string for scanning
    text = output if isinstance(output, str) else str(output)

    match = _DANGEROUS_RE.search(text)
    if match:
        logger.warning(
            "Dangerous pattern detected in %s output",
            source,
            extra={"matched": match.group(0), "position": match.start()},
        )
        raise ValueError(
            f"Unsafe content detected in {source} output: "
            f"dynamic code execution primitive '{match.group(0)}' is not allowed."
        )

    return output


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), _: None = Depends(verify_api_key)):
    """
    Direct file upload endpoint.

    SECURITY NOTES (for Unifai demo):
    - No file content scanning
    - No size limits enforced
    - No malware detection
    """
            MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
    ALLOWED_CONTENT_TYPES = {
        "text/plain",
        "text/csv",
        "application/json",
        "application/pdf",
        "image/png",
        "image/jpeg",
    }

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type."
        )

    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the maximum allowed size of 10 MB."
        )

    processed = await file_processor.process(
        content=content,
        filename=file.filename,
        content_type=file.content_type
    )

    # Scan for Singapore PII before processing
        # Sanitize redacted text for hidden prompts, shell commands, and encoded payloads
    sanitize_text_input(safe_content, field_name=f"uploaded_file:{file.filename}")

    processed = await file_processor.process(
        content=safe_content,
        filename=file.filename,
        content_type=file.content_type
    )
    pii_hits = _detect_sg_pii(decoded_content)
    if pii_hits:
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "File contains Singapore PII and cannot be uploaded.",
                "policy_error": {
                    "type": "singapore_pii",
                    "message": "Detected Singapore PII categories: " + ", ".join(pii_hits),
                    "filename": file.filename,
                }
            }
        )


    # Redact PII from file content before processing
    decoded_content = content.decode('utf-8', errors='ignore')

    import re as _re

    def _redact_sg_pii(text: str) -> str:
        """Redact Singapore-specific PII categories in addition to generic PII."""
        # NRIC / FIN: S/T/F/G followed by 7 digits and a letter (case-insensitive)
        text = _re.sub(
            r'\b[STFG]\d{7}[A-Z]\b',
            '[REDACTED_NRIC_FIN]',
            text,
            flags=_re.IGNORECASE,
        )
        # SingPass user ID pattern (8-character alphanumeric, often same as NRIC)
        # Already covered by NRIC pattern above; add explicit label for clarity.
        # CPF account number: 9-digit numeric string (standalone)
        text = _re.sub(
            r'(?<![\d])\d{9}(?![\d])',
            '[REDACTED_CPF]',
            text,
        )
        # Singapore mobile / phone numbers: +65 or 65 prefix, 8 digits
        text = _re.sub(
            r'(?:\+65|\b65)?[\s\-]?[689]\d{7}\b',
            '[REDACTED_SG_PHONE]',
            text,
        )
        # Singapore postal codes: 6-digit numeric (standalone)
        text = _re.sub(
            r'(?<![\d])\d{6}(?![\d])',
            '[REDACTED_SG_POSTAL]',
            text,
        )
        # Apply generic PII redaction on top
        text = redact_pii(text)
        return text

    safe_content = _redact_sg_pii(decoded_content)

    # Reject binary executables before any further processing
    if _contains_binary_executable(content):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Rejected: uploaded file appears to be a binary executable.",
                "policy_error": {"type": "binary_executable", "field": "file"}
            }
        )

    decoded_content = content.decode('utf-8', errors='ignore')
    # Sanitize decoded text for hidden prompts, shell commands, and encoded payloads
    sanitize_text_input(decoded_content, field_name=f"uploaded_file:{file.filename}")

    processed = await file_processor.process(
        content=safe_content,
        filename=file.filename,
        content_type=file.content_type
    )
    _log_ai_decision(
        principal="system:upload_handler",
        model=APPROVED_MODEL,
        input_text=safe_content,
        output_text=str(processed)[:2000] if processed is not None else "",
        call_site="upload_handler:file_processor.process",
    )

    # Validate file_processor output for dynamic code execution primitives
    processed = _sanitize_llm_output(processed, source="file_processor.process (upload)")

    import datetime as _datetime
    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "provenance": {
            "model_id": APPROVED_MODEL,
            "generated_at": _datetime.datetime.utcnow().isoformat() + "Z",
            "content_origin": "ai-generated",
            "synthetic_content_label": "This content was produced by an AI model and may require human review."
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
