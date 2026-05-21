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
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import openai

# Approved LLM client using OpenAI (organization-approved registry)
_openai_client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
APPROVED_MODEL = "gpt-4o"


class AgentOrchestrator:
    """Inline orchestrator using only approved LLMs from the organization registry."""

    def process(self, message: str, context: str = "") -> str:
        prompt = message
        if context:
            prompt = f"Context:\n{context}\n\nUser message:\n{message}"
        response = _openai_client.chat.completions.create(
            model=APPROVED_MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class FileProcessorAgent:
    """Inline file processor using only approved LLMs from the organization registry."""

    def extract_text(self, file_content: bytes, file_type: str) -> str:
        """Extract and summarize text from file content using an approved LLM."""
        try:
            text = file_content.decode("utf-8", errors="replace")
        except Exception:
            text = repr(file_content[:500])
        response = _openai_client.chat.completions.create(
            model=APPROVED_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": f"Summarize the following file content (type: {file_type}):\n\n{text[:4000]}",
                }
            ],
        )
        return response.choices[0].message.content

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
AUTH_PASSWORD = os.environ.get("API_PASSWORD", "changeme")


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
    if not (correct_username and correct_password):
                raise HTTPException(
            status_code=500,
            detail="An internal error occurred processing your request."
        )
    return credentials.username

# Authentication
_bearer_scheme = HTTPBearer()
_API_KEY = os.environ.get("API_KEY", "")


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(_bearer_scheme)) -> None:
    """Validate the bearer token against the configured API key."""
    if not _API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if credentials.credentials != _API_KEY:
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
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type,
                    auth_token=inter_agent_auth
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
    decoded_content = content.decode('utf-8', errors='ignore')
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
    safe_content = redact_pii(decoded_content)

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
        content=decoded_content,
        filename=file.filename,
        content_type=file.content_type
    )

    processed = await file_processor.process(
        content=content.decode('utf-8', errors='ignore'),
        filename=file.filename,
        content_type=file.content_type
    )
    # Validate file_processor output for dynamic code execution primitives
    processed = _sanitize_llm_output(processed, source="file_processor.process (upload)")

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
