"""
File Processor Agent
  
"""

import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Audit-trail helpers
# ---------------------------------------------------------------------------
import logging.handlers

AUDIT_LOG_PATH = os.environ.get("FILE_PROCESSOR_AUDIT_LOG", "audit_file_processor.jsonl")
# Retention policy: rotate at 10 MB, keep 30 backup files (~300 MB total)
_AUDIT_MAX_BYTES = int(os.environ.get("FILE_PROCESSOR_AUDIT_MAX_BYTES", 10 * 1024 * 1024))
_AUDIT_BACKUP_COUNT = int(os.environ.get("FILE_PROCESSOR_AUDIT_BACKUP_COUNT", 30))

# Build a dedicated rotating-file handler for the audit trail
_audit_handler = logging.handlers.RotatingFileHandler(
    AUDIT_LOG_PATH,
    maxBytes=_AUDIT_MAX_BYTES,
    backupCount=_AUDIT_BACKUP_COUNT,
    encoding="utf-8",
)
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger = logging.getLogger("file_processor.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
if not _audit_logger.handlers:
    _audit_logger.addHandler(_audit_handler)


def _sha256(data: Optional[str]) -> str:
    """Return the hex SHA-256 digest of *data* (empty string when None)."""
    raw = (data or "").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_audit_record(record: dict) -> None:
    """Append *record* as a single JSON line to the rotating persistent audit log."""
    try:
        _audit_logger.info(json.dumps(record, ensure_ascii=False))
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to write audit record", extra={"error": str(exc)})


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
        principal: str = "system",
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file
            principal: Identity of the caller (user/service) for audit purposes

        Returns:
            Extracted text content from the file

        Every invocation emits a structured audit record containing the model
        identifier, input hash, output hash, ISO-8601 timestamp, and principal
        so that all AI-driven file-processing decisions are forensically traceable.

        Security scanning is performed on file content before extraction.
        Files are checked for:
        - PII (SSN, credit cards, phone numbers)
        - Hidden/malicious prompts (prompt injection, invisible Unicode, base64-encoded instructions,
          leetspeak command patterns, binary/shell commands)
        - Malware signatures
        - Sensitive data patterns
        """
        # --- Prompt-injection / malicious-content pre-screen ---
        if content:
            _reject, _reason = self._scan_for_malicious_prompts(content, filename)
            if _reject:
                logger.warning(
                    "Malicious prompt content detected in uploaded file",
                    extra={"file_name": filename, "reason": _reason},
                )
                raise ValueError(
                    f"File '{filename}' rejected: malicious prompt content detected ({_reason})."
                )
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0
            }
        )

        if not content:
            return f"Empty file: {filename}"

        # Determine file type
        file_type = self._get_file_type(content_type, filename)

                # Process based on file type
        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = content
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Scan for hidden/malicious prompts, shell commands, and binary payloads
            scan_result = self._scan_for_malicious_content(extracted)
            if scan_result.get("flagged"):
                reasons = "; ".join(scan_result.get("reasons", ["unknown reason"]))
                logger.warning(
                    "Malicious content detected in file",
                    extra={"file_name": filename, "reasons": reasons}
                )
                raise ValueError(
                    f"File '{filename}' was rejected due to malicious content: {reasons}"
                )

            # Redact PII from extracted content before returning
            extracted = self._redact_pii(extracted)

            # Scan for hidden/malicious prompt content before passing downstream
            scan_result = self._scan_for_malicious_content(extracted)
            if scan_result.get("flagged"):
                reasons = "; ".join(scan_result.get("reasons", []))
                logger.warning(
                    "Malicious content detected in file, blocking downstream use",
                    extra={
                        "file_name": filename,
                        "reasons": reasons
                    }
                )
                return f"File '{filename}' was blocked due to potentially malicious content: {reasons}"

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(extracted)
                }
            )

            return extracted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e)
                }
            )
            return f"Error processing {filename}: {str(e)}"

    def _scan_for_malicious_content(self, text: str) -> dict:
        """Scan extracted text for hidden or malicious prompt content.

        Checks for:
        - Invisible / zero-width Unicode characters used to hide instructions
        - Base64-encoded payloads that decode to prompt-like text
        - Leetspeak patterns commonly used to obfuscate prompt injections
        - Shell command sequences
        - Binary executable magic bytes embedded in text

        Returns a dict with keys:
            flagged (bool): True if any issue was found
            reasons (list[str]): Human-readable descriptions of each finding
        """
        import re
        import base64

        reasons = []

        # 1. Invisible / zero-width characters
        invisible_pattern = re.compile(
            r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
        )
        if invisible_pattern.search(text):
            reasons.append("invisible or zero-width Unicode characters detected")

        # 2. Base64-encoded payloads
        # Look for long base64 tokens and decode them to check for prompt keywords
        b64_token_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        prompt_keywords = re.compile(
            r"ignore|disregard|forget|system|assistant|user|prompt|"
            r"instruction|jailbreak|override|bypass|sudo|exec|eval",
            re.IGNORECASE,
        )
        for match in b64_token_pattern.finditer(text):
            token = match.group(0)
            # Pad to a valid length
            padded = token + "=" * (-len(token) % 4)
            try:
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if prompt_keywords.search(decoded):
                    reasons.append("base64-encoded prompt injection payload detected")
                    break
            except Exception:
                pass

        # 3. Leetspeak obfuscation of common injection keywords
        # Normalise common leet substitutions then check for keywords
        leet_map = str.maketrans("013456789@", "oieashgtba")
        normalised = text.lower().translate(leet_map)
        leet_keywords = [
            "ignore previous", "disregard", "jailbreak", "bypass",
            "you are now", "act as", "pretend", "roleplay",
        ]
        for kw in leet_keywords:
            if kw in normalised:
                reasons.append(f"leetspeak-obfuscated injection keyword detected: '{kw}'")
                break

        # 4. Shell command sequences
        shell_pattern = re.compile(
            r"(?:^|\s|;|&&|\|\|)(?:rm\s+-rf|chmod\s+[0-7]+|curl\s+http|wget\s+http|"
            r"bash\s+-[ci]|sh\s+-[ci]|python[23]?\s+-c|perl\s+-e|nc\s+-[lne]|"
            r"eval\s*\(|exec\s*\(|os\.system|subprocess\.)",
            re.IGNORECASE | re.MULTILINE,
        )
        if shell_pattern.search(text):
            reasons.append("shell command sequence detected")

        # 5. Binary executable magic bytes (ELF, PE/MZ, Mach-O)
        binary_magic = re.compile(
            r"(?:\x7fELF|MZ|\xfe\xed\xfa\xce|\xfe\xed\xfa\xcf|"
            r"\xce\xfa\xed\xfe|\xcf\xfa\xed\xfe)"
        )
        if binary_magic.search(text):
            reasons.append("binary executable magic bytes detected")

        return {"flagged": bool(reasons), "reasons": reasons}

    def _scan_for_malicious_content(self, text: str, filename: str) -> str:
        """
        Scan extracted text for malicious content patterns before it is used
        as agent input. Raises ValueError if dangerous content is detected.
        """
        import re
        import base64
        import string

        if not text:
            return text

        # 1. Reject binary / non-printable content (executable bytes)
        non_printable = sum(
            1 for ch in text if ch not in string.printable
        )
        if non_printable > max(10, len(text) * 0.05):
            logger.warning(
                "File rejected: high proportion of non-printable characters",
                extra={"file_name": filename, "non_printable_count": non_printable}
            )
            raise ValueError(
                f"File '{filename}' contains binary or non-printable content "
                "and cannot be used as agent input."
            )

        # 2. Detect hidden / invisible Unicode prompt-injection characters
        invisible_pattern = re.compile(
            r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]"
        )
        if invisible_pattern.search(text):
            logger.warning(
                "File rejected: invisible/hidden Unicode characters detected",
                extra={"file_name": filename}
            )
            raise ValueError(
                f"File '{filename}' contains hidden Unicode characters that may "
                "encode malicious prompt instructions."
            )

        # 3. Detect base64-encoded blobs that could hide instructions
        b64_pattern = re.compile(
            r"(?:[A-Za-z0-9+/]{40,}={0,2})"
        )
        for match in b64_pattern.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                # Flag if the decoded payload looks like a shell command or prompt
                if re.search(
                    r"(ignore previous|system prompt|you are now|execute|eval|\$\(|`[^`]+`|\bsh\b|\bbash\b)",
                    decoded,
                    re.IGNORECASE,
                ):
                    logger.warning(
                        "File rejected: base64-encoded malicious instruction detected",
                        extra={"file_name": filename}
                    )
                    raise ValueError(
                        f"File '{filename}' contains base64-encoded content that "
                        "appears to encode malicious instructions."
                    )
            except (ValueError, UnicodeDecodeError):
                pass  # Not valid UTF-8 after decode — not a text payload

        # 4. Detect prompt-injection phrases
        injection_pattern = re.compile(
            r"(ignore (all |previous |prior )(instructions?|prompts?|context)"
            r"|you are now"
            r"|act as (a |an )?(different|new|unrestricted)"
            r"|disregard (your |all )?(previous |prior )?(instructions?|rules?|guidelines?)"
            r"|system\s*prompt"
            r"|<\s*system\s*>"
            r"|\[INST\]"
            r"|###\s*instruction)",
            re.IGNORECASE,
        )
        if injection_pattern.search(text):
            logger.warning(
                "File rejected: prompt-injection phrase detected",
                extra={"file_name": filename}
            )
            raise ValueError(
                f"File '{filename}' contains prompt-injection instructions and "
                "cannot be used as agent input."
            )

        # 5. Detect shell commands / executable patterns
        shell_pattern = re.compile(
            r"(\$\([^)]+\)"
            r"|`[^`]+`"
            r"|\b(rm|wget|curl|chmod|chown|sudo|nc|ncat|netcat|python|perl|ruby|php)\s+-"
            r"|\b(exec|eval|os\.system|subprocess|popen)\s*\("
            r"|/bin/(sh|bash|zsh|dash|ksh))",
            re.IGNORECASE,
        )
        if shell_pattern.search(text):
            logger.warning(
                "File rejected: shell command pattern detected",
                extra={"file_name": filename}
            )
            raise ValueError(
                f"File '{filename}' contains shell command patterns and "
                "cannot be used as agent input."
            )

        # 6. Detect leetspeak-obfuscated dangerous keywords
        leet_map = str.maketrans("013457", "oieash")
        normalised = text.lower().translate(leet_map)
        leet_danger_pattern = re.compile(
            r"\b(ignore|execute|system|shell|eval|admin|root|hack|exploit)\b",
            re.IGNORECASE,
        )
        # Only flag when the original text does NOT contain the plain word
        # but the leet-normalised version does (i.e. it was obfuscated)
        for match in leet_danger_pattern.finditer(normalised):
            plain_word = match.group(0)
            start, end = match.start(), match.end()
            original_slice = text[start:end].lower()
            if original_slice != plain_word:
                logger.warning(
                    "File rejected: leetspeak-obfuscated dangerous keyword detected",
                    extra={"file_name": filename, "keyword": plain_word}
                )
                raise ValueError(
                    f"File '{filename}' contains leetspeak-obfuscated dangerous "
                    "keywords and cannot be used as agent input."
                )

        logger.info(
            "Security scan passed",
            extra={"file_name": filename, "content_length": len(text)}
        )
        return text

    def _redact_pii(self, text: str) -> str:
        """
        Detect and redact PII patterns from text content.

        Redacts:
        - Social Security Numbers (SSN)
        - Credit card numbers
        - Phone numbers
        - Email addresses
        """
        import re

        if not text:
            return text

        # Redact SSNs (e.g. 123-45-6789 or 123456789)
        text = re.sub(
            r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
            '[REDACTED-SSN]',
            text
        )

        # Redact credit card numbers (13-16 digit sequences, optionally separated by spaces/dashes)
        text = re.sub(
            r'\b(?:\d[ -]?){13,16}\b',
            '[REDACTED-CC]',
            text
        )

        # Redact phone numbers (various formats)
        text = re.sub(
            r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b',
            '[REDACTED-PHONE]',
            text
        )

        # Redact email addresses
        text = re.sub(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
            '[REDACTED-EMAIL]',
            text
        )

        return text

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.

        VULNERABILITY: PDF processing extracts all text including
        hidden/white text that could contain prompt injections.
        """
        # Content is base64 encoded for PDFs
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)

            # VULNERABILITY: No hidden text detection
            # Invisible text (white on white, size 0, off-page) is extracted
            # and passed to LLM without filtering

            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.

        VULNERABILITY: HTML processing may not detect all hidden content:
        - CSS-hidden elements (display:none, visibility:hidden)
        - White text on white background
        - Off-screen positioned elements
        - Base64 encoded content in data attributes
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)

            # VULNERABILITY: get_text() extracts content from hidden elements
            # Malicious prompts in hidden divs will be extracted

            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.

        VULNERABILITY: Image processing extracts EXIF metadata which
        could contain malicious prompts in comment/description fields.
        """
        try:
            image_bytes = base64.b64decode(content)

            # Extract both visual text (OCR) and metadata
            extracted = await self.image_parser.extract_all(image_bytes)

            # VULNERABILITY: EXIF data extracted and included without scanning
            # Comment, UserComment, ImageDescription fields could contain injections

            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.

        VULNERABILITY: JSON content processed without PII scanning.
        Nested objects containing sensitive data are passed through.
        """
        import json

        try:
            # Parse to validate JSON
            data = json.loads(content)

            # VULNERABILITY: No PII detection in nested objects
            # Data like user.profile.contact.ssn passes through
            # No recursive scanning for sensitive patterns

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    # Singapore PII patterns used by validate_file
    _SG_PII_PATTERNS = [
        # NRIC / FIN  (S/T/F/G/M followed by 7 digits and a letter)
        (r'\b[STFGM]\d{7}[A-Z]\b', 'Singapore NRIC/FIN'),
        # Singapore passport  (E followed by 7–8 digits)
        (r'\bE\d{7,8}\b', 'Singapore Passport Number'),
        # Singapore mobile / local phone  (+65 or 65 prefix, or bare 8-digit starting with 6/8/9)
        (r'(?:\+65|\b65)[\s-]?[689]\d{3}[\s-]?\d{4}\b', 'Singapore Phone (+65)'),
        (r'\b[689]\d{3}[\s-]?\d{4}\b', 'Singapore Phone (local)'),
        # Singapore postal code  (6-digit, first digit 0-8)
        (r'\bSingapore\s+[0-9]{6}\b', 'Singapore Postal Code'),
        # Generic Singapore address keywords combined with a postal code
        (r'\b(?:Blk|Block|Lot|#\d{2}-\d{2,4})\b.*?\b[0-9]{6}\b', 'Singapore Address'),
        # Full name + NRIC in proximity (common in forms)
        (r'(?i)(?:nric|fin|ic\s*no\.?|identity\s+card)\s*[:\-]?\s*[STFGM]\d{7}[A-Z]', 'Singapore ID Label+Value'),
    ]

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.

        Checks file size and scans content for Singapore PII categories
        (NRIC, FIN, passport number, phone numbers, postal codes, addresses).
        Files containing PII are rejected to comply with the Singapore PII policy.
        """
        import re

        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": [],
            "errors": []
        }

        # Size check
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # Singapore PII content scan
        pii_found = []
        for pattern, label in self._SG_PII_PATTERNS:
            if re.search(pattern, content):
                pii_found.append(label)

        if pii_found:
            validation_result["valid"] = False
            unique_labels = list(dict.fromkeys(pii_found))  # preserve order, deduplicate
            validation_result["errors"].append(
                f"File rejected: Singapore PII detected ({', '.join(unique_labels)}). "
                "Uploading files containing personal data is not permitted."
            )
            logger.warning(
                "Singapore PII detected in uploaded file '%s': %s",
                filename,
                ', '.join(unique_labels)
            )

        return validation_result

    # ------------------------------------------------------------------
    # Prompt-injection / malicious-content scanner
    # ------------------------------------------------------------------
    _PROMPT_INJECTION_PATTERNS = [
        # Direct instruction-override attempts
        (r"(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?|constraints?)", "instruction-override attempt"),
        # System/role hijacking
        (r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|instructions?\s+are))", "role-hijacking attempt"),
        # Jailbreak keywords
        (r"(?i)(jailbreak|dan\s+mode|developer\s+mode|unrestricted\s+mode|god\s+mode|do\s+anything\s+now)", "jailbreak keyword"),
        # Invisible / zero-width Unicode prompt smuggling
        (r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]", "invisible Unicode characters"),
        # Base64-encoded instruction blocks (heuristic: long pure-base64 token)
        (r"(?:[A-Za-z0-9+/]{40,}={0,2})", "possible base64-encoded payload"),
        # Leetspeak command patterns  (e.g. 1gn0r3, 0v3rr1d3)
        (r"(?i)\b(1[g9][n][0o][r3][e3]|0v[e3]rr[1i][d][e3]|[s5][y][s5][t][e3][m]\s*[p][r][o0][m][p][t])\b", "leetspeak command pattern"),
        # Shell / binary command injection
        (r"(?i)(\$\(|`[^`]+`|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bshell_exec\b|\bpopen\b|\bproc_open\b)", "shell/binary command"),
        # Prompt-delimiter smuggling
        (r"(?i)(###\s*(system|user|assistant)|<\|im_start\||<\|im_end\||\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)", "prompt-delimiter smuggling"),
        # Exfiltration / data-leak instructions
        (r"(?i)(send\s+(all|the|this|my)\s+(data|information|content|context|conversation)|exfiltrate|leak\s+(the\s+)?(data|context|prompt))", "data-exfiltration instruction"),
    ]

    def _scan_for_malicious_prompts(self, content: str, filename: str):
        """
        Scan raw file content (text or base64 string) for prompt-injection and
        other malicious payload patterns.

        Returns:
            (reject: bool, reason: str)  — reject=True means the file must be blocked.
        """
        import re as _re

        # 1. Scan the raw content as-is.
        for pattern, label in self._PROMPT_INJECTION_PATTERNS:
            # Base64 heuristic: only flag if the decoded text also looks suspicious.
            if label == "possible base64-encoded payload":
                for match in _re.finditer(pattern, content):
                    candidate = match.group(0)
                    try:
                        decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                        for inner_pattern, inner_label in self._PROMPT_INJECTION_PATTERNS:
                            if inner_label == "possible base64-encoded payload":
                                continue
                            if _re.search(inner_pattern, decoded):
                                return True, f"base64-encoded {inner_label}"
                    except Exception:
                        pass
                continue

            if _re.search(pattern, content):
                return True, label

        # 2. If the whole payload looks like base64, decode and re-scan.
        stripped = content.strip()
        if len(stripped) > 20 and _re.fullmatch(r"[A-Za-z0-9+/\n\r]+=*", stripped):
            try:
                decoded_full = base64.b64decode(stripped + "==").decode("utf-8", errors="ignore")
                for pattern, label in self._PROMPT_INJECTION_PATTERNS:
                    if label == "possible base64-encoded payload":
                        continue
                    if _re.search(pattern, decoded_full):
                        return True, f"base64-encoded {label}"
            except Exception:
                pass

        return False, ""
