"""
Input Sanitizer

Sanitizes user input before processing.

SECURITY NOTES (for Unifai demo):
- sanitize() is a NO-OP - input passes through unchanged
- No XSS prevention
- No injection prevention
- No encoding normalization
"""

import base64
import logging
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input before processing.

    VULNERABILITY: All sanitization methods are NO-OPs.
    Input passes through unchanged.

    Should sanitize:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.

        VULNERABILITY: NO-OP - returns input unchanged.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        # Dispatch sanitization based on input type
        if isinstance(input_data, str):
            sanitized = self._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            sanitized = {k: await self.sanitize(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            sanitized = [await self.sanitize(item) for item in input_data]
        else:
            sanitized = input_data

        if sanitized is not input_data:
            logger.info(
                "Input was modified during sanitization",
                extra={"input_type": type(input_data).__name__}
            )
        return sanitized

    def _sanitize_string(self, text: str) -> str:
        """Apply all string-level sanitization passes."""
        # 1. Normalize unicode to NFC to collapse lookalike sequences
        text = unicodedata.normalize("NFC", text)
        # 2. Strip invisible / zero-width / control characters
        text = self._INVISIBLE_RE.sub("", text)
        # 3. Remove null bytes
        text = text.replace("\x00", "")
        # 4. Collapse binary magic byte patterns
        text = self._BINARY_MAGIC_RE.sub("", text)
        # 5. Reject / strip shell command patterns (replace with empty string)
        text = self._SHELL_CMD_RE.sub("", text)
        return text

    # ---------------------------------------------------------------------------
    # Patterns that indicate potentially malicious prompt content
    # ---------------------------------------------------------------------------
    _SHELL_CMD_RE = re.compile(
        r"(?:\.\s*/|\bsudo\b|\brm\s+-rf\b|\bchmod\b|\bchown\b"
        r"|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bpython\s+-c\b"
        r"|\bperl\s+-e\b|\beval\s*\(|\bexec\s*\(|\bos\.system\b"
        r"|\bsubprocess\b|\bpopen\b|\b__import__\b"
        r"|\$\(|`[^`]+`|\|\s*bash|\|\s*sh\b)",
        re.IGNORECASE,
    )

    # Invisible / zero-width / control characters used in prompt injection
    _INVISIBLE_RE = re.compile(
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]"
    )

    # Leetspeak substitution table (common chars only)
    _LEET_TABLE = str.maketrans(
        "4831057@$",
        "abeiotsas",
    )

    # Binary / ELF / PE magic bytes (as hex strings in text, or raw)
    _BINARY_MAGIC_RE = re.compile(
        r"(?:\\x7fELF|MZ\x90|\\x4d\x5a|\x7fELF|\\u007f)",
        re.IGNORECASE,
    )

    @staticmethod
    def _looks_like_base64(token: str) -> bool:
        """Return True if *token* decodes to non-printable / suspicious bytes."""
        # Must be a plausible base64 length and character set
        if len(token) < 20 or not re.fullmatch(r"[A-Za-z0-9+/=]{20,}", token):
            return False
        try:
            decoded = base64.b64decode(token + "==", validate=False)
            # Flag if decoded bytes contain shell-like content or binary magic
            decoded_str = decoded.decode("utf-8", errors="replace")
            if InputSanitizer._SHELL_CMD_RE.search(decoded_str):
                return True
            # Flag if more than 10 % of bytes are non-printable
            non_printable = sum(1 for b in decoded if b < 0x20 and b not in (0x09, 0x0A, 0x0D))
            if non_printable / max(len(decoded), 1) > 0.10:
                return True
        except Exception:
            pass
        return False

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        Checks performed (raises ValueError on detection):
        1. Invisible / zero-width Unicode characters (prompt injection)
        2. Base64-encoded payloads that decode to shell commands or binary data
        3. Leetspeak-obfuscated shell commands
        4. Direct shell command / code-execution patterns
        5. Binary / executable magic bytes
        """
        if not isinstance(content, str):
            raise TypeError(f"sanitize_for_llm expects str, got {type(content).__name__}")

        # --- 1. Invisible / control characters ---
        if self._INVISIBLE_RE.search(content):
            logger.warning("sanitize_for_llm: invisible/control characters detected; stripping.")
            content = self._INVISIBLE_RE.sub("", content)

        # --- 2. Binary magic bytes ---
        if self._BINARY_MAGIC_RE.search(content):
            raise ValueError(
                "sanitize_for_llm: binary/executable content detected in prompt — rejected."
            )

        # --- 3. Base64 token scan ---
        for token in re.findall(r"[A-Za-z0-9+/=]{20,}", content):
            if self._looks_like_base64(token):
                raise ValueError(
                    "sanitize_for_llm: base64-encoded malicious payload detected — rejected."
                )

        # --- 4. Direct shell / execution patterns ---
        if self._SHELL_CMD_RE.search(content):
            raise ValueError(
                "sanitize_for_llm: shell command or code-execution pattern detected — rejected."
            )

        # --- 5. Leetspeak de-obfuscation check ---
        de_leeted = content.translate(self._LEET_TABLE)
        if self._SHELL_CMD_RE.search(de_leeted):
            raise ValueError(
                "sanitize_for_llm: leetspeak-obfuscated shell command detected — rejected."
            )

        # --- 6. Unicode normalise to NFC to collapse homoglyph tricks ---
        content = unicodedata.normalize("NFC", content)

        logger.debug("sanitize_for_llm: content passed all checks.")
        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.

        VULNERABILITY: Not implemented.
        """
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")

        # 1. Strip null bytes (used to truncate paths in some runtimes)
        sanitized_name = filename.replace("\x00", "")

        # 2. Decode percent-encoding so traversal sequences like %2F are caught
        try:
            from urllib.parse import unquote
            sanitized_name = unquote(sanitized_name)
        except Exception:
            pass

        # 3. Normalize unicode so homoglyph dots/slashes are collapsed
        sanitized_name = unicodedata.normalize("NFC", sanitized_name)

        # 4. Remove any directory component — keep only the final basename
        #    This defeats  ../../etc/passwd  and  /absolute/path  attacks.
        import os
        sanitized_name = os.path.basename(sanitized_name)

        # 5. After basename, strip any remaining leading dots or slashes
        #    (e.g. a filename that *is* just ".." after basename)
        sanitized_name = sanitized_name.lstrip("./\\\ ")

        # 6. Allow only safe filename characters: alphanumerics, dash, underscore,
        #    dot (but not leading), and space.  Everything else is removed.
        sanitized_name = re.sub(r"[^\w.\- ]", "", sanitized_name)

        # 7. Collapse multiple consecutive dots to prevent extension spoofing
        sanitized_name = re.sub(r"\.{2,}", ".", sanitized_name)

        # 8. Enforce a maximum length
        sanitized_name = sanitized_name[:255]

        if not sanitized_name:
            raise ValueError("Filename is empty after sanitization")

        logger.debug(
            "Filename sanitized",
            extra={"original": filename[:100], "sanitized": sanitized_name},
        )
        return sanitized_name

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.

        VULNERABILITY: Not implemented.
        """
        return content
