"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import base64
import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


class ImageParser:
    """
    Parses image files and extracts metadata.

    VULNERABILITY: Extracts EXIF data without security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    """

    # Patterns that indicate prompt injection or malicious content
    _INJECTION_PATTERNS = [
        # Direct prompt injection keywords
        re.compile(r'ignore\s+(previous|above|prior|all)\s+(instructions?|prompts?|context)', re.IGNORECASE),
        re.compile(r'(system|assistant|user)\s*:\s*', re.IGNORECASE),
        re.compile(r'<\s*(system|instructions?|prompt)\s*>', re.IGNORECASE),
        re.compile(r'\[\s*(system|instructions?|prompt)\s*\]', re.IGNORECASE),
        re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
        re.compile(r'act\s+as\s+(a|an)\s+', re.IGNORECASE),
        re.compile(r'(forget|disregard|override)\s+(your|all|previous)', re.IGNORECASE),
        re.compile(r'new\s+(instructions?|directives?|rules?|persona)', re.IGNORECASE),
        re.compile(r'jailbreak', re.IGNORECASE),
        re.compile(r'do\s+anything\s+now', re.IGNORECASE),
        re.compile(r'dan\s+mode', re.IGNORECASE),
        # Shell command patterns
        re.compile(r'(\$\(|`)[^`]*`', re.IGNORECASE),
        re.compile(r'\b(bash|sh|cmd|powershell|exec|eval|system|popen)\s*[\(\[]', re.IGNORECASE),
        re.compile(r'&&|\|\||;\s*(rm|del|wget|curl|nc|ncat|python|perl|ruby)', re.IGNORECASE),
        re.compile(r'\b(wget|curl)\s+https?://', re.IGNORECASE),
        # Leetspeak / obfuscation heuristic (high density of digit-letter substitutions)
        re.compile(r'(?:[i1][g9][n][o0][r][e3]|[s5][y][s5][t7][e3][m])', re.IGNORECASE),
    ]

    # Suspicious base64 payload minimum length (short strings are usually benign)
    _B64_MIN_SUSPICIOUS_LEN = 40

    # Patterns that indicate potentially malicious content in EXIF fields
    import re as _re
    _SHELL_CMD_RE = _re.compile(
        r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|curl|wget|nc|ncat|eval|exec|system|passthru|popen)\b',
        _re.IGNORECASE | _re.MULTILINE,
    )
    _BASE64_RE = _re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    _INVISIBLE_RE = _re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]')
    _LEET_RE = _re.compile(r'(?:[i!1][g9][n][o0][r][e3]|[i!1][g9][n][o0][r][e3]\s+[a-z]+|[s$][y][s$][t][e3][m])', _re.IGNORECASE)
    _BINARY_MAGIC = [
        b'\x4d\x5a',   # PE/EXE
        b'\x7fELF',    # ELF
        b'\xca\xfe\xba\xbe',  # Mach-O
        b'\x23\x21',   # shebang #!
    ]

    # Fields whose text content is passed downstream and must be sanitized
    _TEXT_FIELDS = {
        'ImageDescription', 'XPComment', 'XPSubject', 'XPTitle',
        'XPKeywords', 'UserComment', 'Comment', 'Artist', 'Copyright', 'Software',
    }

    # Patterns that indicate a prompt-injection attempt
    _INJECTION_PATTERNS = [
        r'(?i)ignore\s+(previous|above|all)\s+instructions',
        r'(?i)you\s+are\s+now',
        r'(?i)act\s+as\s+(a|an)?\s*\w+',
        r'(?i)system\s*:',
        r'(?i)assistant\s*:',
        r'(?i)\[INST\]',
        r'(?i)<\|.*?\|>',
    ]

    _MAX_FIELD_LENGTH = 512

    def __init__(self):
        import re
        self._compiled_patterns = [
            re.compile(p) for p in self._INJECTION_PATTERNS
        ]

    def _sanitize_text(self, value: str, field_name: str = '') -> str:
        """Strip control characters, truncate, and reject injection attempts."""
        import re
        # Remove non-printable / control characters (keep newline for readability)
        value = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', value)
        # Truncate to a safe maximum length
        value = value[:self._MAX_FIELD_LENGTH]
        # Reject values that match known injection patterns
        for pattern in self._compiled_patterns:
            if pattern.search(value):
                logger.warning(
                    "Potential prompt injection detected in EXIF field",
                    extra={"field": field_name}
                )
                return '[REDACTED: suspicious content]'
        return value

    def _is_suspicious_text(self, value: str) -> bool:
        """Return True if the text value contains patterns associated with prompt injection or malicious commands."""
        import re
        # Check for invisible / control characters used to hide instructions
        if self._INVISIBLE_RE.search(value):
            return True
        # Check for shell command patterns
        if self._SHELL_CMD_RE.search(value):
            return True
        # Check for long base64 blobs (potential encoded payloads)
        if self._BASE64_RE.search(value):
            return True
        # Check for common leetspeak obfuscation patterns
        if self._LEET_RE.search(value):
            return True
        # Check for binary magic bytes embedded in the string
        encoded = value.encode('utf-8', errors='ignore')
        for magic in self._BINARY_MAGIC:
            if magic in encoded:
                return True
        return False

    def _sanitize_text(self, value: str, field: str) -> Optional[str]:
        """Return sanitized text or None if the value is flagged as malicious."""
        if self._is_suspicious_text(value):
            logger.warning(
                "Suspicious content detected in EXIF field — field suppressed",
                extra={"field": field},
            )
            return None
        # Strip invisible characters even from values that pass the full check
        import re
        cleaned = self._INVISIBLE_RE.sub('', value)
        return cleaned

    def _is_base64_payload(self, text: str) -> bool:
        """Return True if text looks like a base64-encoded payload with suspicious decoded content."""
        # Strip whitespace and check if it looks like base64
        stripped = text.strip()
        if len(stripped) < self._B64_MIN_SUSPICIOUS_LEN:
            return False
        b64_pattern = re.compile(r'^[A-Za-z0-9+/\-_]+=*$')
        if not b64_pattern.match(stripped):
            return False
        try:
            # Pad if necessary
            padded = stripped + '=' * (-len(stripped) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            # Check decoded content for injection patterns
            return self._contains_injection(decoded)
        except Exception:
            return False

    def _contains_injection(self, text: str) -> bool:
        """Return True if text matches any known malicious prompt injection pattern."""
        for pattern in self._INJECTION_PATTERNS:
            if pattern.search(text):
                return True
        return False

    def _sanitize_exif_field(self, field_name: str, value: str) -> Optional[str]:
        """
        Sanitize a single EXIF text field.

        Returns the original value if safe, or None if the value contains
        malicious content (prompt injection, shell commands, base64 payloads, etc.).
        """
        if not value or not isinstance(value, str):
            return value

        # Check for direct injection patterns
        if self._contains_injection(value):
            logger.warning(
                "Malicious prompt injection detected in EXIF field",
                extra={"field": field_name, "value_length": len(value)}
            )
            return None

        # Check for base64-encoded payloads
        if self._is_base64_payload(value):
            logger.warning(
                "Suspicious base64 payload detected in EXIF field",
                extra={"field": field_name, "value_length": len(value)}
            )
            return None

        return value

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data — text fields are sanitized before storage
            TEXT_TAGS = {
                'ImageDescription', 'XPComment', 'XPSubject', 'XPTitle',
                'XPKeywords', 'UserComment', 'Comment', 'Artist',
                'Copyright', 'Software',
            }
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    # Sanitize known text fields before storing in metadata
                    if tag in TEXT_TAGS and isinstance(value, str):
                        sanitized = self._sanitize_exif_text(value, str(tag))
                        if sanitized is None:
                            continue  # Drop rejected values entirely
                        value = sanitized
                    # Sanitize text fields before storing
                    if isinstance(value, str):
                        sanitized = self._sanitize_exif_field(str(tag), value)
                        if sanitized is None:
                            # Replace malicious content with a safe placeholder
                            value = "[REDACTED: potentially malicious content detected]"
                        else:
                            value = sanitized
                    if isinstance(value, str):
                            sanitized = self._sanitize_text(value, str(tag))
                            if sanitized is None:
                                continue
                            value = sanitized
                    metadata[tag] = value

                        # Safe log: only non-PII structural fields are recorded
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                }
            ),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": "[sanitized]"
                }
            )

            return metadata

        except Exception:
            logger.error("Image metadata extraction failed", exc_info=False)
            return {"error": "Failed to extract image metadata."}

    @staticmethod
    def _sanitize_exif_text(value: str, field: str) -> Optional[str]:
        """
        Sanitize a text value extracted from an EXIF metadata field.

        - Truncates excessively long values.
        - Strips null bytes and non-printable control characters.
        - Rejects values that contain patterns commonly used in prompt injection
          (e.g. lines that look like system/user/assistant role markers or
          instruction-override phrases).
        Returns None if the value is considered malicious/invalid.
        """
        import re

        if not isinstance(value, str):
            return None

        # Truncate to a safe maximum length
        MAX_LEN = 500
        value = value[:MAX_LEN]

        # Strip null bytes and ASCII control characters (except tab/newline)
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

        # Reject values that contain prompt-injection patterns
        INJECTION_PATTERNS = [
            r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
            r'(?i)you\s+are\s+now\s+',
            r'(?i)act\s+as\s+(a\s+|an\s+)?(?:different|new|unrestricted)',
            r'(?i)<\s*/?\s*(system|user|assistant|prompt|instruction)\s*>',
            r'(?i)\[\s*(system|user|assistant|inst|instruction)\s*\]',
            r'(?i)###\s*(system|user|assistant|instruction)',
            r'(?i)disregard\s+(all\s+)?(previous|prior|above)',
            r'(?i)new\s+instructions?\s*:',
            r'(?i)override\s+(previous\s+)?instructions?',
        ]
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, value):
                logger.warning(
                    "Rejected EXIF field due to suspected prompt injection",
                    extra={"field": field, "pattern": pattern}
                )
                return None

        return value.strip() or None

        # PII patterns for redaction
    _PII_PATTERNS = [
        # SSN: 123-45-6789 or 123456789
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
        (re.compile(r'\b\d{9}\b'), '[REDACTED-SSN]'),
        # Email addresses
        (re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'), '[REDACTED-EMAIL]'),
        # Phone numbers (various formats)
        (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED-PHONE]'),
        # Credit card numbers (basic pattern)
        (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED-CC]'),
        # GPS/location coordinates that could identify individuals
        (re.compile(r'\bGPS\w*\s*[:=]\s*[\d.,\s]+'), '[REDACTED-LOCATION]'),
    ]

    def _redact_pii(self, text: str) -> str:
        """Scan text for PII patterns and replace with redacted placeholders."""
        if not isinstance(text, str):
            return text
        for pattern, replacement in self._PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields with PII redaction.
        """
        text_fields = []

        # Fields that commonly contain text content
        dangerous_fields = [
            'ImageDescription',
            'XPTitle',
        ]

                for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Values are already sanitized by extract_metadata;
                    # apply sanitization here too in case metadata came
                    # from a source other than extract_metadata.
                    value = self._sanitize_text(value, field_name=field)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        "Found text in EXIF field",
                        extra={"field": field}
                    ):
                    redacted_value = self._redact_pii(value)
                    text_fields.append(f"{field}: {redacted_value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            "value_preview": redacted_value[:50]
                        }
                    )

        return '\n'.join(text_fields)

        # Singapore PII field categories to block
    _SG_PII_EXIF_FIELDS = {
        # Fields that may carry facial/biometric data
        'MakerNote', 'FaceDetect', 'FaceInfo', 'FaceRecognition',
        'FacePosition', 'FaceSize', 'FaceName', 'FaceId',
        # Fields that may carry personal names / descriptions
        'Artist', 'Copyright', 'ImageDescription',
        'XPAuthor', 'XPTitle', 'XPSubject', 'XPComment', 'XPKeywords',
        'UserComment', 'Comment',
        # GPS fields that can identify a person's location
        'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
        'GPSLatitudeRef', 'GPSLongitudeRef',
    }

    # Regex patterns for Singapore PII in free-text fields
    import re as _re
    _SG_PII_PATTERNS = [
        # NRIC / FIN  (S/T/F/G followed by 7 digits and a letter)
        _re.compile(r'\b[STFG]\d{7}[A-Z]\b', _re.IGNORECASE),
        # Singapore mobile numbers (+65 8xxx / 9xxx or local 8/9 prefix)
        _re.compile(r'(\+65[\s-]?)?[89]\d{3}[\s-]?\d{4}\b'),
        # Generic name-like pattern in labelled context ("Name:", "Artist:", etc.)
        _re.compile(r'(?i)(full[\s_-]?name|name|artist|author)\s*[:\-]\s*[A-Z][a-z]+\s+[A-Z][a-z]+'),
    ]

    def _scan_for_sg_pii(self, metadata: dict, text_content: str) -> list:
        """
        Scan metadata dict and extracted text for Singapore PII.
        Returns a list of violation descriptions (empty == clean).
        """
        violations = []

        # 1. Check for high-risk EXIF field names present in the image
        for field in self._SG_PII_EXIF_FIELDS:
            if field in metadata and metadata[field] not in (None, '', b''):
                violations.append(
                    f"Potential Singapore PII in EXIF field '{field}'"
                )

        # 2. Scan free-text content with regex patterns
        combined_text = text_content + ' ' + ' '.join(
            str(v) for v in metadata.values()
            if isinstance(v, str)
        )
        for pattern in self._SG_PII_PATTERNS:
            if pattern.search(combined_text):
                violations.append(
                    f"Potential Singapore PII matched pattern: {pattern.pattern[:60]}"
                )

        return violations

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        Singapore PII check: metadata and text fields are scanned for
        PII categories (Full Name, Facial Image, Biometric Data,
        Personal Mobile Number, NRIC/FIN, GPS location) before the
        content is returned.  Processing is aborted if PII is found.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # --- Singapore PII gate ---
        pii_violations = self._scan_for_sg_pii(metadata, text_content)
        if pii_violations:
            # Log only the violation summary, never the raw PII values
            logger.warning(
                "Image upload blocked: Singapore PII detected in metadata",
                extra={"violations": pii_violations}
            )
            raise ValueError(
                "Upload rejected: image metadata contains Singapore PII "
                f"({len(pii_violations)} violation(s) detected). "
                "Please strip metadata before uploading."
            )
        # --- end PII gate ---

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(
            f"Image Info: {metadata.get('format', 'unknown')} "
            f"{metadata.get('size', 'unknown')}"
        )

        return '\n\n'.join(result_parts)
