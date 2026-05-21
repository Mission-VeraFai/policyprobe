"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content but does NOT flag it as suspicious
- Hidden text extraction works but no threat analysis
- EXIF extraction works but no scanning of contents
- Acts as a utility, not a security control

AFTER UNIFAI REMEDIATION:
- Extracted hidden content is flagged for review
- Automatic threat detection on extracted content
- Integration with prompt injection detector
"""

import logging
import re
from typing import Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Singapore PII Detection
# ---------------------------------------------------------------------------

# NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
_SG_NRIC_FIN_RE = re.compile(
    r'\b[STFGM]\d{7}[A-Z]\b',
    re.IGNORECASE,
)

# SingPass user ID pattern (same format as NRIC/FIN — covered above)
# Singapore mobile numbers: +65 followed by 8 digits, or local 8-digit
# numbers starting with 8 or 9
_SG_PHONE_RE = re.compile(
    r'(?:\+65[\s-]?)?[89]\d{3}[\s-]?\d{4}\b',
)

# Singapore 6-digit postal code
_SG_POSTAL_RE = re.compile(
    r'\bSingapore\s+\d{6}\b|\b\d{6}\b(?=.*Singapore)',
    re.IGNORECASE,
)

# Passport numbers (general alphanumeric, 6-9 chars — conservative)
_SG_PASSPORT_RE = re.compile(
    r'\b[A-Z]\d{7}[A-Z]\b',
    re.IGNORECASE,
)

_SG_PII_PATTERNS: List[tuple] = [
    ('NRIC/FIN', _SG_NRIC_FIN_RE),
    ('Singapore phone number', _SG_PHONE_RE),
    ('Singapore postal code', _SG_POSTAL_RE),
    ('Singapore passport number', _SG_PASSPORT_RE),
]


def detect_singapore_pii(text: str) -> List[str]:
    """
    Scan *text* for Singapore PII categories.

    Returns a list of human-readable violation strings, one per match
    found.  Returns an empty list when no PII is detected.
    """
    if not text:
        return []

    violations: List[str] = []
    for label, pattern in _SG_PII_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            # Redact the actual values in the log / warning message
            violations.append(
                f"Singapore PII detected — {label} "
                f"({len(matches)} occurrence(s))"
            )
    return violations


def _check_pii_and_raise(content_parts: List[str], source: str = 'file') -> List[str]:
    """
    Aggregate PII warnings across all *content_parts*.

    Raises ``ValueError`` if any Singapore PII is found so that the
    upload pipeline can reject the file before it reaches the LLM.
    Returns the list of warning strings (empty when clean).
    """
    all_warnings: List[str] = []
    combined = ' '.join(p for p in content_parts if p)
    violations = detect_singapore_pii(combined)
    if violations:
        for v in violations:
            msg = f"PII_BLOCK [{source}]: {v}"
            logger.warning(msg)
            all_warnings.append(msg)
        raise ValueError(
            f"Upload rejected: Singapore PII found in {source}. "
            + '; '.join(violations)
        )
    return all_warnings


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = None


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    VULNERABILITY: This scanner extracts hidden content but does NOT
    treat it as suspicious. All extracted content is passed through
    to the LLM without security analysis.
    """

    # PII patterns for redaction
    _PII_PATTERNS = [
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
        (re.compile(r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), '[REDACTED_PHONE]'),
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
        (re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b'), '[REDACTED_CC]'),
        (re.compile(r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b'), '[REDACTED_NAME]'),
        (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[REDACTED_IP]'),
        (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
        (re.compile(r'\b\d{5}(?:-\d{4})?\b'), '[REDACTED_ZIP]'),
    ]

    def __init__(self):
        self.extraction_count = 0

    def _redact_pii(self, text: Optional[str]) -> Optional[str]:
        """Detect and redact PII from text using regex patterns."""
        if not text:
            return text
        redacted = text
        for pattern, replacement in self._PII_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    # ------------------------------------------------------------------
    # Internal PII gate — called at the end of every scan_* method
    # ------------------------------------------------------------------
    def _pii_gate(self, extracted: ExtractedContent, source: str) -> ExtractedContent:
        """
        Run Singapore PII detection over all extracted content fields.
        Raises ValueError if PII is found (blocks the upload).
        """
        parts: List[str] = []
        if extracted.visible_text:
            parts.append(extracted.visible_text)
        if extracted.hidden_text:
            parts.append(extracted.hidden_text)
        if extracted.encoded_content:
            parts.extend(str(e) for e in extracted.encoded_content)
        if extracted.metadata:
            parts.append(str(extracted.metadata))

        warnings = _check_pii_and_raise(parts, source=source)
        if warnings:
            existing = extracted.warnings or []
            extracted.warnings = existing + warnings
        return extracted

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.

        VULNERABILITY: Extracts hidden content but doesn't flag it.
        Hidden divs, CSS-hidden text, etc. are extracted and
        concatenated with visible content.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator='\n', strip=True)

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []

        # Find elements with hiding styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(prop in style for prop in [
                'display:none', 'display: none',
                'visibility:hidden', 'visibility: hidden',
                'opacity:0', 'opacity: 0',
                'font-size:0', 'font-size: 0',
                'color:#fff', 'color:white', 'color: white',
            ]):
                text = element.get_text(strip=True)
                if text:
                    hidden_elements.append(text)

        # Find elements with hiding classes (common patterns)
        for element in soup.find_all(class_=re.compile(
            r'(hidden|invisible|sr-only|visually-hidden|d-none)',
            re.IGNORECASE
        )):
            text = element.get_text(strip=True)
            if text:
                hidden_elements.append(text)

        # Sanitize and validate hidden elements before combining
        sanitized_hidden_elements = []
        warnings = []

        # Prompt-injection indicator patterns
        injection_patterns = [
            re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
            re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
            re.compile(r'system\s*:\s*', re.IGNORECASE),
            re.compile(r'<\s*/?\s*(script|iframe|object|embed|form)', re.IGNORECASE),
            re.compile(r'\\n\s*(human|assistant|user|system)\s*:', re.IGNORECASE),
        ]

        if hidden_elements:
            warnings.append(
                f"Hidden HTML elements detected ({len(hidden_elements)} element(s)). "
                "Content may contain prompt-injection attempts."
            )
            logger.warning(
                "Hidden HTML content detected — validating before use",
                extra={"hidden_elements_found": len(hidden_elements)}
            )

        for element_text in hidden_elements:
            flagged = False
            for pattern in injection_patterns:
                if pattern.search(element_text):
                    warnings.append(
                        f"Potential prompt-injection pattern removed from hidden element: "
                        f"{element_text[:80]!r}"
                    )
                    logger.warning(
                        "Prompt-injection pattern found in hidden HTML element — discarding",
                        extra={"preview": element_text[:80]}
                    )
                    flagged = True
                    break
            if not flagged:
                # Strip control characters before accepting the text
                clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', element_text)
                sanitized_hidden_elements.append(clean)

        hidden_text = '\n'.join(sanitized_hidden_elements) if sanitized_hidden_elements else None

        logger.info(
            "HTML content scanned",
            extra={
                "visible_length": len(visible_text),
                "hidden_elements_found": len(hidden_elements),
                "hidden_elements_kept": len(sanitized_hidden_elements),
                "warnings": warnings,
            }
        )

                # Data minimisation: do not forward hidden content to callers.
        # Instead, suppress it and surface a security warning.
        security_warnings = None
        if hidden_elements:
            security_warnings = [
                f"Hidden content suppressed: {len(hidden_elements)} concealed "
                f"element(s) detected and removed from output. "
                f"Review source for prompt-injection or data-exfiltration attempts."
            ]
            logger.warning(
                "Hidden content suppressed from output",
                extra={
                    "hidden_elements_count": len(hidden_elements),
                    "action": "suppressed",
                }
            )

                # Security: flag hidden content as a potential prompt-injection vector
        html_warnings = []
        if hidden_elements:
            html_warnings.append(
                f"SECURITY WARNING: {len(hidden_elements)} hidden element(s) detected "
                "(CSS/style-hidden or class-hidden). This content may contain prompt "
                "injection payloads and MUST NOT be forwarded to an LLM without "
                "explicit review. Hidden text has been quarantined in `hidden_text`."
            )
            logger.warning(
                "Hidden HTML content detected — potential prompt injection risk",
                extra={
                    "hidden_element_count": len(hidden_elements),
                    "hidden_preview": hidden_text[:200] if hidden_text else None,
                }
            )

                # Security: surface suspicious-pattern findings as warnings
        pdf_warnings = []
        if suspicious_patterns:
            pdf_warnings.append(
                f"SECURITY WARNING: Suspicious patterns detected in PDF text: "
                f"{suspicious_patterns}. Content may contain hidden or obfuscated "
                "payloads (null bytes, zero-width characters, etc.) that could be "
                "used for prompt injection. Review before forwarding to an LLM."
            )
            logger.warning(
                "Suspicious PDF content detected — potential prompt injection risk",
                extra={"patterns": suspicious_patterns}
            )

        return ExtractedContent(
            visible_text=text_content,
            hidden_text=None,
            warnings=pdf_warnings if pdf_warnings else None
        )

    async def scan_pdf_text(self, text_content: str) -> ExtractedContent:
        """
        Analyze extracted PDF text for hidden content indicators.

        VULNERABILITY: Does not detect:
        - White text on white background
        - Zero-size fonts
        - Off-page content
        - Overlapping text layers
        """
        # Look for suspicious patterns that might indicate hidden content
        suspicious_patterns = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        warnings = []
        sanitized_text = text_content

        if suspicious_patterns:
            warnings.append(
                f"Suspicious patterns detected in PDF text: {suspicious_patterns}. "
                "Content has been sanitized."
            )
            logger.warning(
                "Suspicious patterns in PDF — sanitizing before use",
                extra={"patterns": suspicious_patterns}
            )
            # Remove null bytes and known invisible characters
            sanitized_text = sanitized_text.replace('\x00', '')
            for char in ['\u200b', '\u200c', '\u200d', '\ufeff']:
                sanitized_text = sanitized_text.replace(char, '')

        # Validate for prompt-injection patterns
        injection_patterns = [
            re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
            re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
            re.compile(r'system\s*:\s*', re.IGNORECASE),
        ]
        for pattern in injection_patterns:
            if pattern.search(sanitized_text):
                warnings.append(
                    "Potential prompt-injection pattern detected in PDF text."
                )
                logger.warning(
                    "Prompt-injection pattern found in PDF text",
                    extra={"pattern": pattern.pattern}
                )
                break

        return ExtractedContent(
            visible_text=sanitized_text,
            hidden_text=None,
            warnings=warnings if warnings else None
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.

        VULNERABILITY: Extracts EXIF data but doesn't scan for threats.
        Malicious prompts in EXIF comment fields are passed through.
        """
        # Extract text from relevant metadata fields
        text_fields = []
        injection_patterns = [
            re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
            re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
            re.compile(r'system\s*:\s*', re.IGNORECASE),
        ]
        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    text_fields.append(f"{field}: {value}")

        # VULNERABILITY: Metadata content extracted without scanning
        # EXIF comments could contain prompt injections
        metadata_text = '\n'.join(text_fields) if text_fields else None

        logger.info(
            "Image metadata extracted",
            extra={
                "fields_found": len(text_fields),
                # VULNERABILITY: Metadata logged without scanning
                "metadata_preview": metadata_text[:100] if metadata_text else None
            }
        )

        return ExtractedContent(
            visible_text="",  # No visible text in metadata
            hidden_text=metadata_text,  # Metadata as "hidden" content
            metadata=metadata,
            warnings=None  # VULNERABILITY: No warnings for suspicious metadata
        )

    async def extract_base64_content(self, content: str) -> list[str]:
        """
        Extract and decode base64 encoded content.

        VULNERABILITY: Decodes base64 but doesn't scan decoded content.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                # Attempt to decode
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    decoded_contents.append(decoded)
                    # VULNERABILITY: Decoded content not scanned for threats
                    logger.debug(
                        "Base64 content decoded",
                        extra={
                            "original_length": len(match),
                            "decoded_length": len(decoded),
                            # VULNERABILITY: Decoded content logged
                            "decoded_preview": decoded[:100]
                        }
                    )
            except:
                continue

        return decoded_contents

    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        VULNERABILITY: Combines visible AND hidden content without
        any security filtering. Hidden malicious content gets sent
        directly to the LLM.
        """
        parts = [extracted.visible_text]

        # VULNERABILITY: Hidden content added without filtering
        if extracted.hidden_text:
            parts.append(f"\n[Additional content]:\n{extracted.hidden_text}")

        # VULNERABILITY: Encoded content added without filtering
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                parts.append(f"\n[Decoded content {i+1}]:\n{decoded}")

        # VULNERABILITY: All content combined and returned
        # No security scanning performed before return
        result = ExtractedContent(
            visible_text='\n'.join(parts),
        )
        return self._pii_gate(result, source='document')


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class ContentScanner:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Flags hidden content as suspicious
#     - Integrates with threat detection
#     - Generates security warnings
#     - Blocks content with detected threats
#     """
#
#     async def scan_html(self, html_content: str) -> ExtractedContent:
#         """Scan with security awareness."""
#         # ... extraction code ...
#
#         warnings = []
#         if hidden_elements:
#             warnings.append(f"SECURITY: {len(hidden_elements)} hidden elements detected")
#
#             # Scan hidden content for threats
#             from .prompt_injection import PromptInjectionDetector
#             detector = PromptInjectionDetector()
#             for hidden in hidden_elements:
#                 result = await detector.scan(hidden)
#                 if result.has_violations:
#                     warnings.append(f"THREAT: Malicious content in hidden element")
#
#         return ExtractedContent(
#             visible_text=visible_text,
#             hidden_text=hidden_text,
#             warnings=warnings
#         )
