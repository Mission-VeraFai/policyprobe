"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
"""

import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Singapore PII patterns
_SG_PII_PATTERNS: Dict[str, re.Pattern] = {
    # NRIC / FIN: S/T/F/G followed by 7 digits and a letter
    "NRIC_FIN": re.compile(
        r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE
    ),
    # Singapore passport: E followed by 7 digits (or older formats)
    "PASSPORT": re.compile(
        r'\b[EK]\d{7}[A-Z]?\b', re.IGNORECASE
    ),
    # Singapore local phone numbers (+65 or 65 prefix, or bare 8-digit starting with 6/8/9)
    "SG_PHONE": re.compile(
        r'(?:\+65|\b65)[\s\-]?[689]\d{3}[\s\-]?\d{4}\b'
        r'|\b[689]\d{3}[\s\-]?\d{4}\b'
    ),
    # Singapore postal code (6 digits, commonly preceded by keywords)
    "POSTAL_CODE": re.compile(
        r'(?:singapore|s)\s*\(?(\d{6})\)?'
        r'|\bpostal\s+code[:\s]+(\d{6})\b',
        re.IGNORECASE
    ),
    # Common address indicators
    "ADDRESS": re.compile(
        r'\b(?:blk|block|lot|unit|#\d{2}[-–]\d{2,4}|jalan|lorong|bukit|toa payoh|ang mo kio|jurong|tampines|woodlands|yishun|bedok|clementi|bishan|hougang|sengkang|punggol|geylang|kallang|novena|orchard|raffles|marina|sentosa)\b',
        re.IGNORECASE
    ),
}


def _scan_for_sg_pii(text: str) -> List[str]:
    """
    Scan text for Singapore PII categories.
    Returns a list of warning strings describing each finding.
    Does NOT include the actual PII values in warnings to avoid
    propagating sensitive data into logs.
    """
    warnings: List[str] = []
    for pii_type, pattern in _SG_PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            warnings.append(
                f"Potential Singapore PII detected: {pii_type} "
                f"({len(matches)} occurrence(s))"
            )
    return warnings


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    # PII redaction patterns
    _PII_PATTERNS = [
        # Social Security Numbers: 123-45-6789 or 123 45 6789 or 123456789
        (re.compile(r'\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b'), '[REDACTED-SSN]'),
        # Credit card numbers: 16-digit groups (Visa, MC, Amex, Discover)
        (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[\s\-]){3}[0-9]{4})\b'), '[REDACTED-CC]'),
        # Email addresses
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
        # IPv4 addresses
        (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED-IP]'),
        # US phone numbers: (123) 456-7890, 123-456-7890, 123.456.7890, +11234567890
        (re.compile(r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b'), '[REDACTED-PHONE]'),
    ]

    def __init__(self):
        pass

    def _redact_pii(self, text: str) -> str:
        """Redact PII from text using regex patterns."""
        redacted = text
        for pattern, replacement in self._PII_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                page_text = page.extract_text()
                if page_text:
                    page_text = self._redact_pii(page_text)
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text)
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return self._redact_pii(full_text)

        except Exception as e:
            logger.error("PDF extraction error", exc_info=True)
            return "Error extracting PDF: an internal error occurred."

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

        # Maximum characters returned in extract_all to enforce output data minimisation
    _MAX_TEXT_LENGTH = 50_000

    # Allowlist of metadata fields safe to expose in responses
    _ALLOWED_METADATA_KEYS = {
        "/Title", "/Author", "/Subject", "/Creator",
        "/Producer", "/CreationDate", "/ModDate", "/Keywords"
    }

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract a bounded subset of content from PDF.

        Output is minimised: text is truncated to _MAX_TEXT_LENGTH characters
        and only allowlisted metadata fields are returned.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        # Truncate text to prevent unbounded content in responses
        truncated = len(text) > self._MAX_TEXT_LENGTH
        text_out = text[:self._MAX_TEXT_LENGTH]

        # Filter metadata to allowlisted fields only
        filtered_metadata = {
            k: v for k, v in metadata.items()
            if k in self._ALLOWED_METADATA_KEYS
        }

        warnings = []
        if truncated:
            warnings.append(
                f"Text truncated to {self._MAX_TEXT_LENGTH} characters "
                f"(original length: {len(text)})"
            )

        return {
            "text": text_out,
            "metadata": filtered_metadata,
            "warnings": warnings
        }
