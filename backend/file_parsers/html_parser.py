"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import base64
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    # Singapore PII patterns
    _SG_PII_PATTERNS = {
        "NRIC/FIN": re.compile(
            r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE
        ),
        "Singapore Passport": re.compile(
            r'\bE\d{7}[A-Z]\b', re.IGNORECASE
        ),
        "Singapore Phone": re.compile(
            r'(?<![\d])(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}(?![\d])'
        ),
        "Email Address": re.compile(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        ),
        "Singapore Postal Code": re.compile(
            r'\bSingapore\s+\d{6}\b', re.IGNORECASE
        ),
    }

    def __init__(self):
        pass

    def _scan_for_sg_pii(self, text: str) -> List[str]:
        """
        Scan text for Singapore PII categories.
        Returns a list of warning strings for each PII type detected.
        """
        warnings: List[str] = []
        for pii_type, pattern in self._SG_PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                warnings.append(
                    f"Singapore PII detected: {pii_type} "
                    f"({len(matches)} occurrence(s) found). "
                    "Upload blocked to protect personal data."
                )
        return warnings

        @staticmethod
    def _is_hidden_element(element) -> bool:
        """
        Detect elements that are visually hidden via inline CSS, which are
        commonly used for prompt-injection attacks.
        Returns True if the element should be considered hidden.
        """
        import re
        style = element.get('style', '')
        if not style:
            return False
        style_lower = style.lower().replace(' ', '')

        # display:none
        if re.search(r'display\s*:\s*none', style_lower):
            return True
        # visibility:hidden
        if re.search(r'visibility\s*:\s*hidden', style_lower):
            return True
        # opacity:0
        if re.search(r'opacity\s*:\s*0(?:\.0+)?(?:;|$)', style_lower):
            return True
        # Off-screen positioning (left/top with large negative values)
        if re.search(r'(?:left|top)\s*:\s*-[0-9]{4,}', style_lower):
            return True
        # font-size:0
        if re.search(r'font-size\s*:\s*0(?:px)?(?:;|$)', style_lower):
            return True
        # White / near-white / transparent text color (basic check)
        if re.search(r'color\s*:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*\))', style_lower):
            return True
        return False

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content.

        Hidden elements (display:none, visibility:hidden, off-screen,
        white-on-white, etc.) are removed before text extraction to
        prevent hidden prompt injection into LLM pipelines.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements to prevent prompt injection
            hidden_count = 0
            for element in soup.find_all(True):
                if self._is_hidden_element(element):
                    logger.warning(
                        "Hidden HTML element removed to prevent prompt injection",
                        extra={"tag": element.name}
                    )
                    element.decompose()
                    hidden_count += 1

                        text = soup.get_text(separator='
', strip=True)

            # Redact PII before returning or logging
            text = _redact_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                    "preview": text[:100]
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text.

        Delegates to extract_text() which now properly removes hidden
        elements before extraction.
        """
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = _redact_pii(title.get_text())

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = _redact_pii(content)

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        warnings = []
        if "[HIDDEN CONTENT REMOVED]" in text or True:
            # Re-parse to count hidden elements for the warning list
            try:
                from bs4 import BeautifulSoup
                soup_check = BeautifulSoup(html_content, 'html.parser')
                hidden_tags = [
                    el.name for el in soup_check.find_all(True)
                    if self._is_hidden_element(el)
                ]
                if hidden_tags:
                    warnings.append(
                        f"Hidden elements detected and removed to prevent prompt injection: "
                        f"{len(hidden_tags)} element(s) ({', '.join(set(hidden_tags))})"
                    )
            except Exception:
                pass

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }
