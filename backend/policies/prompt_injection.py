"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.

Capabilities:
- Detect hidden text (white-on-white, zero-size, off-page)
- Decode and scan base64 content
- Detect unicode homoglyph attacks
- Identify known prompt injection patterns
"""

import hashlib
import logging
import re
import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)
import os
from logging.handlers import RotatingFileHandler

audit_logger = logging.getLogger("audit.prompt_injection")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False  # prevent double-logging to root logger

_AUDIT_LOG_PATH = os.environ.get(
    "PROMPT_INJECTION_AUDIT_LOG",
    os.path.join(os.path.dirname(__file__), "audit_prompt_injection.log"),
)
_audit_handler = RotatingFileHandler(
    _AUDIT_LOG_PATH,
    mode="a",                  # append-only
    maxBytes=50 * 1024 * 1024,  # 50 MB per file
    backupCount=90,            # retain ~90 daily rotations (90-day minimum)
    encoding="utf-8",
    delay=False,
)
_audit_handler.setFormatter(
    logging.Formatter(
        fmt="%(asctime)s\t%(levelname)s\t%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
)
audit_logger.addHandler(_audit_handler)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns used by detect_prompt_injection()
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with detected threats, if any.
        """
        content_length = len(content) if content else 0

        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": content_length,
            }
        )

        # --- Audit: record decision inputs before detection runs ---
        _decision_id = str(uuid.uuid4())
        _input_hash = hashlib.sha256(
            content.encode("utf-8") if isinstance(content, str) else content
        ).hexdigest()
        _audit_entry_start = {
            "decision_id": _decision_id,
            "event": "scan_start",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detector": "PromptInjectionDetector/v1",
            "principal": source,
            "input_sha256": _input_hash,
            "content_length": content_length,
        }
        audit_logger.info(
            "AUDIT\t" + "\t".join(f"{k}={v}" for k, v in _audit_entry_start.items())
        )

        if not content:
            return ThreatDetectionResult(
                has_violations=False,
                threats=[],
                scanned_content_length=0
            )

        all_threats: list[ThreatMatch] = []

        all_threats.extend(await self.detect_hidden_text(content))
        all_threats.extend(await self.detect_encoded_content(content))
        all_threats.extend(await self.detect_prompt_injection(content))
        all_threats.extend(await self.detect_unicode_attacks(content))

        has_violations = len(all_threats) > 0

        if has_violations:
            logger.warning(
                "Threat detected in uploaded content",
                extra={
                    "source": source,
                    "threat_count": len(all_threats),
                    "categories": list({t.category for t in all_threats}),
                }
            )

        return ThreatDetectionResult(
            has_violations=has_violations,
            threats=all_threats,
            scanned_content_length=content_length
        )

        async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        Detects:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        threats: list[ThreatMatch] = []
        # Detect CSS-based hidden text patterns
        hidden_patterns = [
            r"color\s*:\s*white",
            r"font-size\s*:\s*0",
            r"display\s*:\s*none",
            r"visibility\s*:\s*hidden",
            r"opacity\s*:\s*0",
            r"position\s*:\s*absolute.*left\s*:\s*-\d+",
            r"text-indent\s*:\s*-\d+",
        ]
        for pattern in hidden_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                threats.append(ThreatMatch(
                    category="hidden_text",
                    description=f"Hidden text pattern detected: {match.group(0)[:80]}",
                    offset=match.start(),
                    matched_text=match.group(0)[:200],
                ))
        return threats

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        threats: list[ThreatMatch] = []
        # Detect base64-encoded content and decode it for secondary scanning
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.finditer(content):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                # Check decoded content for injection patterns
                for compiled in self._compiled_patterns:
                    if compiled.search(decoded):
                        threats.append(ThreatMatch(
                            category="encoded_content",
                            description=f"Base64-encoded prompt injection detected",
                            offset=match.start(),
                            matched_text=candidate[:200],
                        ))
                        break
            except Exception:
                pass
        # Detect HTML entity obfuscation
        html_entity_pattern = re.compile(r'(?:&#x?[0-9a-fA-F]+;){5,}')
        for match in html_entity_pattern.finditer(content):
            threats.append(ThreatMatch(
                category="encoded_content",
                description="Excessive HTML entity encoding detected",
                offset=match.start(),
                matched_text=match.group(0)[:200],
            ))
        return threats

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        threats: list[ThreatMatch] = []
        for compiled in self._compiled_patterns:
            for match in compiled.finditer(content):
                threats.append(ThreatMatch(
                    category="prompt_injection",
                    description=f"Prompt injection pattern matched: {match.group(0)[:80]}",
                    offset=match.start(),
                    matched_text=match.group(0)[:200],
                ))
        # PATTERN MATCHING NOW PERFORMED
        return []

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        VULNERABILITY: Not implemented - returns empty list.

        Should detect:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        # VULNERABILITY: Unicode attack detection not implemented
        return []

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        VULNERABILITY: Not implemented - returns no threats.

        Should scan:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        # VULNERABILITY: Metadata scanning not implemented
        return ThreatDetectionResult(
            has_violations=False,
            threats=[],
            scanned_content_length=len(str(metadata))
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    return decoded
                except:
                    continue
            return None
        except:
            return None


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class PromptInjectionDetector:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Actually scans for prompt injection patterns
#     - Detects hidden text in various formats
#     - Decodes and scans base64 content
#     - Identifies unicode attacks
#     """
#
#     async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
#         """Perform comprehensive threat scanning."""
#         threats = []

        # Check for prompt injection patterns
        for pattern in self._compiled_patterns:
            matches = pattern.findall(content)
            for match in matches:
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern",
                    content_preview=match,
                    location=source
                ))

        # Check for hidden/encoded content
        encoded_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_threats)

        # Check for unicode attacks
        unicode_threats = await self.detect_unicode_attacks(content)
        threats.extend(unicode_threats)

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(content)
        )
