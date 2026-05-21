"""
Policy Enforcement Modules

Contains modules for detecting and enforcing security policies:
- PII Detection: Identifies personally identifiable information
- Prompt Injection: Detects hidden/malicious prompts
- Content Scanner: Extracts and analyzes hidden content

SECURITY REQUIREMENTS:
All policy modules MUST perform active security scanning before content
is forwarded to the AI model. NO-OP or pass-through implementations
are strictly prohibited in any environment.
"""

from .pii_detection import PIIDetector, PIIDetectionResult
from .prompt_injection import PromptInjectionDetector, ThreatDetectionResult
from .content_scanner import ContentScanner

__all__ = [
    "PIIDetector",
    "PIIDetectionResult",
    "PromptInjectionDetector",
    "ThreatDetectionResult",
    "ContentScanner",
]

# Runtime enforcement: verify that critical policy classes expose a callable
# scan/detect interface, preventing silent NO-OP stub deployments.
def _verify_policy_implementations() -> None:
    required = {
        "PIIDetector": (PIIDetector, "detect"),
        "PromptInjectionDetector": (PromptInjectionDetector, "detect"),
        "ContentScanner": (ContentScanner, "scan"),
    }
    for name, (cls, method) in required.items():
        if not callable(getattr(cls, method, None)):
            raise NotImplementedError(
                f"{name}.{method}() is not implemented. "
                "All policy modules must perform active security scanning. "
                "NO-OP pass-through implementations are not permitted."
            )

_verify_policy_implementations()
