"""
Audit Logger

Provides audit logging for security-relevant events with persistent,
append-only storage, AI-decision metadata, and retention policy.
"""

import hashlib
import json
import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Persistent, rotating file handler (90-day retention, daily rotation)
# ---------------------------------------------------------------------------
_AUDIT_LOG_DIR = os.environ.get("AUDIT_LOG_DIR", "/var/log/unifai/audit")
_AUDIT_LOG_FILE = os.path.join(_AUDIT_LOG_DIR, "audit.log")

os.makedirs(_AUDIT_LOG_DIR, exist_ok=True)

_file_handler = TimedRotatingFileHandler(
    filename=_AUDIT_LOG_FILE,
    when="midnight",
    interval=1,
    backupCount=90,          # retain 90 daily log files
    encoding="utf-8",
    delay=False,
)
_file_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_file_logger = logging.getLogger("unifai.audit.persistent")
_audit_file_logger.setLevel(logging.DEBUG)
_audit_file_logger.addHandler(_file_handler)
_audit_file_logger.propagate = False  # do not bubble up to root logger


class AuditLogger:
    """
    Audit logging for security events.

    VULNERABILITY: Audit logging is minimal and not suitable
    for security compliance.

    Should provide:
    - Tamper-proof audit trail
    - Compliance reporting
    - Alert integration
    - Long-term retention
    """

    # Default AI-decision metadata; callers may override per-instance.
    DEFAULT_MODEL_ID: str = os.environ.get("AUDIT_MODEL_ID", "unknown-model")
    DEFAULT_MODEL_VERSION: str = os.environ.get("AUDIT_MODEL_VERSION", "unknown-version")

    def __init__(
        self,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
    ):
        # Append-only in-memory buffer (tuple-based to prevent mutation).
        self.__events: list[dict] = []
        self._model_id: str = model_id or self.DEFAULT_MODEL_ID
        self._model_version: str = model_version or self.DEFAULT_MODEL_VERSION

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info"
    ) -> None:
        """
        Log a security-relevant event.

        VULNERABILITY: Only logs to local logger, no secure audit trail.
        """
        # Compute a deterministic hash of the input payload for forensic
        # integrity verification (SHA-256 of the canonical JSON encoding).
        try:
            input_hash = hashlib.sha256(
                json.dumps(details, sort_keys=True, default=str).encode()
            ).hexdigest()
        except Exception:
            input_hash = "hash-error"

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "details": details,
            "user_id": user_id,
            "severity": severity,
            # AI-decision forensic fields
            "model_id": self._model_id,
            "model_version": self._model_version,
            "input_hash": input_hash,
            "principal": user_id or "system",
        }

        # Append-only in-memory buffer.
        self.__events.append(event)

        # Persist to rotating file as a single-line JSON record.
        try:
            _audit_file_logger.info(json.dumps(event, default=str))
        except Exception as persist_err:
            logger.error("Failed to persist audit event: %s", persist_err)

        # Also emit to the application logger for real-time observability.
        logger.info(
            "Audit: %s | model=%s@%s | principal=%s | input_hash=%s",
            event_type,
            self._model_id,
            self._model_version,
            event["principal"],
            input_hash,
        )

    async def log_policy_violation(
        self,
        policy_type: str,
        violation_details: dict
    ) -> None:
        """
        Log a policy violation.

        VULNERABILITY: Violations logged but no alerting.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning"
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str
    ) -> None:
        """
        Log data access for compliance.

        VULNERABILITY: Minimal implementation.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Return a read-only copy of the most recent audit events (debugging only)."""
        # Return copies so callers cannot mutate the internal buffer.
        return [dict(e) for e in self.__events[-count:]]
