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

    # ---------------------------------------------------------------------------
    # Approved model registry: only these (model_id, model_version) pairs are
    # permitted.  Entries are immutable at class definition time.
    # ---------------------------------------------------------------------------
    _APPROVED_REGISTRY: dict[str, list[str]] = {
        "unifai-audit-v1": ["1.0.0", "1.1.0", "1.2.0"],
        "unifai-audit-v2": ["2.0.0", "2.1.0"],
    }

    # Pinned defaults — never fall back to env-var strings like 'unknown-model'.
    DEFAULT_MODEL_ID: str = "unifai-audit-v2"
    DEFAULT_MODEL_VERSION: str = "2.1.0"

    @classmethod
    def _validate_model(cls, model_id: str, model_version: str) -> None:
        """Raise ValueError if (model_id, model_version) is not in the approved registry."""
        approved_versions = cls._APPROVED_REGISTRY.get(model_id)
        if approved_versions is None:
            raise ValueError(
                f"Model '{model_id}' is not in the approved model registry. "
                f"Approved models: {list(cls._APPROVED_REGISTRY.keys())}"
            )
        if model_version not in approved_versions:
            raise ValueError(
                f"Model version '{model_version}' for '{model_id}' is not approved. "
                f"Approved versions: {approved_versions}"
            )

    def __init__(
        self,
        model_id: Optional[str] = None,
        model_version: Optional[str] = None,
    ):
        # Resolve to pinned defaults when not explicitly supplied.
        resolved_model_id: str = model_id if model_id is not None else self.DEFAULT_MODEL_ID
        resolved_model_version: str = model_version if model_version is not None else self.DEFAULT_MODEL_VERSION

        # Enforce registry membership before any state is set.
        self._validate_model(resolved_model_id, resolved_model_version)

        # Append-only in-memory buffer (tuple-based to prevent mutation).
        self.__events: list[dict] = []
        self._model_id: str = resolved_model_id
        self._model_version: str = resolved_model_version

    async def log_event(
        self,
        event_type: str,
        details: dict[str, Any],
        user_id: Optional[str] = None,
        severity: str = "info",
        correlation_id: Optional[str] = None,
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

        import uuid as _uuid
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "correlation_id": correlation_id or str(_uuid.uuid4()),
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
            # Re-raise so callers and alerting channels are notified of the
            # persistence failure — silent failure is not acceptable for audit
            # trail integrity.
            raise RuntimeError(
                f"Audit persistence failure for event '{event_type}': {persist_err}"
            ) from persist_err

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
        violation_details: dict,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Log a policy violation.
        """
        await self.log_event(
            event_type="policy_violation",
            details={
                "policy": policy_type,
                **violation_details
            },
            severity="warning",
            correlation_id=correlation_id,
        )

    async def log_data_access(
        self,
        resource: str,
        action: str,
        user_id: str,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Log data access for compliance.
        """
        await self.log_event(
            event_type="data_access",
            details={
                "resource": resource,
                "action": action
            },
            user_id=user_id,
            correlation_id=correlation_id,
        )

    def get_recent_events(self, count: int = 100) -> list[dict]:
        """Return a read-only copy of the most recent audit events (debugging only)."""
        # Return copies so callers cannot mutate the internal buffer.
        return [dict(e) for e in self.__events[-count:]]
