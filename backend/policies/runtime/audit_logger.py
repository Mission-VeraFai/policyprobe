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
    backupCount=365,         # retain 365 daily log files (1-year minimum retention policy)
    encoding="utf-8",
    delay=False,
)

# Attempt to set append-only flag on the log file to prevent truncation/deletion.
# This is a best-effort hardening step; failures are logged but do not abort startup.
def _set_append_only(path: str) -> None:
    """Set the append-only immutable flag on *path* using chattr (Linux only)."""
    import subprocess
    try:
        subprocess.run(
            ["chattr", "+a", path],
            check=True,
            capture_output=True,
            timeout=5,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "audit_logger: could not set append-only flag on %s: %s",
            path,
            exc,
        )

_set_append_only(_AUDIT_LOG_FILE)
_file_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_file_logger = logging.getLogger("unifai.audit.persistent")
_audit_file_logger.setLevel(logging.DEBUG)
_audit_file_logger.addHandler(_file_handler)
_audit_file_logger.propagate = False  # do not bubble up to root logger


class _AppendOnlyList(list):
    """A list subclass that forbids operations which would remove or replace entries.

    Only ``append`` and read operations are permitted, enforcing an append-only
    guarantee on the in-memory audit event store.
    """

    _MUTATING_METHODS = (
        "clear", "pop", "remove", "__delitem__", "__setitem__", "__iadd__",
        "__imul__", "insert",  # insert could be used to overwrite via slice
    )

    def _raise(self, *_args: Any, **_kwargs: Any) -> None:  # type: ignore[override]
        raise RuntimeError(
            "Audit event log is append-only: destructive operations are not permitted."
        )

    clear = _raise  # type: ignore[assignment]
    pop = _raise  # type: ignore[assignment]
    remove = _raise  # type: ignore[assignment]

    def __delitem__(self, key: Any) -> None:  # type: ignore[override]
        raise RuntimeError(
            "Audit event log is append-only: deletion is not permitted."
        )

    def __setitem__(self, key: Any, value: Any) -> None:  # type: ignore[override]
        raise RuntimeError(
            "Audit event log is append-only: item replacement is not permitted."
        )


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
        self.__events: "_AppendOnlyList" = _AppendOnlyList()
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
        except Exception as hash_err:
            logger.error(
                "Audit hashing failure for event '%s': %s", event_type, hash_err
            )
            raise RuntimeError(
                f"Audit hashing failure for event '{event_type}': {hash_err}"
            ) from hash_err

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
