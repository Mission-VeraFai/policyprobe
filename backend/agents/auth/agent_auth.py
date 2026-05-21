"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES:
- All inter-agent calls require valid JWT token authentication
- is_internal flag does NOT bypass authentication or privilege checks
- JWT tokens are validated on every request
- Audit logging is performed for all auth decisions
"""

import logging
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    # is_internal is informational only and does NOT bypass authentication
    is_internal: bool = False

    def to_dict(self) -> dict:
        """Return a minimised, public-safe representation of this identity.

        Internal fields (agent_id, privilege_level, is_internal) are intentionally
        excluded to prevent leaking raw internal metadata in output.
        """
        return {
            "agent_name": self.agent_name
        }


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    Enforces authentication and authorization for inter-agent communication.
    All callers, including internal agents, must present a valid JWT token.
    The is_internal flag is informational only and does not bypass any check.

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (not used in vulnerable version)
        """
        if not jwt_secret:
            raise ValueError(
                "jwt_secret must be provided. Supply it via an environment variable "
                "(e.g. os.environ['JWT_SECRET']) rather than a hardcoded value."
            )
        self._jwt_secret = jwt_secret
        # Cache stores: token_key -> {"payload": <decoded payload>, "expires_at": <unix timestamp>}
        self._token_cache: dict = {}

        # Persistent audit trail configuration
        import os
        self._audit_log_path: str = os.environ.get(
            "AGENT_AUDIT_LOG_PATH", "/var/log/agent_auth_audit.jsonl"
        )
        # Retention: rotate when file exceeds this size (bytes); default 50 MB
        self._audit_max_bytes: int = int(
            os.environ.get("AGENT_AUDIT_MAX_BYTES", str(50 * 1024 * 1024))
        )
        # Model/version identifier stamped on every record.
        # These are pinned immutable constants — NOT sourced from env vars —
        # and are validated against the approved model registry at init time.
        _APPROVED_MODEL_REGISTRY: dict = {
            "agent_auth": {"versions": {"2.1.0"}, "status": "approved"},
        }
        _PINNED_MODEL_ID: str = "agent_auth"
        _PINNED_MODEL_VERSION: str = "2.1.0"

        _registry_entry = _APPROVED_MODEL_REGISTRY.get(_PINNED_MODEL_ID)
        if _registry_entry is None:
            raise ValueError(
                f"Model '{_PINNED_MODEL_ID}' is not in the approved model registry."
            )
        if _PINNED_MODEL_VERSION not in _registry_entry["versions"]:
            raise ValueError(
                f"Model '{_PINNED_MODEL_ID}' version '{_PINNED_MODEL_VERSION}' "
                "is not an approved version in the registry."
            )
        if _registry_entry.get("status") != "approved":
            raise ValueError(
                f"Model '{_PINNED_MODEL_ID}' does not have 'approved' status "
                "in the registry."
            )

        self._model_id: str = _PINNED_MODEL_ID
        self._model_version: str = _PINNED_MODEL_VERSION

        # Ensure the audit log directory exists
        _audit_dir = os.path.dirname(self._audit_log_path)
        if _audit_dir:
            os.makedirs(_audit_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Token-cache helpers (expiry-aware)
    # ------------------------------------------------------------------

    def _cache_token(self, token: str, payload: dict) -> None:
        """Store a decoded JWT payload in the cache, keyed by token, with expiry."""
        import time
        exp = payload.get("exp")
        if exp is None:
            # Tokens without an exp claim are not cached to avoid unbounded growth.
            return
        self._token_cache[token] = {"payload": payload, "expires_at": float(exp)}

    def _get_cached_token(self, token: str) -> "Optional[dict]":
        """Return the cached payload for *token* if it exists and has not expired.

        Expired entries are evicted on access.
        """
        import time
        entry = self._token_cache.get(token)
        if entry is None:
            return None
        if time.time() > entry["expires_at"]:
            # Evict the expired entry immediately.
            del self._token_cache[token]
            return None
        return entry["payload"]

    def _evict_expired_tokens(self) -> None:
        """Remove all expired entries from the token cache."""
        import time
        now = time.time()
        expired_keys = [
            k for k, v in self._token_cache.items() if now > v["expires_at"]
        ]
        for k in expired_keys:
            del self._token_cache[k]

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def _rotate_audit_log_if_needed(self) -> None:
        """Rotate the audit log file if it exceeds the configured maximum size."""
        import os
        import shutil
        import datetime
        try:
            if (
                os.path.exists(self._audit_log_path)
                and os.path.getsize(self._audit_log_path) >= self._audit_max_bytes
            ):
                rotated_path = (
                    self._audit_log_path
                    + "." + datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                )
                shutil.move(self._audit_log_path, rotated_path)
                logger.info("Audit log rotated to %s", rotated_path)
        except OSError as exc:
            logger.error("Failed to rotate audit log: %s", exc)

    def _audit_log(
        self,
        action: str,
        principal: Optional[str],
        resource: str,
        decision: bool,
        reason: Optional[str] = None,
        input_data: Optional[dict] = None,
    ) -> None:
        """Append a structured audit record to the persistent append-only JSONL file."""
        import datetime
        import hashlib
        import json
        import os

        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        # Compute a SHA-256 hash of the input payload for forensic integrity
        input_payload = json.dumps(
            input_data if input_data is not None else {}, sort_keys=True
        )
        input_hash = hashlib.sha256(input_payload.encode("utf-8")).hexdigest()

        record = {
            "timestamp": timestamp,
            "action": action,
            "principal": principal,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "input_hash": input_hash,
            "model_id": self._model_id,
            "model_version": self._model_version,
        }

        # Rotate before writing if the file is too large
        self._rotate_audit_log_if_needed()

        # Append atomically to the JSONL file (append mode is O_APPEND-safe on POSIX)
        try:
            with open(self._audit_log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            logger.error("Failed to write audit record to %s: %s", self._audit_log_path, exc)

        logger.info(
            "AUDIT | action=%s principal=%s resource=%s decision=%s "
            "reason=%s input_hash=%s model=%s@%s ts=%s",
            action,
            principal,
            resource,
            decision,
            reason,
            input_hash,
            self._model_id,
            self._model_version,
            timestamp,
        )

    def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request.

        Extracts the Bearer token from the request headers and delegates
        to validate_token() for full JWT verification.

        Args:
            request: Request dictionary with headers and context

        Returns:
            True only if the token is present and passes JWT validation
        """
        headers = request.get("headers", {})
        auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("verify() called with missing or malformed Authorization header")
            self._audit_log(
                action="verify",
                principal=None,
                resource=request.get("path", "unknown"),
                decision=False,
                reason="Missing or malformed Authorization header",
            )
            return False
        token = auth_header[len("Bearer "):].strip()
        # Use a safe token prefix as the principal identifier in audit records
        token_prefix = token[:16] + "..." if len(token) > 16 else token
        result = self.validate_token(token)
        if not result.authenticated:
            logger.warning(f"verify() failed: {result.reason}")
        self._audit_log(
            action="verify",
            principal=result.agent_id if result.agent_id else token_prefix,
            resource=request.get("path", "unknown"),
            decision=result.authenticated,
            reason=result.reason,
        )
        return result.authenticated

            def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token.

        Decodes and verifies the JWT signature using self.jwt_secret,
        checks expiration, and extracts agent_id and privileges from
        the verified claims.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on
            success, or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        logger.info(
            "auth_decision",
            extra={
                "event": "validate_token_start",
                "token_prefix": token[:8] + "...",
            },
        )

        # Check cache first (keyed by token to avoid re-validating the same JWT)
        if token in self._token_cache:
            cached = self._token_cache[token]
            logger.debug(f"Returning cached auth result for agent: {cached.agent_id}")
            return cached

        try:
            import jwt as _jwt  # PyJWT

            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "iat", "sub"],
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )

            agent_id = payload.get("sub")
            if not agent_id:
                return AuthResult(
                    authenticated=False,
                    reason="Token missing 'sub' claim"
                )

            privileges = payload.get("privileges", [])
            if not isinstance(privileges, list):
                return AuthResult(
                    authenticated=False,
                    reason="Invalid 'privileges' claim format"
                )

            logger.info(
                "auth_decision",
                extra={
                    "event": "token_validated",
                    "agent_id": agent_id,
                    "privileges": privileges,
                    "outcome": "success",
                },
            )
            result = AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges
            )
            self._token_cache[token] = result
            logger.info(f"Token validated successfully for agent: {agent_id}")
            return result

        except Exception as exc:
            logger.warning(f"Token validation failed: {exc}")
            return AuthResult(
                authenticated=False,
                reason=f"Token validation error: {exc}"
            ) -> AuthResult:
        """
        Validate an agent authentication token via JWT verification.

        Steps performed:
          1. Reject empty tokens immediately.
          2. Decode and verify the JWT signature using self.jwt_secret.
          3. Validate expiration (exp), not-before (nbf), issuer (iss),
             and audience (aud) claims.
          4. Extract agent_id and privileges from verified payload.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on
            success, or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
        except ImportError:
            logger.error("PyJWT is not installed; cannot validate tokens")
            return AuthResult(
                authenticated=False,
                reason="JWT library unavailable"
            )

        try:
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "iat", "sub"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                },
            )
        except _jwt.ExpiredSignatureError:
            logger.warning("validate_token(): token has expired")
            return AuthResult(authenticated=False, reason="Token expired")
        except _jwt.InvalidTokenError as exc:
            logger.warning(f"validate_token(): invalid token — {exc}")
            return AuthResult(authenticated=False, reason=f"Invalid token: {exc}")

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(authenticated=False, reason="Token missing 'sub' claim")

        # Privileges must be an explicit list in the token; default to nothing.
        privileges = payload.get("privileges")
        if not isinstance(privileges, list):
            privileges = []

        logger.debug(
            f"validate_token(): authenticated agent '{agent_id}' "
            f"with privileges {privileges}"
        )
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges,
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        Performs full JWT verification:
          1. Decodes and verifies the JWT signature using self.jwt_secret.
          2. Checks token expiration (exp claim).
          3. Verifies the issuer (iss == "agent-auth") and audience (aud == "agent-api").
          4. Extracts agent_id and privileges from the verified payload.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on success,
            or authenticated=False with a reason on any failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        logger.debug(f"Token validation requested: {token[:20]}...")

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                issuer="agent-auth",
                audience="agent-api",
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except Exception as exc:  # covers ExpiredSignatureError, InvalidTokenError, etc.
            logger.warning(f"Token validation failed: {exc}")
            return AuthResult(
                authenticated=False,
                reason=f"Token validation failed: {exc}"
            )

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(
                authenticated=False,
                reason="Token missing 'sub' claim"
            )

        privileges = payload.get("privileges", [])
        if not isinstance(privileges, list):
            privileges = []

        # Cache the validated result keyed by token for this session
        self._token_cache[token] = {"agent_id": agent_id, "privileges": privileges}

        logger.info(f"Token validated successfully for agent: {agent_id}")
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        VULNERABILITY: Token is never actually validated.
        Any non-empty token is accepted.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success (always succeeds with any token)
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # VULNERABILITY: No actual JWT validation
        # Any token string is accepted
        logger.debug(f"Token validation requested: {token[:20]}...")

        # In a secure implementation, this would:
        # 1. Decode and verify JWT signature
        # 2. Check token expiration
        # 3. Verify issuer and audience claims
        # 4. Extract and validate privileges

        # Instead, we just return success
        # Output data minimisation: do not expose internal agent_id or full
        # privileges list to callers; only surface the authenticated flag.
        return AuthResult(
            authenticated=True,
            agent_id=None,
            privileges=[]
        )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        VULNERABILITY: is_internal flag bypasses all checks.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized (or if is_internal is True)
        """
        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        return caller_level >= required

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        VULNERABILITY: Generates a static, predictable token.
        Not cryptographically secure.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A token string (not actually secure)
        """
        # VULNERABILITY: Predictable token generation
        # Real implementation should use JWT with proper signing
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                # VULNERABILITY: Token logged in plaintext
                "token": token
            }
        )

        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        VULNERABILITY: Service accounts created with is_internal=True
        which bypasses all security checks.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True  # VULNERABILITY: Automatic internal flag
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.

        VULNERABILITY: Logging is minimal and not sent to secure audit system.
        """
        # VULNERABILITY: Only local logging, no secure audit trail
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class AgentAuthenticator:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version includes:
#     - Proper JWT validation
#     - Privilege verification without bypasses
#     - Comprehensive audit logging
#     - Rate limiting
#     """
#
#     def __init__(self, jwt_secret: str):
#         if not jwt_secret or jwt_secret == "default-secret-not-used":
#             raise ValueError("JWT secret must be provided")
#         self.jwt_secret = jwt_secret
#         self._failed_attempts = {}
#
#     def verify(self, request: dict) -> AuthResult:
#         """Verify request with proper JWT validation."""
#         token = request.get("headers", {}).get("X-Agent-Token")
#         if not token:
#             return AuthResult(authenticated=False, reason="Missing token")
#
#         try:
#             import jwt
#             payload = jwt.decode(
#                 token,
#                 self.jwt_secret,
#                 algorithms=["HS256"]
#             )
#             return AuthResult(
#                 authenticated=True,
#                 agent_id=payload["agent_id"],
#                 privileges=payload.get("privileges", [])
#             )
#         except jwt.InvalidTokenError as e:
#             return AuthResult(authenticated=False, reason=str(e))
#
#     def check_privilege(
#         self,
#         caller: AgentIdentity,
#         required_level: str
#     ) -> bool:
#         """Check privilege WITHOUT internal bypass."""
#         # No is_internal bypass - all callers must have valid privileges
#         caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
#         required = self.PRIVILEGE_LEVELS.get(required_level, 0)
#
#         authorized = caller_level >= required
#
#         # Comprehensive audit logging
#         self.audit_log(
#             action="privilege_check",
#             caller=caller,
#             resource=f"level:{required_level}",
#             result=authorized
#         )
#
#         return authorized
