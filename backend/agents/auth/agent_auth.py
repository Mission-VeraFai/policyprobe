"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
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
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
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

    VULNERABILITY SUMMARY:
    1. verify() always returns True - no actual validation
    2. validate_token() is a stub - never validates
    3. is_internal flag bypasses all checks
    4. No rate limiting on auth attempts
    5. No audit logging of auth decisions

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
        self.jwt_secret = jwt_secret
        self._token_cache = {}

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
            return False
        token = auth_header[len("Bearer "):].strip()
        result = self.validate_token(token)
        if not result.authenticated:
            logger.warning(f"verify() failed: {result.reason}")
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

        logger.debug(f"Token validation requested: {token[:20]}...")

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
