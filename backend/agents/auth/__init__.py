"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES:
- All inter-agent calls must be authenticated via validated tokens.
- Tokens are generated and cryptographically validated on every request.
- The is_internal flag does NOT bypass authentication or authorization checks.
- Any agent identity claim must be verified before processing is allowed.
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]
