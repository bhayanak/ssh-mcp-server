"""Authentication and authorization middleware."""

from __future__ import annotations

import hmac

from .config import CommandTemplate, HostEntry, Role, ServerConfig, UserIdentity


class AuthError(Exception):
    """Raised when authentication or authorization fails."""


class AuthProvider:
    """Validates caller identity and enforces RBAC policies."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config

    def authenticate(self, token: str) -> UserIdentity:
        """Validate bearer token and return identity.

        For MVP this uses a shared token from config.
        Production should use OIDC / mTLS client certs.
        """
        if not self._config.auth_token:
            # No token configured — dev mode, return default developer identity
            return UserIdentity(
                user_id="dev-user",
                roles=[Role.DEVELOPER, Role.OPERATOR, Role.ADMIN],
                display_name="Dev User",
            )

        if not token or not hmac.compare_digest(token, self._config.auth_token):
            raise AuthError("Invalid or missing authentication token")

        # In production, decode JWT / lookup session and populate properly
        return UserIdentity(
            user_id="authenticated-user",
            roles=[Role.DEVELOPER, Role.OPERATOR],
            display_name="Authenticated User",
        )

    @staticmethod
    def authorize_host(user: UserIdentity, host: HostEntry) -> None:
        """Check user has a role that is allowed on this host."""
        if not any(r in host.allowed_roles for r in user.roles):
            raise AuthError(
                f"User '{user.user_id}' lacks required role for host '{host.host_id}'"
            )

    @staticmethod
    def authorize_command(user: UserIdentity, template: CommandTemplate) -> None:
        """Check user has a role that is allowed for this command template."""
        if not any(r in template.allowed_roles for r in user.roles):
            raise AuthError(
                f"User '{user.user_id}' lacks required role for command '{template.template_id}'"
            )

    @staticmethod
    def authorize_role(user: UserIdentity, required: Role) -> None:
        """Check user has a specific role."""
        if required not in user.roles:
            raise AuthError(
                f"User '{user.user_id}' missing required role '{required.value}'"
            )

    @staticmethod
    def check_roles(user: UserIdentity, allowed: list[Role]) -> None:
        """Check user has at least one of the allowed roles."""
        if not any(r in allowed for r in user.roles):
            raise AuthError(
                f"User '{user.user_id}' lacks any of the required roles"
            )
