"""Tests for auth middleware."""

import pytest
from ssh_mcp.auth import AuthError, AuthProvider
from ssh_mcp.config import (
    CommandTemplate,
    HostEntry,
    Role,
    ServerConfig,
    UserIdentity,
)


@pytest.fixture
def config_no_token():
    return ServerConfig(auth_token="")


@pytest.fixture
def config_with_token():
    return ServerConfig(auth_token="test-secret-token")


class TestAuthentication:
    def test_dev_mode_no_token(self, config_no_token):
        provider = AuthProvider(config_no_token)
        user = provider.authenticate("")
        assert user.user_id == "dev-user"
        assert Role.ADMIN in user.roles

    def test_valid_token(self, config_with_token):
        provider = AuthProvider(config_with_token)
        user = provider.authenticate("test-secret-token")
        assert user.user_id == "authenticated-user"

    def test_invalid_token(self, config_with_token):
        provider = AuthProvider(config_with_token)
        with pytest.raises(AuthError, match="Invalid or missing"):
            provider.authenticate("wrong-token")

    def test_empty_token_when_required(self, config_with_token):
        provider = AuthProvider(config_with_token)
        with pytest.raises(AuthError, match="Invalid or missing"):
            provider.authenticate("")


class TestAuthorization:
    def test_authorize_host_allowed(self):
        user = UserIdentity(user_id="u1", roles=[Role.OPERATOR])
        host = HostEntry(host_id="h1", hostname="x", allowed_roles=[Role.OPERATOR])
        AuthProvider.authorize_host(user, host)  # should not raise

    def test_authorize_host_denied(self):
        user = UserIdentity(user_id="u1", roles=[Role.DEVELOPER])
        host = HostEntry(host_id="h1", hostname="x", allowed_roles=[Role.ADMIN])
        with pytest.raises(AuthError, match="lacks required role"):
            AuthProvider.authorize_host(user, host)

    def test_authorize_command_allowed(self):
        user = UserIdentity(user_id="u1", roles=[Role.ADMIN])
        tpl = CommandTemplate(
            template_id="t1",
            description="test",
            command="echo",
            allowed_roles=[Role.ADMIN],
        )
        AuthProvider.authorize_command(user, tpl)

    def test_authorize_command_denied(self):
        user = UserIdentity(user_id="u1", roles=[Role.DEVELOPER])
        tpl = CommandTemplate(
            template_id="t1",
            description="test",
            command="echo",
            allowed_roles=[Role.ADMIN],
        )
        with pytest.raises(AuthError):
            AuthProvider.authorize_command(user, tpl)

    def test_check_roles(self):
        user = UserIdentity(user_id="u1", roles=[Role.AUDITOR])
        AuthProvider.check_roles(user, [Role.AUDITOR, Role.ADMIN])

    def test_check_roles_denied(self):
        user = UserIdentity(user_id="u1", roles=[Role.DEVELOPER])
        with pytest.raises(AuthError):
            AuthProvider.check_roles(user, [Role.ADMIN])
