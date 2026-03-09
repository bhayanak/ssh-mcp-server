"""Configuration and policy model for SSH MCP server."""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings


def default_config_dir() -> Path:
    """Return the default config directory: ~/.ssh-mcp"""
    return Path.home() / ".ssh-mcp"


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class Role(str, Enum):
    DEVELOPER = "developer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    ADMIN = "admin"


# ---------------------------------------------------------------------------
# Host definition
# ---------------------------------------------------------------------------


class HostEntry(BaseModel):
    host_id: str = Field(..., pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str
    port: int = 22
    ssh_user: str = ""  # SSH username; empty = current OS user
    labels: dict[str, str] = {}
    description: str = ""
    allowed_roles: list[Role] = [Role.OPERATOR, Role.ADMIN]


# ---------------------------------------------------------------------------
# Command template — only these are executable
# ---------------------------------------------------------------------------


class CommandTemplate(BaseModel):
    template_id: str = Field(..., pattern=r"^[a-z0-9_]+$")
    description: str
    command: str  # e.g. "systemctl status {service}"
    allowed_params: dict[str, str] = {}  # param_name -> regex pattern
    allowed_roles: list[Role] = [Role.OPERATOR, Role.ADMIN]
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    risk_level: str = Field(default="medium", pattern=r"^(low|medium|high)$")

    def render(self, params: dict[str, str]) -> str:
        """Safely substitute params after validation."""
        for name, pattern in self.allowed_params.items():
            value = params.get(name, "")
            if not re.fullmatch(pattern, value):
                raise ValueError(
                    f"Parameter '{name}' value '{value}' does not match policy pattern"
                )
            # Block path traversal sequences in any parameter
            if ".." in value:
                raise ValueError(
                    f"Parameter '{name}' contains path traversal sequence"
                )
        # Only substitute known params — anything else stays literal
        try:
            return self.command.format(**{k: params[k] for k in self.allowed_params if k in params})
        except KeyError as exc:
            raise ValueError(f"Missing required parameter: {exc}") from exc


# ---------------------------------------------------------------------------
# Transfer policy
# ---------------------------------------------------------------------------


class TransferPolicy(BaseModel):
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=0)  # 50 MB
    max_download_bytes: int = Field(default=50 * 1024 * 1024, ge=0)
    allowed_paths: list[str] = ["/tmp/*", "/var/log/*"]
    blocked_extensions: list[str] = [".exe", ".sh", ".bat", ".ps1", ".dll", ".so"]
    require_justification_for_download: bool = True


# ---------------------------------------------------------------------------
# Key policy
# ---------------------------------------------------------------------------


class KeyPolicy(BaseModel):
    default_ttl_seconds: int = Field(default=86400, ge=60)  # 24h
    max_ttl_seconds: int = Field(default=86400 * 7, ge=60)  # 7d
    min_key_bits: int = 2048
    require_approval_for_privileged: bool = True


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


class RateLimits(BaseModel):
    max_requests_per_minute: int = 30
    max_concurrent: int = 5


# ---------------------------------------------------------------------------
# User identity (from auth token / cert)
# ---------------------------------------------------------------------------


class UserIdentity(BaseModel):
    user_id: str
    roles: list[Role]
    display_name: str = ""


# ---------------------------------------------------------------------------
# Top-level server config
# ---------------------------------------------------------------------------


class ServerConfig(BaseSettings):
    model_config = {"env_prefix": "SSH_MCP_"}

    server_name: str = "ssh-mcp-server"
    host: str = "127.0.0.1"
    port: int = 8022

    # Base config directory — all relative paths resolve from here.
    # Override with SSH_MCP_CONFIG_DIR env var.
    config_dir: Path = Field(default_factory=default_config_dir)

    # Auth
    auth_token: str = Field(default="", description="Shared bearer token for dev/test")

    # Paths — when None, resolved from config_dir by _resolve_paths validator.
    # Set explicitly (or via env vars) to override.
    hosts_file: Path | None = None
    templates_file: Path | None = None

    # Policy
    transfer_policy: TransferPolicy = TransferPolicy()
    key_policy: KeyPolicy = KeyPolicy()
    rate_limits: RateLimits = RateLimits()

    # Audit
    audit_log_dir: Path | None = None

    # Certificate manager
    cert_data_dir: Path | None = None

    # Approvals
    approval_data_dir: Path | None = None
    require_two_party_approval: bool = True

    # SSH known hosts (for paramiko)
    ssh_known_hosts_file: Path | None = None
    ssh_timeout_seconds: int = 30

    @model_validator(mode="after")
    def _resolve_paths(self) -> "ServerConfig":
        """Derive unset paths from config_dir so a single env var suffices."""
        if self.hosts_file is None:
            self.hosts_file = self.config_dir / "hosts.json"
        if self.templates_file is None:
            self.templates_file = self.config_dir / "templates.json"
        if self.audit_log_dir is None:
            self.audit_log_dir = self.config_dir / "audit_logs"
        if self.cert_data_dir is None:
            self.cert_data_dir = self.config_dir / "cert_data"
        if self.approval_data_dir is None:
            self.approval_data_dir = self.config_dir / "approval_data"
        return self
