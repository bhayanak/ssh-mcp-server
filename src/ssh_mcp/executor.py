"""SSH execution engine — runs commands on remote hosts via paramiko."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import paramiko

from .config import CommandTemplate, HostEntry, ServerConfig
from .redact import redact


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    redacted: bool = False


class SSHExecutor:
    """Execute commands on remote hosts with policy-enforced constraints."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config

    def run_command(
        self,
        host: HostEntry,
        template: CommandTemplate,
        params: dict[str, str],
        *,
        timeout: int | None = None,
    ) -> ExecResult:
        """Render template, execute via SSH, redact output, return result."""
        resolved_cmd = template.render(params)
        effective_timeout = min(
            timeout or template.timeout_seconds,
            template.timeout_seconds,
        )

        client = paramiko.SSHClient()
        if self._config.ssh_known_hosts_file:
            client.load_host_keys(str(self._config.ssh_known_hosts_file))
        else:
            # For dev/test only — production must use known hosts or CA verification
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        t0 = time.monotonic()
        connect_kwargs: dict[str, Any] = {
            "hostname": host.hostname,
            "port": host.port,
            "timeout": self._config.ssh_timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if host.ssh_user:
            connect_kwargs["username"] = host.ssh_user
        try:
            client.connect(**connect_kwargs)
            _, stdout_ch, stderr_ch = client.exec_command(
                resolved_cmd, timeout=effective_timeout
            )
            stdout_raw = stdout_ch.read().decode("utf-8", errors="replace")
            stderr_raw = stderr_ch.read().decode("utf-8", errors="replace")
            exit_code = stdout_ch.channel.recv_exit_status()
        except Exception as exc:
            duration = (time.monotonic() - t0) * 1000
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=redact(str(exc)),
                duration_ms=duration,
                redacted=True,
            )
        finally:
            client.close()

        duration = (time.monotonic() - t0) * 1000
        return ExecResult(
            exit_code=exit_code,
            stdout=redact(stdout_raw),
            stderr=redact(stderr_raw),
            duration_ms=round(duration, 2),
            redacted=True,
        )

    @staticmethod
    def get_host_facts_cmd() -> str:
        """Return a safe composite command that gathers host metadata."""
        return (
            "echo '---HOSTNAME---' && hostname -f 2>/dev/null || hostname && "
            "echo '---UPTIME---' && uptime && "
            "echo '---OS---' && (cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || echo unknown) && "
            "echo '---KERNEL---' && uname -a"
        )

    def run_command_on_client(
        self,
        client: paramiko.SSHClient,
        template: CommandTemplate,
        params: dict[str, str],
        *,
        timeout: int | None = None,
    ) -> ExecResult:
        """Execute a template command on an already-connected SSH client.

        Used by session-based execution to avoid reconnecting.
        """
        resolved_cmd = template.render(params)
        effective_timeout = min(
            timeout or template.timeout_seconds,
            template.timeout_seconds,
        )

        t0 = time.monotonic()
        try:
            _, stdout_ch, stderr_ch = client.exec_command(
                resolved_cmd, timeout=effective_timeout
            )
            stdout_raw = stdout_ch.read().decode("utf-8", errors="replace")
            stderr_raw = stderr_ch.read().decode("utf-8", errors="replace")
            exit_code = stdout_ch.channel.recv_exit_status()
        except Exception as exc:
            duration = (time.monotonic() - t0) * 1000
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=redact(str(exc)),
                duration_ms=duration,
                redacted=True,
            )

        duration = (time.monotonic() - t0) * 1000
        return ExecResult(
            exit_code=exit_code,
            stdout=redact(stdout_raw),
            stderr=redact(stderr_raw),
            duration_ms=round(duration, 2),
            redacted=True,
        )
