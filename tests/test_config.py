"""Tests for config and policy model."""

import pytest
from pathlib import Path
from ssh_mcp.config import CommandTemplate, HostEntry, Role, ServerConfig, TransferPolicy, KeyPolicy


class TestCommandTemplate:
    def test_render_valid_params(self):
        tpl = CommandTemplate(
            template_id="svc_status",
            description="Check service",
            command="systemctl status {service}",
            allowed_params={"service": r"^[a-zA-Z0-9_.-]+$"},
        )
        assert tpl.render({"service": "nginx"}) == "systemctl status nginx"

    def test_render_rejects_shell_injection(self):
        tpl = CommandTemplate(
            template_id="svc_status",
            description="Check service",
            command="systemctl status {service}",
            allowed_params={"service": r"^[a-zA-Z0-9_.-]+$"},
        )
        with pytest.raises(ValueError, match="does not match policy pattern"):
            tpl.render({"service": "nginx; rm -rf /"})

    def test_render_rejects_missing_param(self):
        tpl = CommandTemplate(
            template_id="tail",
            description="Tail log",
            command="tail -n {lines} {log_path}",
            allowed_params={
                "lines": r"^[0-9]+$",
                "log_path": r"^/var/log/[a-zA-Z0-9_./-]+$",
            },
        )
        with pytest.raises(ValueError, match="does not match policy pattern"):
            tpl.render({"lines": "100"})

    def test_render_rejects_path_traversal(self):
        tpl = CommandTemplate(
            template_id="tail",
            description="Tail log",
            command="tail -n {lines} {log_path}",
            allowed_params={
                "lines": r"^[0-9]+$",
                "log_path": r"^/var/log/[a-zA-Z0-9_./-]+$",
            },
        )
        with pytest.raises(ValueError, match="does not match policy pattern"):
            tpl.render({"lines": "10", "log_path": "/etc/shadow"})

    def test_no_params_command(self):
        tpl = CommandTemplate(
            template_id="df",
            description="Disk usage",
            command="df -h",
            allowed_params={},
        )
        assert tpl.render({}) == "df -h"


class TestHostEntry:
    def test_valid_host(self):
        h = HostEntry(host_id="web-01", hostname="10.0.0.1")
        assert h.port == 22
        assert h.allowed_roles == [Role.OPERATOR, Role.ADMIN]

    def test_invalid_host_id(self):
        with pytest.raises(Exception):
            HostEntry(host_id="web 01; bad", hostname="10.0.0.1")


class TestTransferPolicy:
    def test_defaults(self):
        p = TransferPolicy()
        assert p.max_upload_bytes == 50 * 1024 * 1024
        assert ".exe" in p.blocked_extensions
        assert p.require_justification_for_download is True


class TestKeyPolicy:
    def test_defaults(self):
        kp = KeyPolicy()
        assert kp.default_ttl_seconds == 86400
        assert kp.min_key_bits == 2048


class TestServerConfig:
    def test_default_config_dir(self):
        cfg = ServerConfig()
        assert cfg.config_dir == Path.home() / ".ssh-mcp"

    def test_paths_derive_from_config_dir(self):
        cfg = ServerConfig(config_dir=Path("/opt/ssh-mcp"))
        assert cfg.hosts_file == Path("/opt/ssh-mcp/hosts.json")
        assert cfg.templates_file == Path("/opt/ssh-mcp/templates.json")
        assert cfg.audit_log_dir == Path("/opt/ssh-mcp/audit_logs")
        assert cfg.cert_data_dir == Path("/opt/ssh-mcp/cert_data")
        assert cfg.approval_data_dir == Path("/opt/ssh-mcp/approval_data")

    def test_explicit_path_overrides_config_dir(self):
        cfg = ServerConfig(
            config_dir=Path("/opt/ssh-mcp"),
            hosts_file=Path("/custom/hosts.json"),
        )
        assert cfg.hosts_file == Path("/custom/hosts.json")
        # Other paths still derive from config_dir
        assert cfg.templates_file == Path("/opt/ssh-mcp/templates.json")
