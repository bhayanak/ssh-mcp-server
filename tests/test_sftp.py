"""Tests for enhanced SFTP operations and guardrails updates."""

import pytest

from ssh_mcp.guardrails import (
    RiskLevel,
    build_risk_summary,
    require_confirmation,
    require_approval,
    wrap_response,
)


class TestNewToolGuardrails:
    """Test that new tools have correct risk levels and guardrails."""

    def test_session_tools_are_low_risk(self):
        for tool in ("ssh_connect", "ssh_disconnect", "ssh_list_sessions", "ssh_session_ping"):
            summary = build_risk_summary(tool)
            assert summary.risk_level == RiskLevel.LOW, f"{tool} should be low risk"

    def test_background_read_tools_are_low_risk(self):
        for tool in ("poll_background_job", "list_background_jobs"):
            summary = build_risk_summary(tool)
            assert summary.risk_level == RiskLevel.LOW, f"{tool} should be low risk"

    def test_background_mutate_tools_are_medium(self):
        for tool in ("run_ssh_command_background", "cancel_background_job"):
            summary = build_risk_summary(tool)
            assert summary.risk_level == RiskLevel.MEDIUM, f"{tool} should be medium risk"

    def test_sftp_list_is_low_risk(self):
        summary = build_risk_summary("sftp_list_directory")
        assert summary.risk_level == RiskLevel.LOW

    def test_sftp_delete_is_medium_risk(self):
        summary = build_risk_summary("sftp_delete")
        assert summary.risk_level == RiskLevel.MEDIUM

    def test_sftp_delete_requires_confirmation(self):
        assert require_confirmation("sftp_delete") is True

    def test_background_run_requires_confirmation(self):
        assert require_confirmation("run_ssh_command_background") is True

    def test_cancel_requires_confirmation(self):
        assert require_confirmation("cancel_background_job") is True

    def test_session_tools_no_confirmation(self):
        for tool in ("ssh_connect", "ssh_disconnect", "ssh_list_sessions", "ssh_session_ping"):
            assert require_confirmation(tool) is False

    def test_read_tools_no_confirmation(self):
        for tool in ("poll_background_job", "list_background_jobs", "sftp_list_directory"):
            assert require_confirmation(tool) is False

    def test_new_tools_no_approval_required(self):
        """None of the new tools require the approval workflow."""
        for tool in (
            "ssh_connect", "ssh_disconnect", "ssh_list_sessions", "ssh_session_ping",
            "run_ssh_command_background", "poll_background_job",
            "list_background_jobs", "cancel_background_job",
            "sftp_list_directory", "sftp_delete",
        ):
            assert require_approval(tool) is False

    def test_wrap_response_includes_new_tool_meta(self):
        resp = wrap_response("sftp_list_directory", {"entries": []})
        assert resp["_meta"]["tool"] == "sftp_list_directory"
        assert resp["_meta"]["risk_level"] == "low"

        resp2 = wrap_response("run_ssh_command_background", {"job_id": "abc"})
        assert resp2["_meta"]["risk_level"] == "medium"
        assert resp2["_meta"]["confirmation_required"] is True


class TestNewConfigFields:
    """Test that new config fields have correct defaults."""

    def test_session_config_defaults(self):
        from ssh_mcp.config import ServerConfig
        config = ServerConfig(config_dir="/tmp/test-ssh-mcp-sftp")
        assert config.max_sessions == 10
        assert config.session_idle_timeout == 300
        assert config.keepalive_interval == 15
        assert config.keepalive_count_max == 3

    def test_job_config_defaults(self):
        from ssh_mcp.config import ServerConfig
        config = ServerConfig(config_dir="/tmp/test-ssh-mcp-sftp")
        assert config.max_background_jobs == 10
        assert config.job_output_max_bytes == 1_048_576
        assert config.job_ttl_seconds == 3600
