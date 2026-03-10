"""Tests for background job manager."""

import time
from unittest.mock import MagicMock, patch

import pytest

from ssh_mcp.config import CommandTemplate, HostEntry, Role, ServerConfig
from ssh_mcp.jobs import BackgroundJobManager, JobStatus


@pytest.fixture
def config():
    return ServerConfig(
        config_dir="/tmp/test-ssh-mcp-jobs",
        max_background_jobs=3,
        job_output_max_bytes=1024,
        job_ttl_seconds=60,
    )


@pytest.fixture
def manager(config):
    return BackgroundJobManager(config)


@pytest.fixture
def test_host():
    return HostEntry(
        host_id="test-host",
        hostname="192.168.1.10",
        port=22,
        ssh_user="deploy",
    )


@pytest.fixture
def test_template():
    return CommandTemplate(
        template_id="disk_usage",
        description="Check disk usage",
        command="df -h",
        allowed_params={},
        allowed_roles=[Role.OPERATOR],
        timeout_seconds=10,
        risk_level="low",
    )


class TestBackgroundJobManager:
    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_start_job(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")

        assert job.job_id
        assert job.host_id == "test-host"
        assert job.user_id == "user1"
        assert job.template_id == "disk_usage"
        assert job.command == "df -h"

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_max_jobs_enforced(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        # Make jobs stay running (exit_status_ready never returns True quickly)
        mock_channel.exit_status_ready.return_value = False
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        for _ in range(3):
            manager.start_job(test_host, test_template, {}, "user1")

        with pytest.raises(ValueError, match="Max background jobs"):
            manager.start_job(test_host, test_template, {}, "user1")

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_poll_job(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")
        # Wait for thread to complete
        if job._thread:
            job._thread.join(timeout=2)

        result = manager.poll_job(job.job_id, "user1")

        assert result["job_id"] == job.job_id
        assert result["status"] in ("completed", "running", "failed")
        assert "stdout" in result
        assert "stderr" in result

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_poll_wrong_user_rejected(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")

        with pytest.raises(ValueError, match="Cannot access another user"):
            manager.poll_job(job.job_id, "user2")

    def test_poll_unknown_job(self, manager):
        with pytest.raises(ValueError, match="Unknown job"):
            manager.poll_job("nonexistent", "user1")

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_list_jobs(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        manager.start_job(test_host, test_template, {}, "user1")
        manager.start_job(test_host, test_template, {}, "user1")
        manager.start_job(test_host, test_template, {}, "user2")

        user1_jobs = manager.list_jobs("user1")
        user2_jobs = manager.list_jobs("user2")

        assert len(user1_jobs) == 2
        assert len(user2_jobs) == 1

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_cancel_job(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = False
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")
        result = manager.cancel_job(job.job_id, "user1")

        assert result["status"] == "cancelling"
        assert job._cancel_event.is_set()

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_cancel_wrong_user_rejected(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = False
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")

        with pytest.raises(ValueError, match="Cannot cancel another user"):
            manager.cancel_job(job.job_id, "user2")

    def test_cancel_unknown_job(self, manager):
        with pytest.raises(ValueError, match="Unknown job"):
            manager.cancel_job("nonexistent", "user1")

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_cancel_completed_job_rejected(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        job = manager.start_job(test_host, test_template, {}, "user1")
        if job._thread:
            job._thread.join(timeout=2)

        with pytest.raises(ValueError, match="not running"):
            manager.cancel_job(job.job_id, "user1")

    def test_output_buffer_limit(self, manager):
        """Test that output buffer respects max size."""
        from ssh_mcp.jobs import BackgroundJob
        job = BackgroundJob(
            job_id="test",
            host_id="test-host",
            user_id="user1",
            template_id="test",
            command="test",
        )
        # manager._output_max_bytes is 1024
        manager._append_output(job, "stdout", "x" * 2000)
        assert len(job.stdout_buffer) == 1024

    @patch("ssh_mcp.jobs.paramiko.SSHClient")
    def test_expired_jobs_cleaned_up(self, mock_ssh_class, manager, test_host, test_template):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_channel = MagicMock()
        mock_channel.exit_status_ready.return_value = True
        mock_channel.recv_ready.return_value = False
        mock_channel.recv_stderr_ready.return_value = False
        mock_channel.recv_exit_status.return_value = 0
        mock_transport.open_session.return_value = mock_channel
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        manager._job_ttl = 0.1  # Very short TTL for test

        job = manager.start_job(test_host, test_template, {}, "user1")
        if job._thread:
            job._thread.join(timeout=2)

        time.sleep(0.2)

        # list_jobs triggers cleanup
        jobs = manager.list_jobs("user1")
        assert len(jobs) == 0
