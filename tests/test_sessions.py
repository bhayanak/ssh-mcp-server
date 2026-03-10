"""Tests for SSH session management."""

import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ssh_mcp.config import HostEntry, Role, ServerConfig
from ssh_mcp.sessions import SessionManager, SSHSession


@pytest.fixture
def config():
    return ServerConfig(
        config_dir="/tmp/test-ssh-mcp-sessions",
        max_sessions=3,
        session_idle_timeout=5,
        keepalive_interval=15,
        keepalive_count_max=3,
    )


@pytest.fixture
def manager(config):
    mgr = SessionManager(config)
    yield mgr
    mgr.close_all()


@pytest.fixture
def test_host():
    return HostEntry(
        host_id="test-host",
        hostname="192.168.1.10",
        port=22,
        ssh_user="deploy",
    )


class TestSessionManager:
    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_connect_creates_session(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")

        assert session.session_id
        assert session.host_id == "test-host"
        assert session.user_id == "user1"
        assert session.alive
        assert manager.active_count == 1
        mock_client.connect.assert_called_once()
        mock_transport.set_keepalive.assert_called_once_with(15)

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_max_sessions_enforced(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        # Fill up sessions
        for _ in range(3):
            manager.connect(test_host, "user1")

        with pytest.raises(ValueError, match="Max sessions"):
            manager.connect(test_host, "user1")

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_disconnect(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")
        assert manager.active_count == 1

        manager.disconnect(session.session_id, "user1")
        assert manager.active_count == 0
        mock_client.close.assert_called()

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_disconnect_wrong_user_rejected(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")

        with pytest.raises(ValueError, match="Cannot disconnect another user"):
            manager.disconnect(session.session_id, "user2")

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_disconnect_unknown_session(self, mock_ssh_class, manager, test_host):
        with pytest.raises(ValueError, match="Unknown session"):
            manager.disconnect("nonexistent", "user1")

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_get_session(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")
        retrieved = manager.get_session(session.session_id, "user1")

        assert retrieved.session_id == session.session_id

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_get_session_wrong_user(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")

        with pytest.raises(ValueError, match="Cannot access another user"):
            manager.get_session(session.session_id, "user2")

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_get_session_detects_dead_transport(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")

        # Simulate transport dying
        mock_transport.is_active.return_value = False

        with pytest.raises(ValueError, match="has been disconnected"):
            manager.get_session(session.session_id, "user1")

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_ping(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        session = manager.connect(test_host, "user1")
        info = manager.ping(session.session_id, "user1")

        assert info["session_id"] == session.session_id
        assert info["host_id"] == "test-host"
        assert info["alive"] is True
        assert "idle_seconds" in info
        assert "uptime_seconds" in info

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_list_sessions(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        manager.connect(test_host, "user1")
        manager.connect(test_host, "user1")
        manager.connect(test_host, "user2")

        user1_sessions = manager.list_sessions("user1")
        user2_sessions = manager.list_sessions("user2")

        assert len(user1_sessions) == 2
        assert len(user2_sessions) == 1

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_cleanup_idle(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        # Set very short idle timeout for test
        manager._idle_timeout = 0.1

        manager.connect(test_host, "user1")
        time.sleep(0.2)

        closed = manager.cleanup_idle()
        assert closed == 1
        assert manager.active_count == 0

    @patch("ssh_mcp.sessions.paramiko.SSHClient")
    def test_close_all(self, mock_ssh_class, manager, test_host):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_class.return_value = mock_client

        manager.connect(test_host, "user1")
        manager.connect(test_host, "user1")

        manager.close_all()
        assert manager.active_count == 0
