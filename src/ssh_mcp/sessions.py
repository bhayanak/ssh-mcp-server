"""SSH session manager — persistent connection pool with keepalive.

Provides reusable SSH sessions keyed by (host_id, user_id) to avoid
the overhead of connect/disconnect on every command.  Sessions have
configurable idle timeout and keepalive probes.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import paramiko

from .config import HostEntry, ServerConfig


@dataclass
class SSHSession:
    """A pooled SSH session."""

    session_id: str
    host_id: str
    user_id: str
    client: paramiko.SSHClient
    created_at: float = field(default_factory=time.monotonic)
    last_used_at: float = field(default_factory=time.monotonic)
    alive: bool = True

    def touch(self) -> None:
        """Update last-used timestamp."""
        self.last_used_at = time.monotonic()


class SessionManager:
    """Manage a pool of persistent SSH connections with keepalive."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self._sessions: dict[str, SSHSession] = {}
        self._lock = threading.Lock()
        self._max_sessions = getattr(config, "max_sessions", 10)
        self._idle_timeout = getattr(config, "session_idle_timeout", 300)  # 5 min
        self._keepalive_interval = getattr(config, "keepalive_interval", 15)
        self._keepalive_count_max = getattr(config, "keepalive_count_max", 3)

    def connect(
        self,
        host: HostEntry,
        user_id: str,
    ) -> SSHSession:
        """Open a new persistent SSH session to a host."""
        with self._lock:
            # Enforce max sessions
            active = [s for s in self._sessions.values() if s.alive]
            if len(active) >= self._max_sessions:
                raise ValueError(
                    f"Max sessions ({self._max_sessions}) reached. "
                    "Disconnect an existing session first."
                )

        client = paramiko.SSHClient()
        if self._config.ssh_known_hosts_file:
            client.load_host_keys(str(self._config.ssh_known_hosts_file))
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": host.hostname,
            "port": host.port,
            "timeout": self._config.ssh_timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if host.ssh_user:
            connect_kwargs["username"] = host.ssh_user

        client.connect(**connect_kwargs)

        # Configure keepalive on the transport
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(self._keepalive_interval)

        session_id = uuid.uuid4().hex[:12]
        session = SSHSession(
            session_id=session_id,
            host_id=host.host_id,
            user_id=user_id,
            client=client,
        )

        with self._lock:
            self._sessions[session_id] = session

        return session

    def disconnect(self, session_id: str, user_id: str) -> bool:
        """Close and remove a session. Returns True if found and closed."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Unknown session: {session_id}")
            if session.user_id != user_id:
                raise ValueError("Cannot disconnect another user's session")
            session.alive = False
            try:
                session.client.close()
            except Exception:
                pass
            del self._sessions[session_id]
            return True

    def get_session(self, session_id: str, user_id: str) -> SSHSession:
        """Get a session by ID, verifying ownership and liveness."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Unknown session: {session_id}")
            if session.user_id != user_id:
                raise ValueError("Cannot access another user's session")
            if not session.alive:
                raise ValueError(f"Session {session_id} is no longer alive")

            # Check if transport is still active
            transport = session.client.get_transport()
            if transport is None or not transport.is_active():
                session.alive = False
                del self._sessions[session_id]
                raise ValueError(f"Session {session_id} has been disconnected")

            session.touch()
            return session

    def ping(self, session_id: str, user_id: str) -> dict[str, Any]:
        """Health-check a session. Returns status info."""
        session = self.get_session(session_id, user_id)
        transport = session.client.get_transport()
        is_active = transport is not None and transport.is_active()
        idle_seconds = round(time.monotonic() - session.last_used_at, 1)
        uptime_seconds = round(time.monotonic() - session.created_at, 1)

        return {
            "session_id": session.session_id,
            "host_id": session.host_id,
            "alive": is_active,
            "idle_seconds": idle_seconds,
            "uptime_seconds": uptime_seconds,
        }

    def list_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """List all sessions for a user."""
        with self._lock:
            result = []
            for s in self._sessions.values():
                if s.user_id != user_id:
                    continue
                transport = s.client.get_transport()
                is_active = transport is not None and transport.is_active()
                result.append({
                    "session_id": s.session_id,
                    "host_id": s.host_id,
                    "alive": is_active,
                    "idle_seconds": round(time.monotonic() - s.last_used_at, 1),
                    "uptime_seconds": round(time.monotonic() - s.created_at, 1),
                })
            return result

    def cleanup_idle(self) -> int:
        """Close sessions that have been idle beyond the timeout. Returns count closed."""
        now = time.monotonic()
        to_remove = []
        with self._lock:
            for sid, session in self._sessions.items():
                if now - session.last_used_at > self._idle_timeout:
                    to_remove.append(sid)
            for sid in to_remove:
                session = self._sessions.pop(sid)
                session.alive = False
                try:
                    session.client.close()
                except Exception:
                    pass
        return len(to_remove)

    def close_all(self) -> None:
        """Close all sessions (for shutdown)."""
        with self._lock:
            for session in self._sessions.values():
                session.alive = False
                try:
                    session.client.close()
                except Exception:
                    pass
            self._sessions.clear()

    @property
    def active_count(self) -> int:
        """Number of currently alive sessions."""
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.alive)

    @property
    def max_sessions(self) -> int:
        """Configured maximum sessions."""
        return self._max_sessions
