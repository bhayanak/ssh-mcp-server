"""Background job manager — run template commands asynchronously.

Allows long-running template commands to execute in background threads.
Output is captured in a ring buffer and can be polled by the caller.
Jobs auto-expire after a configurable TTL.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import paramiko

from .config import CommandTemplate, HostEntry, ServerConfig
from .redact import redact


class JobStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class BackgroundJob:
    """A background command execution."""

    job_id: str
    host_id: str
    user_id: str
    template_id: str
    command: str
    status: JobStatus = JobStatus.RUNNING
    exit_code: int | None = None
    stdout_buffer: str = ""
    stderr_buffer: str = ""
    created_at: float = field(default_factory=time.monotonic)
    completed_at: float | None = None
    _poll_offset: int = 0  # Track how much stdout has been read
    _cancel_event: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None


class BackgroundJobManager:
    """Manage background SSH command executions."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self._jobs: dict[str, BackgroundJob] = {}
        self._lock = threading.Lock()
        self._max_jobs = getattr(config, "max_background_jobs", 10)
        self._output_max_bytes = getattr(config, "job_output_max_bytes", 1_048_576)
        self._job_ttl = getattr(config, "job_ttl_seconds", 3600)

    def start_job(
        self,
        host: HostEntry,
        template: CommandTemplate,
        params: dict[str, str],
        user_id: str,
    ) -> BackgroundJob:
        """Start a template command in a background thread."""
        with self._lock:
            # Cleanup expired jobs first
            self._cleanup_expired()

            active = sum(
                1 for j in self._jobs.values() if j.status == JobStatus.RUNNING
            )
            if active >= self._max_jobs:
                raise ValueError(
                    f"Max background jobs ({self._max_jobs}) reached. "
                    "Cancel or wait for existing jobs to complete."
                )

        resolved_cmd = template.render(params)
        job_id = uuid.uuid4().hex[:12]
        job = BackgroundJob(
            job_id=job_id,
            host_id=host.host_id,
            user_id=user_id,
            template_id=template.template_id,
            command=resolved_cmd,
        )

        thread = threading.Thread(
            target=self._execute,
            args=(job, host),
            daemon=True,
            name=f"bg-job-{job_id}",
        )
        job._thread = thread

        with self._lock:
            self._jobs[job_id] = job

        thread.start()
        return job

    def _execute(self, job: BackgroundJob, host: HostEntry) -> None:
        """Execute the command in a background thread."""
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

        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(15)

            channel = client.get_transport().open_session()
            channel.exec_command(job.command)

            # Stream output while command runs
            while not channel.exit_status_ready():
                if job._cancel_event.is_set():
                    channel.close()
                    job.status = JobStatus.CANCELLED
                    job.completed_at = time.monotonic()
                    return

                # Read available data
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="replace")
                    self._append_output(job, "stdout", chunk)
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                    self._append_output(job, "stderr", chunk)

                time.sleep(0.1)

            # Read remaining data
            while channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                self._append_output(job, "stdout", chunk)
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                self._append_output(job, "stderr", chunk)

            job.exit_code = channel.recv_exit_status()
            job.status = JobStatus.COMPLETED
            job.completed_at = time.monotonic()

        except Exception as exc:
            job.stderr_buffer += f"\n[Error: {redact(str(exc))}]"
            job.status = JobStatus.FAILED
            job.exit_code = -1
            job.completed_at = time.monotonic()
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _append_output(self, job: BackgroundJob, stream: str, data: str) -> None:
        """Append data to job output buffer, respecting size limit."""
        if stream == "stdout":
            if len(job.stdout_buffer) < self._output_max_bytes:
                remaining = self._output_max_bytes - len(job.stdout_buffer)
                job.stdout_buffer += data[:remaining]
        else:
            if len(job.stderr_buffer) < self._output_max_bytes:
                remaining = self._output_max_bytes - len(job.stderr_buffer)
                job.stderr_buffer += data[:remaining]

    def poll_job(self, job_id: str, user_id: str) -> dict[str, Any]:
        """Read accumulated output of a background job (redacted)."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Unknown job: {job_id}")
            if job.user_id != user_id:
                raise ValueError("Cannot access another user's job")

            # Return new output since last poll
            new_stdout = redact(job.stdout_buffer[job._poll_offset:])
            job._poll_offset = len(job.stdout_buffer)

            return {
                "job_id": job.job_id,
                "host_id": job.host_id,
                "template_id": job.template_id,
                "status": job.status.value,
                "exit_code": job.exit_code,
                "stdout": new_stdout,
                "stderr": redact(job.stderr_buffer),
                "running_seconds": round(
                    (job.completed_at or time.monotonic()) - job.created_at, 1
                ),
            }

    def list_jobs(self, user_id: str) -> list[dict[str, Any]]:
        """List all jobs for a user."""
        with self._lock:
            self._cleanup_expired()
            result = []
            for job in self._jobs.values():
                if job.user_id != user_id:
                    continue
                result.append({
                    "job_id": job.job_id,
                    "host_id": job.host_id,
                    "template_id": job.template_id,
                    "status": job.status.value,
                    "exit_code": job.exit_code,
                    "running_seconds": round(
                        (job.completed_at or time.monotonic()) - job.created_at, 1
                    ),
                })
            return result

    def cancel_job(self, job_id: str, user_id: str) -> dict[str, Any]:
        """Cancel a running background job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Unknown job: {job_id}")
            if job.user_id != user_id:
                raise ValueError("Cannot cancel another user's job")
            if job.status != JobStatus.RUNNING:
                raise ValueError(f"Job {job_id} is not running (status: {job.status.value})")

            job._cancel_event.set()
            return {
                "job_id": job.job_id,
                "status": "cancelling",
            }

    def _cleanup_expired(self) -> None:
        """Remove completed/failed jobs older than TTL. Must hold lock."""
        now = time.monotonic()
        to_remove = []
        for jid, job in self._jobs.items():
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                if job.completed_at and (now - job.completed_at > self._job_ttl):
                    to_remove.append(jid)
        for jid in to_remove:
            del self._jobs[jid]
