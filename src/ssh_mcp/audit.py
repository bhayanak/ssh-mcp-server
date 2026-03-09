"""Tamper-evident audit logging.

Events are JSON lines, each with a SHA-256 chain hash linking to the
previous entry — providing basic tamper evidence without external infra.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64


class AuditLogger:
    """Append-only, hash-chained audit event writer."""

    def __init__(self, log_dir: Path) -> None:
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "audit.jsonl"
        self._prev_hash = self._load_last_hash()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_event(
        self,
        action: str,
        user_id: str,
        *,
        tool: str = "",
        host_id: str = "",
        detail: dict[str, Any] | None = None,
        status: str = "ok",
    ) -> str:
        """Append a signed audit event and return its audit_id."""
        audit_id = uuid.uuid4().hex
        event = {
            "audit_id": audit_id,
            "timestamp": time.time(),
            "action": action,
            "user_id": user_id,
            "tool": tool,
            "host_id": host_id,
            "status": status,
            "detail": detail or {},
            "prev_hash": self._prev_hash,
        }
        event["hash"] = self._hash_event(event)
        self._prev_hash = event["hash"]

        with open(self._log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")

        return audit_id

    def read_events(self, last_n: int = 50) -> list[dict[str, Any]]:
        """Return the last N audit events."""
        if not self._log_file.exists():
            return []
        lines = self._log_file.read_text(encoding="utf-8").strip().splitlines()
        return [json.loads(line) for line in lines[-last_n:]]

    def verify_chain(self) -> tuple[bool, str]:
        """Walk the log and verify hash chain integrity."""
        if not self._log_file.exists():
            return True, "No events"
        lines = self._log_file.read_text(encoding="utf-8").strip().splitlines()
        expected_prev = _GENESIS_HASH
        for i, line in enumerate(lines):
            event = json.loads(line)
            if event["prev_hash"] != expected_prev:
                return False, f"Chain broken at event index {i}"
            recorded_hash = event.pop("hash")
            if self._hash_event(event) != recorded_hash:
                return False, f"Hash mismatch at event index {i}"
            event["hash"] = recorded_hash
            expected_prev = recorded_hash
        return True, "OK"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_last_hash(self) -> str:
        if not self._log_file.exists():
            return _GENESIS_HASH
        lines = self._log_file.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return _GENESIS_HASH
        last = json.loads(lines[-1])
        return last.get("hash", _GENESIS_HASH)

    @staticmethod
    def _hash_event(event: dict[str, Any]) -> str:
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
