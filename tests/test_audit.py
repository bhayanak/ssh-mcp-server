"""Tests for audit logging and chain integrity."""

import json
import tempfile
from pathlib import Path

import pytest
from ssh_mcp.audit import AuditLogger


@pytest.fixture
def audit_dir(tmp_path):
    return tmp_path / "audit"


class TestAuditLogger:
    def test_log_and_read(self, audit_dir):
        logger = AuditLogger(audit_dir)
        aid = logger.log_event("test_action", "user1", tool="test_tool")
        events = logger.read_events()
        assert len(events) == 1
        assert events[0]["audit_id"] == aid
        assert events[0]["action"] == "test_action"

    def test_chain_integrity(self, audit_dir):
        logger = AuditLogger(audit_dir)
        logger.log_event("a1", "u1")
        logger.log_event("a2", "u2")
        logger.log_event("a3", "u3")
        ok, msg = logger.verify_chain()
        assert ok, msg

    def test_tamper_detection(self, audit_dir):
        logger = AuditLogger(audit_dir)
        logger.log_event("a1", "u1")
        logger.log_event("a2", "u2")

        # Tamper with the log
        log_file = audit_dir / "audit.jsonl"
        lines = log_file.read_text().splitlines()
        event = json.loads(lines[0])
        event["action"] = "TAMPERED"
        lines[0] = json.dumps(event, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n")

        ok, msg = logger.verify_chain()
        assert not ok
        assert "mismatch" in msg.lower() or "broken" in msg.lower()

    def test_read_last_n(self, audit_dir):
        logger = AuditLogger(audit_dir)
        for i in range(10):
            logger.log_event(f"action_{i}", "u1")
        events = logger.read_events(last_n=3)
        assert len(events) == 3
        assert events[0]["action"] == "action_7"

    def test_empty_log(self, audit_dir):
        logger = AuditLogger(audit_dir)
        events = logger.read_events()
        assert events == []
        ok, msg = logger.verify_chain()
        assert ok

    def test_resume_chain_across_instances(self, audit_dir):
        logger1 = AuditLogger(audit_dir)
        logger1.log_event("first", "u1")

        # New instance should pick up the chain
        logger2 = AuditLogger(audit_dir)
        logger2.log_event("second", "u2")

        ok, msg = logger2.verify_chain()
        assert ok, msg
