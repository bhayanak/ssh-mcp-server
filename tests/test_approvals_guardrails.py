"""Tests for the approval workflow (Phase 3) and guardrails (Phase 4)."""

from __future__ import annotations

import time

import pytest

from ssh_mcp.approvals import ApprovalManager, ApprovalMode, ApprovalStatus
from ssh_mcp.guardrails import (
    PolicyViolation,
    RiskLevel,
    build_risk_summary,
    check_local_policy,
    get_risk_level,
    require_approval,
    require_confirmation,
    wrap_response,
)


# ==================================================================
# Approval Manager tests
# ==================================================================


@pytest.fixture()
def approvals(tmp_path):
    return ApprovalManager(tmp_path / "approvals", require_two_party=True)


@pytest.fixture()
def self_approvals(tmp_path):
    return ApprovalManager(tmp_path / "approvals", require_two_party=False)


class TestApprovalCreation:
    def test_create_request(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="Need key for deployment",
            ticket_ref="JIRA-123",
        )
        assert req.request_id
        assert req.action == "add_ssh_key"
        assert req.requester_id == "alice"
        assert req.status == ApprovalStatus.PENDING
        assert req.mode == ApprovalMode.TWO_PARTY
        assert req.approval_token  # token is returned on creation

    def test_create_self_justify_mode(self, self_approvals):
        req = self_approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        assert req.mode == ApprovalMode.SELF_JUSTIFY

    def test_create_requires_justification(self, approvals):
        with pytest.raises(ValueError, match="Justification is required"):
            approvals.create_request(
                action="add_ssh_key",
                requester_id="alice",
                justification="",
            )

    def test_create_with_custom_ttl(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
            ttl_seconds=120,
        )
        assert req.expires_at - req.created_at == pytest.approx(120, abs=2)


class TestApprovalFlow:
    def test_approve_two_party(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="deployment",
        )
        approved = approvals.approve(req.request_id, "bob", req.approval_token)
        assert approved.status == ApprovalStatus.APPROVED
        assert approved.approver_id == "bob"

    def test_two_party_rejects_self_approval(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        with pytest.raises(ValueError, match="different approver"):
            approvals.approve(req.request_id, "alice", req.approval_token)

    def test_self_justify_allows_self_approval(self, self_approvals):
        req = self_approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        approved = self_approvals.approve(req.request_id, "alice", req.approval_token)
        assert approved.status == ApprovalStatus.APPROVED

    def test_approve_with_wrong_token_fails(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        with pytest.raises(ValueError, match="Invalid approval token"):
            approvals.approve(req.request_id, "bob", "wrong-token")

    def test_deny_request(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        denied = approvals.deny(req.request_id, "bob", req.approval_token)
        assert denied.status == ApprovalStatus.DENIED

    def test_cannot_approve_denied_request(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        approvals.deny(req.request_id, "bob", req.approval_token)
        with pytest.raises(ValueError, match="not pending"):
            approvals.approve(req.request_id, "charlie", req.approval_token)


class TestApprovalExpiry:
    def test_expired_request_cannot_be_approved(self, tmp_path):
        mgr = ApprovalManager(tmp_path / "approvals", require_two_party=True)
        req = mgr.create_request(
            action="test",
            requester_id="alice",
            justification="test",
            ttl_seconds=1,
        )
        # Manually expire
        mgr._requests[req.request_id]["expires_at"] = time.time() - 10
        with pytest.raises(ValueError, match="expired"):
            mgr.approve(req.request_id, "bob", req.approval_token)

    def test_verify_catches_expired(self, tmp_path):
        mgr = ApprovalManager(tmp_path / "approvals", require_two_party=False)
        req = mgr.create_request(
            action="test",
            requester_id="alice",
            justification="test",
        )
        mgr.approve(req.request_id, "alice", req.approval_token)
        # Expire the approved request
        mgr._requests[req.request_id]["expires_at"] = time.time() - 10
        with pytest.raises(ValueError, match="expired"):
            mgr.verify_approval(req.request_id, "test")


class TestApprovalConsume:
    def test_consume_marks_as_used(self, self_approvals):
        req = self_approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        self_approvals.approve(req.request_id, "alice", req.approval_token)
        self_approvals.consume(req.request_id)
        # Cannot verify a consumed request
        with pytest.raises(ValueError, match="not valid"):
            self_approvals.verify_approval(req.request_id, "add_ssh_key")

    def test_consume_non_approved_fails(self, approvals):
        req = approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        with pytest.raises(ValueError, match="not approved"):
            approvals.consume(req.request_id)


class TestApprovalVerification:
    def test_verify_valid_approval(self, self_approvals):
        req = self_approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        self_approvals.approve(req.request_id, "alice", req.approval_token)
        info = self_approvals.verify_approval(req.request_id, "add_ssh_key")
        assert info["request_id"] == req.request_id
        assert info["requester_id"] == "alice"

    def test_verify_action_mismatch_fails(self, self_approvals):
        req = self_approvals.create_request(
            action="add_ssh_key",
            requester_id="alice",
            justification="test",
        )
        self_approvals.approve(req.request_id, "alice", req.approval_token)
        with pytest.raises(ValueError, match="action mismatch"):
            self_approvals.verify_approval(req.request_id, "remove_ssh_key")

    def test_verify_unknown_request_fails(self, self_approvals):
        with pytest.raises(ValueError, match="Unknown"):
            self_approvals.verify_approval("nonexistent", "add_ssh_key")


class TestApprovalListing:
    def test_list_pending(self, approvals):
        approvals.create_request("a1", "alice", "j1")
        approvals.create_request("a2", "bob", "j2")
        pending = approvals.list_pending()
        assert len(pending) == 2

    def test_list_pending_filters_by_requester(self, approvals):
        approvals.create_request("a1", "alice", "j1")
        approvals.create_request("a2", "bob", "j2")
        assert len(approvals.list_pending(requester_id="alice")) == 1

    def test_list_pending_excludes_expired(self, tmp_path):
        mgr = ApprovalManager(tmp_path / "approvals", require_two_party=True)
        req = mgr.create_request("a1", "alice", "j1", ttl_seconds=1)
        mgr._requests[req.request_id]["expires_at"] = time.time() - 10
        assert len(mgr.list_pending()) == 0


class TestApprovalPersistence:
    def test_data_survives_reload(self, tmp_path):
        d = tmp_path / "approvals"
        mgr1 = ApprovalManager(d, require_two_party=False)
        req = mgr1.create_request("add_ssh_key", "alice", "justification")
        mgr1.approve(req.request_id, "alice", req.approval_token)

        mgr2 = ApprovalManager(d, require_two_party=False)
        info = mgr2.verify_approval(req.request_id, "add_ssh_key")
        assert info["requester_id"] == "alice"


# ==================================================================
# Guardrails tests (Phase 4)
# ==================================================================


class TestRiskLevel:
    def test_read_only_tools_are_low(self):
        assert get_risk_level("list_hosts") == RiskLevel.LOW
        assert get_risk_level("get_host_facts") == RiskLevel.LOW
        assert get_risk_level("get_audit_logs") == RiskLevel.LOW

    def test_mutating_tools_are_medium(self):
        assert get_risk_level("run_ssh_command") == RiskLevel.MEDIUM
        assert get_risk_level("transfer_file") == RiskLevel.MEDIUM

    def test_privileged_tools_are_high(self):
        assert get_risk_level("add_ssh_key") == RiskLevel.HIGH
        assert get_risk_level("remove_ssh_key") == RiskLevel.HIGH
        assert get_risk_level("issue_cert") == RiskLevel.HIGH
        assert get_risk_level("revoke_cert") == RiskLevel.HIGH

    def test_unknown_tool_defaults_medium(self):
        assert get_risk_level("unknown_tool") == RiskLevel.MEDIUM


class TestConfirmation:
    def test_mutating_tools_require_confirmation(self):
        assert require_confirmation("run_ssh_command")
        assert require_confirmation("transfer_file")
        assert require_confirmation("add_ssh_key")

    def test_read_only_tools_no_confirmation(self):
        assert not require_confirmation("list_hosts")
        assert not require_confirmation("get_host_facts")
        assert not require_confirmation("get_audit_logs")


class TestApprovalRequired:
    def test_tier2_requires_approval(self):
        assert require_approval("add_ssh_key")
        assert require_approval("remove_ssh_key")
        assert require_approval("issue_cert")
        assert require_approval("revoke_cert")

    def test_tier1_does_not_require_approval(self):
        assert not require_approval("run_ssh_command")
        assert not require_approval("transfer_file")

    def test_tier0_does_not_require_approval(self):
        assert not require_approval("list_hosts")


class TestRiskSummary:
    def test_build_summary(self):
        s = build_risk_summary("run_ssh_command", host_id="web-01")
        assert s.tool == "run_ssh_command"
        assert s.risk_level == RiskLevel.MEDIUM
        assert s.target_host == "web-01"
        assert s.requires_confirmation

    def test_build_summary_with_approval(self):
        s = build_risk_summary("add_ssh_key", approval_request_id="abc123")
        assert s.requires_approval
        assert s.approval_request_id == "abc123"


class TestWrapResponse:
    def test_adds_meta(self):
        result = wrap_response("list_hosts", {"hosts": []})
        assert "_meta" in result
        assert result["_meta"]["risk_level"] == "low"
        assert not result["_meta"]["confirmation_required"]

    def test_mutating_tool_meta(self):
        result = wrap_response("run_ssh_command", {"exit_code": 0}, host_id="web-01")
        assert result["_meta"]["confirmation_required"]
        assert result["_meta"]["host_id"] == "web-01"

    def test_approval_info_included(self):
        approval = {"requester_id": "alice", "approver_id": "bob"}
        result = wrap_response("add_ssh_key", {"status": "ok"}, approval_info=approval)
        assert result["_meta"]["approval"] == approval

    def test_original_data_preserved(self):
        data = {"exit_code": 0, "stdout": "ok"}
        result = wrap_response("run_ssh_command", data)
        assert result["exit_code"] == 0
        assert result["stdout"] == "ok"


class TestLocalPolicy:
    def test_blocked_tool(self):
        with pytest.raises(PolicyViolation, match="blocked by local policy"):
            check_local_policy(
                "run_ssh_command", "alice", blocked_tools={"run_ssh_command"}
            )

    def test_blocked_host(self):
        with pytest.raises(PolicyViolation, match="blocked by local policy"):
            check_local_policy(
                "run_ssh_command", "alice",
                host_id="prod-db",
                blocked_hosts={"prod-db"},
            )

    def test_allowed_passes(self):
        # Should not raise
        check_local_policy(
            "run_ssh_command", "alice",
            host_id="staging-01",
            blocked_tools={"transfer_file"},
            blocked_hosts={"prod-db"},
        )
