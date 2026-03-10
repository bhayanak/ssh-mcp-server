"""Risk assessment and confirmation tracking for VS Code UX.

Phase 4 deliverables:
- Risk level metadata attached to every tool response
- Confirmation prompts for mutating operations
- Local policy hooks for user-side blocking
- Approval evidence linked in audit trail

Every tool response passes through `wrap_response()` which adds a
standard risk envelope.  Mutating tools check `require_confirmation()`
before proceeding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Security risk level for tool operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Tool -> risk mapping (static baseline; can be overridden by config)
_TOOL_RISK: dict[str, RiskLevel] = {
    # Tier 0
    "list_hosts": RiskLevel.LOW,
    "get_host_facts": RiskLevel.LOW,
    "get_audit_logs": RiskLevel.LOW,
    "list_templates": RiskLevel.LOW,
    "ssh_connect": RiskLevel.LOW,
    "ssh_disconnect": RiskLevel.LOW,
    "ssh_list_sessions": RiskLevel.LOW,
    "ssh_session_ping": RiskLevel.LOW,
    "poll_background_job": RiskLevel.LOW,
    "list_background_jobs": RiskLevel.LOW,
    "sftp_list_directory": RiskLevel.LOW,
    # Tier 1
    "run_ssh_command": RiskLevel.MEDIUM,
    "transfer_file": RiskLevel.MEDIUM,
    "run_ssh_command_background": RiskLevel.MEDIUM,
    "cancel_background_job": RiskLevel.MEDIUM,
    "sftp_delete": RiskLevel.MEDIUM,
    # Tier 2
    "add_ssh_key": RiskLevel.HIGH,
    "remove_ssh_key": RiskLevel.HIGH,
    "issue_cert": RiskLevel.HIGH,
    "revoke_cert": RiskLevel.HIGH,
    "request_approval": RiskLevel.LOW,
    "approve_request": RiskLevel.HIGH,
    "list_pending_approvals": RiskLevel.LOW,
}

# Which tools require explicit confirmation before execution
_CONFIRMATION_REQUIRED: set[str] = {
    "run_ssh_command",
    "transfer_file",
    "run_ssh_command_background",
    "cancel_background_job",
    "sftp_delete",
    "add_ssh_key",
    "remove_ssh_key",
    "issue_cert",
    "revoke_cert",
    "approve_request",
}

# Which tools require a prior approval request_id
_APPROVAL_REQUIRED: set[str] = {
    "add_ssh_key",
    "remove_ssh_key",
    "issue_cert",
    "revoke_cert",
}


# ---------------------------------------------------------------------------
# Risk summary builder
# ---------------------------------------------------------------------------


@dataclass
class RiskSummary:
    """Human-readable risk summary shown to the user before execution."""

    tool: str
    risk_level: RiskLevel
    target_host: str
    description: str
    requires_confirmation: bool
    requires_approval: bool
    approval_request_id: str = ""


def build_risk_summary(
    tool: str,
    host_id: str = "",
    description: str = "",
    approval_request_id: str = "",
) -> RiskSummary:
    """Build a risk summary for a tool invocation."""
    risk = _TOOL_RISK.get(tool, RiskLevel.MEDIUM)
    return RiskSummary(
        tool=tool,
        risk_level=risk,
        target_host=host_id,
        description=description or f"Execute {tool}",
        requires_confirmation=tool in _CONFIRMATION_REQUIRED,
        requires_approval=tool in _APPROVAL_REQUIRED,
        approval_request_id=approval_request_id,
    )


# ---------------------------------------------------------------------------
# Response envelope
# ---------------------------------------------------------------------------


def wrap_response(
    tool: str,
    data: dict[str, Any],
    host_id: str = "",
    approval_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wrap a tool result in a standard risk-annotated envelope.

    The envelope adds:
    - _meta.risk_level: for VS Code to render as colour/badge
    - _meta.confirmation_required: whether user was prompted
    - _meta.approval: approval evidence if applicable
    """
    risk = _TOOL_RISK.get(tool, RiskLevel.MEDIUM)
    meta: dict[str, Any] = {
        "tool": tool,
        "risk_level": risk.value,
        "confirmation_required": tool in _CONFIRMATION_REQUIRED,
        "approval_required": tool in _APPROVAL_REQUIRED,
    }
    if approval_info:
        meta["approval"] = approval_info
    if host_id:
        meta["host_id"] = host_id

    return {**data, "_meta": meta}


# ---------------------------------------------------------------------------
# Policy hooks
# ---------------------------------------------------------------------------


class PolicyViolation(Exception):
    """Raised when a local policy hook blocks an operation."""


def check_local_policy(
    tool: str,
    user_id: str,
    host_id: str = "",
    params: dict[str, Any] | None = None,
    blocked_tools: set[str] | None = None,
    blocked_hosts: set[str] | None = None,
) -> None:
    """Run local policy hooks before tool execution.

    These are user-side guardrails that can block operations before
    they even reach the server's auth layer.

    Raises PolicyViolation if blocked.
    """
    if blocked_tools and tool in blocked_tools:
        raise PolicyViolation(f"Tool '{tool}' is blocked by local policy")

    if blocked_hosts and host_id in blocked_hosts:
        raise PolicyViolation(
            f"Host '{host_id}' is blocked by local policy"
        )


def require_confirmation(tool: str) -> bool:
    """Return True if the tool requires explicit user confirmation."""
    return tool in _CONFIRMATION_REQUIRED


def require_approval(tool: str) -> bool:
    """Return True if the tool requires a prior approval request."""
    return tool in _APPROVAL_REQUIRED


def get_risk_level(tool: str) -> RiskLevel:
    """Return the risk level for a tool."""
    return _TOOL_RISK.get(tool, RiskLevel.MEDIUM)
