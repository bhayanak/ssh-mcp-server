"""SSH MCP Server — main entry point.

Registers all tools and starts the MCP server using stdio transport
for direct VS Code integration.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import stat as stat_mod
import struct
import uuid
from pathlib import Path
from typing import Any

import paramiko
from mcp.server.fastmcp import FastMCP

from .approvals import ApprovalManager
from .audit import AuditLogger
from .auth import AuthProvider
from .certs import CertManager
from .config import (
    CommandTemplate,
    HostEntry,
    Role,
    ServerConfig,
    UserIdentity,
)
from .executor import ExecResult, SSHExecutor
from .guardrails import (
    check_local_policy,
    require_approval,
    wrap_response,
)
from .jobs import BackgroundJobManager
from .redact import redact
from .sessions import SessionManager

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

_config = ServerConfig()
_auth = AuthProvider(_config)
_audit = AuditLogger(_config.audit_log_dir)
_executor = SSHExecutor(_config)
_certs = CertManager(
    _config.cert_data_dir,
    default_ttl=_config.key_policy.default_ttl_seconds,
    max_ttl=_config.key_policy.max_ttl_seconds,
)
_approvals = ApprovalManager(
    _config.approval_data_dir,
    require_two_party=_config.require_two_party_approval,
)
_sessions = SessionManager(_config)
_jobs = BackgroundJobManager(_config)

mcp = FastMCP(
    _config.server_name,
    instructions=(
        "SSH MCP Server — execute policy-scoped SSH operations on remote hosts. "
        "To run a command: first call list_templates to discover available command "
        "templates (e.g. disk_usage, service_status, list_processes), then call "
        "run_ssh_command with the matching template_id and host_id. "
        "Read-only templates like disk_usage and list_processes are safe to execute. "
        "High-risk templates (e.g. restart_service) require prior approval via "
        "request_approval. Commands are template-only; raw shell is not available. "
        "To download or upload files, use the transfer_file tool directly (not "
        "run_ssh_command) with host_id, direction ('download' or 'upload'), "
        "remote_path, and a justification for downloads."
    ),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_hosts() -> dict[str, HostEntry]:
    path = _config.hosts_file
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {h["host_id"]: HostEntry(**h) for h in data}


def _load_templates() -> dict[str, CommandTemplate]:
    path = _config.templates_file
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {t["template_id"]: CommandTemplate(**t) for t in data}


def _get_user() -> UserIdentity:
    """Resolve caller identity.

    In stdio mode the auth token comes from an env var set by the VS Code
    client.  When empty, dev-mode identity is returned by AuthProvider.
    """
    token = os.environ.get("SSH_MCP_AUTH_TOKEN", "")
    return _auth.authenticate(token)


def _require_host(host_id: str) -> HostEntry:
    hosts = _load_hosts()
    host = hosts.get(host_id)
    if host is None:
        raise ValueError(f"Unknown host_id: {host_id}")
    return host


def _require_template(template_id: str) -> CommandTemplate:
    templates = _load_templates()
    tpl = templates.get(template_id)
    if tpl is None:
        raise ValueError(f"Unknown command template: {template_id}")
    return tpl


def _result_dict(r: ExecResult, audit_id: str) -> dict[str, Any]:
    return {
        "exit_code": r.exit_code,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "duration_ms": r.duration_ms,
        "audit_id": audit_id,
    }


def _check_approval(
    tool: str,
    approval_request_id: str,
) -> dict[str, Any] | None:
    """If the tool requires approval, verify and consume the approval request.

    Returns approval metadata dict on success, or None if no approval needed.
    Raises ValueError if approval is required but invalid/missing.
    """
    if not require_approval(tool):
        return None
    if not approval_request_id:
        raise ValueError(
            f"Tool '{tool}' requires prior approval. "
            "Use request_approval first, then pass the approval_request_id."
        )
    info = _approvals.verify_approval(approval_request_id, tool)
    _approvals.consume(approval_request_id)
    return info


# ===================================================================
# TIER 0 — Read-only tools
# ===================================================================


@mcp.tool()
def list_hosts() -> dict[str, Any]:
    """List all allowed SSH hosts with metadata (labels, roles, description).

    No authentication required beyond basic identity.
    Risk level: low.
    """
    user = _get_user()
    hosts = _load_hosts()
    result = []
    for h in hosts.values():
        result.append(
            {
                "host_id": h.host_id,
                "hostname": h.hostname,
                "port": h.port,
                "labels": h.labels,
                "description": h.description,
            }
        )
    _audit.log_event("list_hosts", user.user_id, tool="list_hosts")
    return wrap_response("list_hosts", {"hosts": result})


@mcp.tool()
def get_host_facts(host_id: str) -> dict[str, Any]:
    """Get safe host metadata (OS, uptime, kernel) — no secrets.

    Risk level: low.
    """
    user = _get_user()
    host = _require_host(host_id)
    _auth.authorize_host(user, host)

    # Build an ephemeral template for the facts command
    facts_tpl = CommandTemplate(
        template_id="_host_facts",
        description="Gather host facts",
        command=SSHExecutor.get_host_facts_cmd(),
        allowed_roles=[Role.DEVELOPER, Role.OPERATOR, Role.ADMIN],
        timeout_seconds=15,
        risk_level="low",
    )
    result = _executor.run_command(host, facts_tpl, {})
    audit_id = _audit.log_event(
        "get_host_facts",
        user.user_id,
        tool="get_host_facts",
        host_id=host_id,
        detail={"exit_code": result.exit_code},
    )
    return wrap_response("get_host_facts", _result_dict(result, audit_id), host_id=host_id)


@mcp.tool()
def list_templates() -> dict[str, Any]:
    """List all available command templates that can be used with run_ssh_command.

    Each template defines a pre-approved command pattern with its allowed
    parameters, roles, and risk level.  Use the template_id when calling
    run_ssh_command.

    Risk level: low.
    """
    user = _get_user()
    templates = _load_templates()
    result = []
    for tpl in templates.values():
        result.append(
            {
                "template_id": tpl.template_id,
                "description": tpl.description,
                "command": tpl.command,
                "allowed_params": tpl.allowed_params,
                "allowed_roles": [r.value if hasattr(r, 'value') else r for r in tpl.allowed_roles],
                "risk_level": tpl.risk_level,
            }
        )
    _audit.log_event("list_templates", user.user_id, tool="list_templates")
    return wrap_response("list_templates", {"templates": result})


@mcp.tool()
def get_audit_logs(last_n: int = 50) -> dict[str, Any]:
    """Return the last N audit log entries. Read-only.

    Risk level: low.
    """
    user = _get_user()
    _auth.check_roles(user, [Role.AUDITOR, Role.ADMIN])
    _audit.log_event("get_audit_logs", user.user_id, tool="get_audit_logs")
    events = _audit.read_events(last_n=min(last_n, 500))
    # Redact any accidental secrets in detail fields
    for ev in events:
        if "detail" in ev:
            for k, v in ev["detail"].items():
                if isinstance(v, str):
                    ev["detail"][k] = redact(v)
    return wrap_response("get_audit_logs", {"events": events})


# ===================================================================
# TIER 1 — Controlled mutation
# ===================================================================


@mcp.tool()
def run_ssh_command(
    host_id: str,
    template_id: str,
    params: dict[str, str] | None = None,
    session_id: str = "",
) -> dict[str, Any]:
    """Execute a pre-approved command template on a target host.

    Use list_templates to discover available template_ids.
    Examples:
      - disk_usage: run df -h (no params needed)
      - service_status: check a systemd service (params: {"service": "docker"})
      - list_processes: show top processes by memory (no params needed)
      - tail_log: tail a log file (params: {"lines": "100", "log_path": "/var/log/syslog"})

    Only commands from the template registry are allowed.
    Parameters are validated against per-template regex rules.
    Output is automatically redacted for secrets.

    Pass session_id from ssh_connect to reuse a persistent connection.

    Risk level: medium (requires user confirmation in VS Code).
    """
    user = _get_user()
    check_local_policy("run_ssh_command", user.user_id, host_id=host_id)

    host = _require_host(host_id)
    template = _require_template(template_id)

    _auth.authorize_host(user, host)
    _auth.authorize_command(user, template)

    params = params or {}

    if session_id:
        # Use persistent session
        session = _sessions.get_session(session_id, user.user_id)
        result = _executor.run_command_on_client(session.client, template, params)
    else:
        result = _executor.run_command(host, template, params)

    audit_id = _audit.log_event(
        "run_ssh_command",
        user.user_id,
        tool="run_ssh_command",
        host_id=host_id,
        detail={
            "template_id": template_id,
            "params": params,
            "exit_code": result.exit_code,
            "risk_level": template.risk_level,
            "confirmation_required": True,
        },
    )
    return wrap_response(
        "run_ssh_command", _result_dict(result, audit_id), host_id=host_id
    )


@mcp.tool()
def transfer_file(
    host_id: str,
    direction: str,
    remote_path: str,
    local_path: str = "",
    justification: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """Upload or download a file to/from a remote host.

    Enforces path policy, blocked extensions, and size limits.
    Downloads require a justification string.
    For uploads, provide local_path (the file to upload).

    Pass session_id from ssh_connect to reuse a persistent connection.

    Risk level: medium-high (requires user confirmation).
    """
    user = _get_user()
    check_local_policy("transfer_file", user.user_id, host_id=host_id)

    host = _require_host(host_id)
    _auth.authorize_host(user, host)
    _auth.check_roles(user, [Role.OPERATOR, Role.ADMIN])

    if direction not in ("upload", "download"):
        raise ValueError("direction must be 'upload' or 'download'")

    # Block path traversal
    if ".." in remote_path:
        raise ValueError("Path contains path traversal sequence")

    policy = _config.transfer_policy

    # Path policy
    if not any(fnmatch.fnmatch(remote_path, pat) for pat in policy.allowed_paths):
        raise ValueError(f"Path '{remote_path}' not in allowed paths")

    # Extension policy
    ext = Path(remote_path).suffix.lower()
    if ext in policy.blocked_extensions:
        raise ValueError(f"File extension '{ext}' is blocked by policy")

    # Download justification
    if direction == "download" and policy.require_justification_for_download:
        if not justification.strip():
            raise ValueError("Downloads require a non-empty justification")

    # Upload validation
    if direction == "upload":
        if not local_path.strip():
            raise ValueError("Upload requires a local_path parameter")
        local_file = Path(local_path)
        if ".." in str(local_file):
            raise ValueError("local_path contains path traversal sequence")
        if not local_file.exists():
            raise ValueError(f"Local file not found: {local_path}")
        if local_file.stat().st_size > policy.max_upload_bytes:
            fsize = local_file.stat().st_size
            raise ValueError(
                f"File size {fsize} exceeds upload limit {policy.max_upload_bytes}"
            )

    # Use session or ephemeral connection
    close_after = False
    if session_id:
        session_obj = _sessions.get_session(session_id, user.user_id)
        client = session_obj.client
    else:
        client = paramiko.SSHClient()
        if _config.ssh_known_hosts_file:
            client.load_host_keys(str(_config.ssh_known_hosts_file))
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": host.hostname,
            "port": host.port,
            "timeout": _config.ssh_timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if host.ssh_user:
            connect_kwargs["username"] = host.ssh_user
        client.connect(**connect_kwargs)
        close_after = True

    status = "ok"
    detail: dict[str, Any] = {
        "direction": direction,
        "remote_path": remote_path,
        "justification": justification,
    }
    try:
        sftp = client.open_sftp()
        if direction == "upload":
            sftp.put(local_path, remote_path)
            detail["local_path"] = local_path
            detail["size_bytes"] = Path(local_path).stat().st_size
        else:
            # Check remote file size before downloading
            file_stat = sftp.stat(remote_path)
            if file_stat.st_size and file_stat.st_size > policy.max_download_bytes:
                raise ValueError(
                    f"File size {file_stat.st_size} exceeds limit {policy.max_download_bytes}"
                )
            local_dest = Path("/tmp") / Path(remote_path).name
            sftp.get(remote_path, str(local_dest))
            detail["local_path"] = str(local_dest)
            detail["size_bytes"] = file_stat.st_size
        sftp.close()
    except Exception as exc:
        status = "error"
        detail["error"] = redact(str(exc))
    finally:
        if close_after:
            client.close()

    audit_id = _audit.log_event(
        "transfer_file",
        user.user_id,
        tool="transfer_file",
        host_id=host_id,
        status=status,
        detail=detail,
    )
    return wrap_response(
        "transfer_file",
        {"status": status, "detail": detail, "audit_id": audit_id},
        host_id=host_id,
    )


# ===================================================================
# TIER 2 — Privileged (key management)
# ===================================================================


@mcp.tool()
def add_ssh_key(
    user_name: str,
    public_key: str,
    ttl_seconds: int = 0,
    reason: str = "",
    approval_request_id: str = "",
) -> dict[str, Any]:
    """Register a new SSH public key with policy checks.

    Validates key format and strength.
    Enforces TTL limits from key policy.
    Requires ADMIN role and prior approval.

    Risk level: high (requires approval).
    """
    caller = _get_user()
    check_local_policy("add_ssh_key", caller.user_id)
    _auth.authorize_role(caller, Role.ADMIN)

    # Require approval for privileged operation
    approval_info = _check_approval("add_ssh_key", approval_request_id)

    kp = _config.key_policy
    effective_ttl = ttl_seconds if ttl_seconds > 0 else kp.default_ttl_seconds
    if effective_ttl > kp.max_ttl_seconds:
        raise ValueError(
            f"Requested TTL {effective_ttl}s exceeds max {kp.max_ttl_seconds}s"
        )

    # Validate key format
    if not public_key.strip().startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2")):
        raise ValueError("Unsupported or invalid public key format")

    parts = public_key.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid public key: expected 'type base64data [comment]'")

    # Check minimum key strength for RSA
    if parts[0] == "ssh-rsa":
        try:
            key_data = base64.b64decode(parts[1])
            # RSA key: read exponent length, exponent, then modulus length
            str_len = struct.unpack(">I", key_data[:4])[0]
            offset = 4 + str_len
            e_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4 + e_len
            n_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            key_bits = (n_len - 1) * 8  # approximate
            if key_bits < kp.min_key_bits:
                raise ValueError(
                    f"RSA key too weak: ~{key_bits} bits, minimum is {kp.min_key_bits}"
                )
        except (struct.error, base64.binascii.Error) as exc:
            raise ValueError(f"Could not parse RSA key: {exc}") from exc

    key_id = uuid.uuid4().hex[:12]

    audit_id = _audit.log_event(
        "add_ssh_key",
        caller.user_id,
        tool="add_ssh_key",
        detail={
            "target_user": user_name,
            "key_id": key_id,
            "ttl_seconds": effective_ttl,
            "reason": reason,
            "key_type": parts[0],
            "approval_request_id": approval_request_id,
        },
    )
    return wrap_response(
        "add_ssh_key",
        {
            "key_id": key_id,
            "ttl_seconds": effective_ttl,
            "status": "registered",
            "audit_id": audit_id,
        },
        approval_info=approval_info,
    )


@mcp.tool()
def remove_ssh_key(
    key_id: str,
    reason: str = "",
    approval_request_id: str = "",
) -> dict[str, Any]:
    """Revoke / remove an SSH key by its key_id.

    Requires ADMIN role and prior approval.
    Risk level: high.
    """
    caller = _get_user()
    check_local_policy("remove_ssh_key", caller.user_id)
    _auth.authorize_role(caller, Role.ADMIN)

    # Require approval for privileged operation
    approval_info = _check_approval("remove_ssh_key", approval_request_id)

    if not reason.strip():
        raise ValueError("Reason is required for key removal")

    audit_id = _audit.log_event(
        "remove_ssh_key",
        caller.user_id,
        tool="remove_ssh_key",
        detail={
            "key_id": key_id,
            "reason": reason,
            "approval_request_id": approval_request_id,
        },
    )
    return wrap_response(
        "remove_ssh_key",
        {"key_id": key_id, "status": "revoked", "audit_id": audit_id},
        approval_info=approval_info,
    )


# ===================================================================
# TIER 2 — Certificate lifecycle
# ===================================================================


@mcp.tool()
def issue_cert(
    user_id: str,
    principals: list[str] | None = None,
    ttl_seconds: int = 0,
    justification: str = "",
    approval_request_id: str = "",
) -> dict[str, Any]:
    """Issue a short-lived SSH certificate for a user.

    Certificates are signed by the local CA with a tight TTL.
    Requires ADMIN role and prior approval.

    Risk level: high.
    """
    caller = _get_user()
    check_local_policy("issue_cert", caller.user_id)
    _auth.authorize_role(caller, Role.ADMIN)

    approval_info = _check_approval("issue_cert", approval_request_id)

    if not justification.strip():
        raise ValueError("Justification is required for cert issuance")

    issued = _certs.issue_cert(
        user_id=user_id,
        principals=principals,
        ttl_seconds=ttl_seconds,
    )

    audit_id = _audit.log_event(
        "issue_cert",
        caller.user_id,
        tool="issue_cert",
        detail={
            "cert_id": issued.cert_id,
            "target_user": user_id,
            "ttl_seconds": issued.expires_at - issued.issued_at,
            "principals": issued.principals,
            "fingerprint": issued.fingerprint,
            "justification": justification,
            "approval_request_id": approval_request_id,
        },
    )
    return wrap_response(
        "issue_cert",
        {
            "cert_id": issued.cert_id,
            "fingerprint": issued.fingerprint,
            "issued_at": issued.issued_at,
            "expires_at": issued.expires_at,
            "principals": issued.principals,
            "audit_id": audit_id,
        },
        approval_info=approval_info,
    )


@mcp.tool()
def revoke_cert(
    cert_id: str,
    reason: str = "",
    approval_request_id: str = "",
) -> dict[str, Any]:
    """Revoke an issued SSH certificate.

    Revoked certificates are added to the revocation list and
    their PEM files are deleted.
    Requires ADMIN role and prior approval.

    Risk level: high.
    """
    caller = _get_user()
    check_local_policy("revoke_cert", caller.user_id)
    _auth.authorize_role(caller, Role.ADMIN)

    approval_info = _check_approval("revoke_cert", approval_request_id)

    if not reason.strip():
        raise ValueError("Reason is required for cert revocation")

    revoked = _certs.revoke_cert(cert_id, reason)

    audit_id = _audit.log_event(
        "revoke_cert",
        caller.user_id,
        tool="revoke_cert",
        detail={
            "cert_id": cert_id,
            "reason": reason,
            "approval_request_id": approval_request_id,
        },
    )
    return wrap_response(
        "revoke_cert",
        {
            "cert_id": cert_id,
            "status": "revoked",
            "revoked_at": revoked.revoked_at,
            "audit_id": audit_id,
        },
        approval_info=approval_info,
    )


# ===================================================================
# Approval workflow tools
# ===================================================================


@mcp.tool()
def request_approval(
    action: str,
    justification: str,
    host_id: str = "",
    ticket_ref: str = "",
) -> dict[str, Any]:
    """Request approval for a privileged (Tier 2) operation.

    Returns a request_id and one-time approval_token.
    The token must be presented to the approver.
    The request_id is then passed to the privileged tool.

    Risk level: low (creating a request is safe).
    """
    caller = _get_user()
    req = _approvals.create_request(
        action=action,
        requester_id=caller.user_id,
        justification=justification,
        host_id=host_id,
        ticket_ref=ticket_ref,
    )

    _audit.log_event(
        "request_approval",
        caller.user_id,
        tool="request_approval",
        detail={
            "request_id": req.request_id,
            "action": action,
            "justification": justification,
            "ticket_ref": ticket_ref,
            "mode": req.mode.value,
        },
    )
    return wrap_response("request_approval", {
        "request_id": req.request_id,
        "approval_token": req.approval_token,
        "mode": req.mode.value,
        "expires_at": req.expires_at,
        "status": req.status.value,
    })


@mcp.tool()
def approve_request(
    request_id: str,
    approval_token: str,
) -> dict[str, Any]:
    """Approve a pending approval request.

    In two-party mode, the approver must be a different user
    from the requester.

    Risk level: high (grants execution permission).
    """
    caller = _get_user()
    check_local_policy("approve_request", caller.user_id)
    _auth.check_roles(caller, [Role.ADMIN, Role.OPERATOR])

    approved = _approvals.approve(request_id, caller.user_id, approval_token)

    _audit.log_event(
        "approve_request",
        caller.user_id,
        tool="approve_request",
        detail={
            "request_id": request_id,
            "action": approved.action,
            "requester_id": approved.requester_id,
            "approver_id": caller.user_id,
        },
    )
    return wrap_response("approve_request", {
        "request_id": request_id,
        "status": approved.status.value,
        "action": approved.action,
    })


@mcp.tool()
def list_pending_approvals() -> dict[str, Any]:
    """List all pending approval requests.

    Risk level: low (read-only).
    """
    caller = _get_user()
    _auth.check_roles(caller, [Role.ADMIN, Role.OPERATOR, Role.AUDITOR])

    pending = _approvals.list_pending()
    items = [
        {
            "request_id": r.request_id,
            "action": r.action,
            "requester_id": r.requester_id,
            "justification": r.justification,
            "host_id": r.host_id,
            "mode": r.mode.value,
            "expires_at": r.expires_at,
        }
        for r in pending
    ]

    _audit.log_event(
        "list_pending_approvals",
        caller.user_id,
        tool="list_pending_approvals",
    )
    return wrap_response("list_pending_approvals", {"pending": items})


# ===================================================================
# Session management tools
# ===================================================================


@mcp.tool()
def ssh_connect(host_id: str) -> dict[str, Any]:
    """Open a persistent SSH session to a host.

    Returns a session_id that can be passed to run_ssh_command and
    transfer_file to reuse the connection.  Sessions have keepalive
    probes and auto-close after idle timeout.

    Risk level: low.
    """
    user = _get_user()
    host = _require_host(host_id)
    _auth.authorize_host(user, host)

    session = _sessions.connect(host, user.user_id)
    _audit.log_event(
        "ssh_connect",
        user.user_id,
        tool="ssh_connect",
        host_id=host_id,
        detail={"session_id": session.session_id},
    )
    return wrap_response("ssh_connect", {
        "session_id": session.session_id,
        "host_id": host_id,
        "status": "connected",
        "max_sessions": _sessions.max_sessions,
        "active_sessions": _sessions.active_count,
    }, host_id=host_id)


@mcp.tool()
def ssh_disconnect(session_id: str) -> dict[str, Any]:
    """Close a persistent SSH session.

    Risk level: low.
    """
    user = _get_user()
    _sessions.disconnect(session_id, user.user_id)
    _audit.log_event(
        "ssh_disconnect",
        user.user_id,
        tool="ssh_disconnect",
        detail={"session_id": session_id},
    )
    return wrap_response("ssh_disconnect", {
        "session_id": session_id,
        "status": "disconnected",
    })


@mcp.tool()
def ssh_list_sessions() -> dict[str, Any]:
    """List all active SSH sessions and remaining connection slots.

    Risk level: low.
    """
    user = _get_user()
    sessions = _sessions.list_sessions(user.user_id)
    _audit.log_event(
        "ssh_list_sessions",
        user.user_id,
        tool="ssh_list_sessions",
    )
    return wrap_response("ssh_list_sessions", {
        "sessions": sessions,
        "active_count": _sessions.active_count,
        "max_sessions": _sessions.max_sessions,
    })


@mcp.tool()
def ssh_session_ping(session_id: str) -> dict[str, Any]:
    """Health-check a persistent SSH session.

    Returns liveness, idle time, and uptime.
    Risk level: low.
    """
    user = _get_user()
    info = _sessions.ping(session_id, user.user_id)
    _audit.log_event(
        "ssh_session_ping",
        user.user_id,
        tool="ssh_session_ping",
        detail={"session_id": session_id},
    )
    return wrap_response("ssh_session_ping", info)


# ===================================================================
# Background command execution tools
# ===================================================================


@mcp.tool()
def run_ssh_command_background(
    host_id: str,
    template_id: str,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Start a template command in the background (non-blocking).

    Returns a job_id immediately. Use poll_background_job to read output,
    list_background_jobs to see all jobs, or cancel_background_job to stop.

    Same template-only security model as run_ssh_command.
    Risk level: medium (requires user confirmation).
    """
    user = _get_user()
    check_local_policy("run_ssh_command_background", user.user_id, host_id=host_id)

    host = _require_host(host_id)
    template = _require_template(template_id)

    _auth.authorize_host(user, host)
    _auth.authorize_command(user, template)

    params = params or {}
    job = _jobs.start_job(host, template, params, user.user_id)

    audit_id = _audit.log_event(
        "run_ssh_command_background",
        user.user_id,
        tool="run_ssh_command_background",
        host_id=host_id,
        detail={
            "job_id": job.job_id,
            "template_id": template_id,
            "params": params,
        },
    )
    return wrap_response("run_ssh_command_background", {
        "job_id": job.job_id,
        "host_id": host_id,
        "template_id": template_id,
        "status": "running",
        "audit_id": audit_id,
    }, host_id=host_id)


@mcp.tool()
def poll_background_job(job_id: str) -> dict[str, Any]:
    """Read accumulated output and status of a background job (redacted).

    Returns new stdout since last poll, plus current status and exit code.
    Risk level: low (read-only).
    """
    user = _get_user()
    result = _jobs.poll_job(job_id, user.user_id)
    _audit.log_event(
        "poll_background_job",
        user.user_id,
        tool="poll_background_job",
        detail={"job_id": job_id, "status": result["status"]},
    )
    return wrap_response("poll_background_job", result)


@mcp.tool()
def list_background_jobs() -> dict[str, Any]:
    """List all background jobs (running + completed).

    Risk level: low (read-only).
    """
    user = _get_user()
    jobs = _jobs.list_jobs(user.user_id)
    _audit.log_event(
        "list_background_jobs",
        user.user_id,
        tool="list_background_jobs",
    )
    return wrap_response("list_background_jobs", {"jobs": jobs})


@mcp.tool()
def cancel_background_job(job_id: str) -> dict[str, Any]:
    """Cancel a running background job.

    Risk level: medium (requires user confirmation).
    """
    user = _get_user()
    check_local_policy("cancel_background_job", user.user_id)
    result = _jobs.cancel_job(job_id, user.user_id)

    _audit.log_event(
        "cancel_background_job",
        user.user_id,
        tool="cancel_background_job",
        detail={"job_id": job_id},
    )
    return wrap_response("cancel_background_job", result)


# ===================================================================
# Enhanced SFTP tools
# ===================================================================


@mcp.tool()
def sftp_list_directory(
    host_id: str,
    remote_path: str,
    session_id: str = "",
) -> dict[str, Any]:
    """List files and directories at a remote path.

    Only paths within the configured allowed_paths are accessible.
    Risk level: low (read-only).
    """
    user = _get_user()
    host = _require_host(host_id)
    _auth.authorize_host(user, host)

    # Block path traversal
    if ".." in remote_path:
        raise ValueError("Path contains path traversal sequence")

    policy = _config.transfer_policy
    allowed_prefixes = [p.rstrip("/*") for p in policy.allowed_paths]
    if not any(remote_path.startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError(f"Path '{remote_path}' not in allowed paths")

    # Use session or ephemeral connection
    if session_id:
        session = _sessions.get_session(session_id, user.user_id)
        client = session.client
        close_after = False
    else:
        client = paramiko.SSHClient()
        if _config.ssh_known_hosts_file:
            client.load_host_keys(str(_config.ssh_known_hosts_file))
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": host.hostname,
            "port": host.port,
            "timeout": _config.ssh_timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if host.ssh_user:
            connect_kwargs["username"] = host.ssh_user
        client.connect(**connect_kwargs)
        close_after = True

    try:
        sftp = client.open_sftp()
        entries = []
        for attr in sftp.listdir_attr(remote_path):
            is_dir = stat_mod.S_ISDIR(attr.st_mode) if attr.st_mode else False
            entries.append({
                "name": attr.filename,
                "size": attr.st_size,
                "is_directory": is_dir,
                "modified": attr.st_mtime,
            })
        sftp.close()
    except Exception as exc:
        if close_after:
            client.close()
        raise ValueError(f"SFTP error: {redact(str(exc))}") from exc

    if close_after:
        client.close()

    audit_id = _audit.log_event(
        "sftp_list_directory",
        user.user_id,
        tool="sftp_list_directory",
        host_id=host_id,
        detail={"remote_path": remote_path, "entries_count": len(entries)},
    )
    return wrap_response("sftp_list_directory", {
        "remote_path": remote_path,
        "entries": entries,
        "count": len(entries),
        "audit_id": audit_id,
    }, host_id=host_id)


@mcp.tool()
def sftp_delete(
    host_id: str,
    remote_path: str,
    justification: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """Delete a remote file via SFTP.

    Only files within allowed_paths can be deleted.
    Blocked extensions are enforced.
    Requires a justification.
    Risk level: medium (requires user confirmation).
    """
    user = _get_user()
    check_local_policy("sftp_delete", user.user_id, host_id=host_id)

    host = _require_host(host_id)
    _auth.authorize_host(user, host)
    _auth.check_roles(user, [Role.OPERATOR, Role.ADMIN])

    # Block path traversal
    if ".." in remote_path:
        raise ValueError("Path contains path traversal sequence")

    policy = _config.transfer_policy
    if not any(fnmatch.fnmatch(remote_path, pat) for pat in policy.allowed_paths):
        raise ValueError(f"Path '{remote_path}' not in allowed paths")

    if not justification.strip():
        raise ValueError("Justification is required for file deletion")

    # Use session or ephemeral connection
    if session_id:
        session = _sessions.get_session(session_id, user.user_id)
        client = session.client
        close_after = False
    else:
        client = paramiko.SSHClient()
        if _config.ssh_known_hosts_file:
            client.load_host_keys(str(_config.ssh_known_hosts_file))
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": host.hostname,
            "port": host.port,
            "timeout": _config.ssh_timeout_seconds,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if host.ssh_user:
            connect_kwargs["username"] = host.ssh_user
        client.connect(**connect_kwargs)
        close_after = True

    try:
        sftp = client.open_sftp()
        sftp.remove(remote_path)
        sftp.close()
        status = "deleted"
    except Exception as exc:
        status = "error"
        if close_after:
            client.close()
        raise ValueError(f"SFTP delete error: {redact(str(exc))}") from exc

    if close_after:
        client.close()

    audit_id = _audit.log_event(
        "sftp_delete",
        user.user_id,
        tool="sftp_delete",
        host_id=host_id,
        detail={
            "remote_path": remote_path,
            "justification": justification,
        },
    )
    return wrap_response("sftp_delete", {
        "remote_path": remote_path,
        "status": status,
        "audit_id": audit_id,
    }, host_id=host_id)


# ===================================================================
# Entry point
# ===================================================================


def main() -> None:
    """Run the MCP server (stdio transport for VS Code)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    # Direct invocation: delegate to CLI for argument parsing
    from .cli import cli

    cli()
