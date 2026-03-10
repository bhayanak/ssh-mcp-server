"""Approval workflow for privileged (Tier 2) operations.

Tier 2 operations require explicit approval evidence before execution.
This module manages approval requests, grants, and verification.

Supported approval modes:
- **self-justify**: caller provides justification + ticket reference
  (minimum bar for dev/test).
- **two-party**: a different user with the required role must approve.

Approval tokens are short-lived and single-use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class ApprovalMode(str, Enum):
    """Approval workflow modes."""

    SELF_JUSTIFY = "self-justify"
    TWO_PARTY = "two-party"


class ApprovalStatus(str, Enum):
    """Approval request lifecycle states."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    USED = "used"


@dataclass
class ApprovalRequest:
    """An approval request with its current state."""

    request_id: str
    action: str
    requester_id: str
    mode: ApprovalMode
    justification: str
    ticket_ref: str
    host_id: str
    detail: dict[str, Any]
    status: ApprovalStatus
    created_at: float
    expires_at: float
    approval_token: str  # opaque token; only hash is stored
    approver_id: str = ""
    resolved_at: float | None = None


# ---------------------------------------------------------------------------
# Approval Manager
# ---------------------------------------------------------------------------


class ApprovalManager:
    """Manages approval requests for privileged operations."""

    def __init__(
        self,
        data_dir: Path,
        default_ttl: int = 600,  # 10 minutes
        require_two_party: bool = True,
    ) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._store_path = self._data_dir / "approvals.json"
        self._default_ttl = default_ttl
        self._require_two_party = require_two_party

        self._requests: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._store_path.exists():
            data = json.loads(self._store_path.read_text(encoding="utf-8"))
            self._requests = {r["request_id"]: r for r in data}

    def _save(self) -> None:
        self._store_path.write_text(
            json.dumps(list(self._requests.values()), indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Create request
    # ------------------------------------------------------------------

    def create_request(
        self,
        action: str,
        requester_id: str,
        justification: str,
        host_id: str = "",
        ticket_ref: str = "",
        detail: dict[str, Any] | None = None,
        ttl_seconds: int = 0,
    ) -> ApprovalRequest:
        """Create a new approval request.

        Returns the request including a one-time approval_token that must
        be presented to approve or consume the request.
        """
        if not justification.strip():
            raise ValueError("Justification is required for approval requests")

        mode = (
            ApprovalMode.TWO_PARTY
            if self._require_two_party
            else ApprovalMode.SELF_JUSTIFY
        )

        effective_ttl = ttl_seconds if ttl_seconds > 0 else self._default_ttl
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)

        now = time.time()
        request_id = uuid.uuid4().hex[:16]

        req = {
            "request_id": request_id,
            "action": action,
            "requester_id": requester_id,
            "mode": mode.value,
            "justification": justification,
            "ticket_ref": ticket_ref,
            "host_id": host_id,
            "detail": detail or {},
            "status": ApprovalStatus.PENDING.value,
            "created_at": now,
            "expires_at": now + effective_ttl,
            "token_hash": token_hash,
            "approver_id": "",
            "resolved_at": None,
        }
        self._requests[request_id] = req
        self._save()

        return ApprovalRequest(
            request_id=request_id,
            action=action,
            requester_id=requester_id,
            mode=mode,
            justification=justification,
            ticket_ref=ticket_ref,
            host_id=host_id,
            detail=detail or {},
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + effective_ttl,
            approval_token=token,
            approver_id="",
        )

    # ------------------------------------------------------------------
    # Approve / deny
    # ------------------------------------------------------------------

    def approve(
        self,
        request_id: str,
        approver_id: str,
        token: str,
    ) -> ApprovalRequest:
        """Approve a pending request.

        In two-party mode, approver_id must differ from requester_id.
        """
        req = self._get_and_validate(request_id, token)

        if req["mode"] == ApprovalMode.TWO_PARTY.value:
            if approver_id == req["requester_id"]:
                raise ValueError(
                    "Two-party approval requires a different approver"
                )

        req["status"] = ApprovalStatus.APPROVED.value
        req["approver_id"] = approver_id
        req["resolved_at"] = time.time()
        self._save()

        return self._to_dataclass(req)

    def deny(
        self,
        request_id: str,
        approver_id: str,
        token: str,
    ) -> ApprovalRequest:
        """Deny a pending request."""
        req = self._get_and_validate(request_id, token)
        req["status"] = ApprovalStatus.DENIED.value
        req["approver_id"] = approver_id
        req["resolved_at"] = time.time()
        self._save()
        return self._to_dataclass(req)

    # ------------------------------------------------------------------
    # Consume (mark as used)
    # ------------------------------------------------------------------

    def consume(self, request_id: str) -> None:
        """Mark an approved request as used (single-use)."""
        req = self._requests.get(request_id)
        if req is None:
            raise ValueError(f"Unknown request: {request_id}")
        if req["status"] != ApprovalStatus.APPROVED.value:
            raise ValueError(
                f"Request {request_id} is not approved (status={req['status']})"
            )
        req["status"] = ApprovalStatus.USED.value
        self._save()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_approval(self, request_id: str, action: str) -> dict[str, Any]:
        """Verify that a request_id has valid, unconsumed approval for the given action.

        Returns approval metadata on success, raises ValueError on failure.
        """
        req = self._requests.get(request_id)
        if req is None:
            raise ValueError(f"Unknown approval request: {request_id}")

        # Expire stale requests
        if req["status"] == ApprovalStatus.PENDING.value and time.time() > req["expires_at"]:
            req["status"] = ApprovalStatus.EXPIRED.value
            self._save()

        if req["status"] != ApprovalStatus.APPROVED.value:
            raise ValueError(
                f"Approval {request_id} is not valid (status={req['status']})"
            )

        if req["action"] != action:
            raise ValueError(
                f"Approval action mismatch: expected '{action}', got '{req['action']}'"
            )

        if time.time() > req["expires_at"]:
            req["status"] = ApprovalStatus.EXPIRED.value
            self._save()
            raise ValueError(f"Approval {request_id} has expired")

        return {
            "request_id": req["request_id"],
            "requester_id": req["requester_id"],
            "approver_id": req["approver_id"],
            "justification": req["justification"],
            "ticket_ref": req["ticket_ref"],
            "approved_at": req["resolved_at"],
        }

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_pending(self, requester_id: str | None = None) -> list[ApprovalRequest]:
        """List pending approval requests."""
        # Expire stale requests first
        now = time.time()
        for req in self._requests.values():
            if req["status"] == ApprovalStatus.PENDING.value and now > req["expires_at"]:
                req["status"] = ApprovalStatus.EXPIRED.value
        self._save()

        results = []
        for req in self._requests.values():
            if req["status"] != ApprovalStatus.PENDING.value:
                continue
            if requester_id and req["requester_id"] != requester_id:
                continue
            results.append(self._to_dataclass(req))
        return results

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        """Get a single approval request by ID."""
        req = self._requests.get(request_id)
        if req is None:
            return None
        return self._to_dataclass(req)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_and_validate(self, request_id: str, token: str) -> dict[str, Any]:
        req = self._requests.get(request_id)
        if req is None:
            raise ValueError(f"Unknown request: {request_id}")

        # Expire stale
        if time.time() > req["expires_at"]:
            if req["status"] == ApprovalStatus.PENDING.value:
                req["status"] = ApprovalStatus.EXPIRED.value
                self._save()
            raise ValueError(f"Request {request_id} has expired")

        if req["status"] != ApprovalStatus.PENDING.value:
            raise ValueError(
                f"Request {request_id} is not pending (status={req['status']})"
            )

        # Verify token
        if not hmac.compare_digest(self._hash_token(token), req["token_hash"]):
            raise ValueError("Invalid approval token")

        return req

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _to_dataclass(self, req: dict[str, Any]) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=req["request_id"],
            action=req["action"],
            requester_id=req["requester_id"],
            mode=ApprovalMode(req["mode"]),
            justification=req["justification"],
            ticket_ref=req.get("ticket_ref", ""),
            host_id=req.get("host_id", ""),
            detail=req.get("detail", {}),
            status=ApprovalStatus(req["status"]),
            created_at=req["created_at"],
            expires_at=req["expires_at"],
            approval_token="",  # never expose token after creation
            approver_id=req.get("approver_id", ""),
            resolved_at=req.get("resolved_at"),
        )
