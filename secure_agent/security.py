"""Trusted identities, strict action schemas, policy, approvals, and audit records."""
from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


class Rejected(ValueError):
    """An invalid action, identity, or approval; messages contain no document data."""


@dataclass(frozen=True)
class Identity:
    user_id: str
    role: str
    department: str


# Classroom identity fixture, NOT a production authentication mechanism.
USERS = {
    "alice": Identity("alice", "employee", "engineering"),
    "bob": Identity("bob", "employee", "finance"),
    "carol": Identity("carol", "admin", "engineering"),
}


def resolve_identity(user_id: str) -> Identity:
    try:
        return USERS[user_id]
    except (KeyError, TypeError):
        raise Rejected("Unknown demo identity") from None


@dataclass(frozen=True)
class Action:
    tool: str
    doc_id: str | None = None


def parse_action(value: object) -> Action:
    """No paths, identity overrides, approval flags, or unknown parameters."""
    if not isinstance(value, dict) or set(value) != {"tool", "args"}:
        raise Rejected("Expected exactly tool and args")
    name, args = value["tool"], value["args"]
    if not isinstance(name, str) or name not in {"list_documents", "read_document", "delete_document"}:
        raise Rejected("Unknown tool")
    if not isinstance(args, dict):
        raise Rejected("Tool args must be an object")
    if name == "list_documents":
        if args:
            raise Rejected("list_documents accepts no arguments")
        return Action(name)
    if set(args) != {"doc_id"}:
        raise Rejected("Expected only doc_id")
    doc_id = args["doc_id"]
    if not isinstance(doc_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", doc_id):
        raise Rejected("Invalid document ID")
    return Action(name, doc_id)


def tool_allowed(user: Identity, tool: str) -> bool:
    return tool in {
        "employee": {"list_documents", "read_document"},
        "admin": {"list_documents", "read_document", "delete_document"},
    }.get(user.role, set())


def data_allowed(user: Identity, document: dict) -> bool:
    visibility = document.get("visibility")
    return visibility == "public" or (
        visibility == "department" and document.get("department") == user.department
    )


@dataclass(frozen=True)
class PendingApproval:
    token: str
    run_id: str
    user_id: str
    action: Action
    fingerprint: str
    expires_at: float


class ApprovalStore:
    """One-shot, expiring approvals bound to actor, run, action, and record version."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._pending: dict[str, PendingApproval] = {}
        self.clock = clock

    def issue(self, user: Identity, run_id: str, action: Action, fingerprint: str) -> PendingApproval:
        pending = PendingApproval(secrets.token_urlsafe(24), run_id, user.user_id,
                                  action, fingerprint, self.clock() + 120)
        self._pending[pending.token] = pending
        return pending

    def cancel(self, token: str) -> None:
        self._pending.pop(token, None)

    def consume(self, token: str, user: Identity, run_id: str,
                action: Action, fingerprint: str) -> None:
        pending = self._pending.pop(token, None)
        if pending is None or (
            pending.user_id != user.user_id or pending.run_id != run_id
            or pending.action != action or pending.fingerprint != fingerprint
            or self.clock() >= pending.expires_at
        ):
            raise Rejected("Approval missing, expired, changed, or already consumed")


class AuditLog:
    """Allowlisted metadata only. Raw queries, responses, keys and bodies never enter logs."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.records: list[dict] = []
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, run_id: str, user: Identity, event: str, outcome: str,
               reason: str, action: Action | None = None) -> None:
        item = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id, "actor_id": user.user_id,
            "event": event, "outcome": outcome, "reason": reason,
            "tool": action.tool if action else None,
        }
        # Deliberately omit even doc_id: attempted IDs could contain sensitive text.
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, sort_keys=True) + "\n")
                handle.flush()
        self.records.append(item)
