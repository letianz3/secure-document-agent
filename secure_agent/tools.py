"""Only this gateway exposes document operations to the agent."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Callable

from .security import (Action, ApprovalStore, AuditLog, Identity, Rejected,
                       data_allowed, parse_action, tool_allowed)


class DocumentStore:
    """In-memory synthetic records; deleting never deletes a host filesystem file."""

    def __init__(self, documents: list[dict]):
        self._documents = {d["id"]: copy.deepcopy(d) for d in documents}

    @classmethod
    def from_fixture(cls) -> "DocumentStore":
        path = Path(__file__).resolve().parent.parent / "data" / "documents.json"
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def fingerprint(self, doc_id: str) -> str:
        encoded = json.dumps(self._documents.get(doc_id), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def contains(self, doc_id: str) -> bool:
        return doc_id in self._documents


# The terminal, not the model, supplies this callback. It receives only an allowed ID.
ApprovalPrompt = Callable[[dict], bool]


class ToolGateway:
    def __init__(self, store: DocumentStore, audit: AuditLog,
                 approvals: ApprovalStore | None = None):
        self.store, self.audit = store, audit
        self.approvals = approvals or ApprovalStore()

    def _record(self, run: str, user: Identity, action: Action | None,
                status: str, reason: str) -> dict:
        self.audit.record(run, user, "tool", status, reason, action)
        return {"status": status, "reason": reason}

    def execute(self, user: Identity, run_id: str, proposal: object,
                approve: ApprovalPrompt | None = None) -> dict:
        try:
            action = parse_action(proposal)
        except Rejected:
            return self._record(run_id, user, None, "denied", "invalid_action")
        if not tool_allowed(user, action.tool):
            return self._record(run_id, user, action, "denied", "tool_permission")
        if action.tool == "list_documents":
            # Filter before returning even titles/IDs to the reasoning node.
            visible = [{"id": d["id"], "title": d["title"]}
                       for d in self.store._documents.values() if data_allowed(user, d)]
            result = self._record(run_id, user, action, "ok", "authorized_list")
            return {**result, "documents": visible}

        document = self.store._documents.get(action.doc_id)
        if document is None or not data_allowed(user, document):
            # Same response for unknown and inaccessible IDs avoids an existence oracle.
            return self._record(run_id, user, action, "denied", "document_unavailable")
        if action.tool == "read_document":
            result = self._record(run_id, user, action, "ok", "authorized_read")
            return {**result, "document": {"id": document["id"], "title": document["title"],
                                           "content": document["content"]}}

        fingerprint = self.store.fingerprint(action.doc_id)
        pending = self.approvals.issue(user, run_id, action, fingerprint)
        try:
            self.audit.record(run_id, user, "approval", "pending", "delete_requires_human", action)
            # Model output cannot supply approval; absent callback always denies.
            accepted = approve is not None and approve({
                "operation": "delete_document", "doc_id": action.doc_id,
                "before": "present", "after": "deleted from this demo session",
                "expires_in_seconds": 120,
            }) is True
            if not accepted:
                return self._record(run_id, user, action, "denied", "approval_not_granted")
            current = self.store._documents.get(action.doc_id)
            if (current is None or not tool_allowed(user, action.tool)
                    or not data_allowed(user, current)):
                return self._record(run_id, user, action, "denied", "policy_changed")
            try:
                self.approvals.consume(pending.token, user, run_id, action,
                                       self.store.fingerprint(action.doc_id))
            except Rejected:
                return self._record(run_id, user, action, "denied", "approval_invalid")
            # Fail closed if the required pre-execution audit cannot be written.
            self.audit.record(run_id, user, "approval", "granted", "bound_action_approved", action)
            del self.store._documents[action.doc_id]
            return self._record(run_id, user, action, "ok", "deleted_after_approval")
        finally:
            self.approvals.cancel(pending.token)
