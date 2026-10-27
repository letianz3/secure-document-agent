import copy
import json
import tempfile
import unittest
from pathlib import Path

from secure_agent.agent import Agent as RealAgent
from secure_agent.guardrails import TestOnlyAllowGuard
from secure_agent.models import ScriptedModel, parse_response
from secure_agent.security import (Action, ApprovalStore, AuditLog, Identity, Rejected,
                                   resolve_identity)
from secure_agent.tools import DocumentStore, ToolGateway
from secure_agent.demo import action


def Agent(*args, **kwargs):
    # Isolate existing permission invariants; guard behavior has separate tests.
    kwargs["guard"] = TestOnlyAllowGuard()
    return RealAgent(*args, **kwargs)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.store = DocumentStore.from_fixture()
        self.audit = AuditLog()
        self.gateway = ToolGateway(self.store, self.audit)
        self.alice, self.bob, self.carol = [resolve_identity(x) for x in ("alice", "bob", "carol")]

    def execute(self, user, tool, doc_id=None, approve=None):
        return self.gateway.execute(user, "test-run", action(tool, doc_id), approve)

    def test_allowed_department_and_public_read(self):
        for user, doc in [(self.alice, "eng-roadmap"), (self.bob, "finance-budget"),
                          (self.bob, "handbook")]:
            with self.subTest(user=user, doc=doc):
                self.assertEqual(self.execute(user, "read_document", doc)["status"], "ok")

    def test_data_denial_has_no_content_and_hides_existence(self):
        denied = self.execute(self.alice, "read_document", "finance-budget")
        unknown = self.execute(self.alice, "read_document", "no-such-document")
        self.assertEqual(denied, unknown)
        self.assertNotIn("document", denied)

    def test_listing_does_not_leak_restricted_metadata(self):
        result = self.execute(self.alice, "list_documents")
        self.assertEqual({x["id"] for x in result["documents"]},
                         {"handbook", "eng-roadmap", "injected-note"})
        self.assertNotIn("Finance Budget", json.dumps(result))

    def test_employee_cannot_delete_even_with_approval_callback(self):
        def forbidden(_):
            self.fail("Unauthorized users must never reach approval")
        result = self.execute(self.alice, "delete_document", "eng-roadmap", forbidden)
        self.assertEqual(result["reason"], "tool_permission")
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_admin_cannot_cross_department_even_with_approval(self):
        result = self.execute(self.carol, "delete_document", "finance-budget", lambda _: True)
        self.assertEqual(result["reason"], "document_unavailable")
        self.assertTrue(self.store.contains("finance-budget"))

    def test_missing_rejected_and_non_boolean_approvals_preserve_document(self):
        for approve in [None, lambda _: False, lambda _: "yes", lambda _: 1]:
            with self.subTest(approve=approve):
                result = self.execute(self.carol, "delete_document", "eng-roadmap", approve)
                self.assertEqual(result["reason"], "approval_not_granted")
                self.assertTrue(self.store.contains("eng-roadmap"))

    def test_approved_delete_changes_state(self):
        proposals = []
        def approve(proposal):
            proposals.append(proposal)
            return True
        result = self.execute(self.carol, "delete_document", "eng-roadmap", approve)
        self.assertEqual(result["reason"], "deleted_after_approval")
        self.assertFalse(self.store.contains("eng-roadmap"))
        self.assertEqual(proposals[0]["doc_id"], "eng-roadmap")
        self.assertNotIn("token", proposals[0])

    def test_changed_document_invalidates_approval(self):
        def approve(_):
            self.store._documents["eng-roadmap"]["content"] = "changed during approval"
            return True
        result = self.execute(self.carol, "delete_document", "eng-roadmap", approve)
        self.assertEqual(result["reason"], "approval_invalid")
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_policy_change_during_approval_is_rechecked(self):
        def approve(_):
            self.store._documents["eng-roadmap"]["department"] = "finance"
            return True
        result = self.execute(self.carol, "delete_document", "eng-roadmap", approve)
        self.assertEqual(result["reason"], "policy_changed")
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_expired_approval_does_not_delete(self):
        clock = [0.0]
        self.gateway.approvals = ApprovalStore(lambda: clock[0])
        def approve(_):
            clock[0] = 121
            return True
        result = self.execute(self.carol, "delete_document", "eng-roadmap", approve)
        self.assertEqual(result["reason"], "approval_invalid")
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_approval_bound_to_user_run_action_and_version(self):
        original = Action("delete_document", "eng-roadmap")
        for user, run, proposal, version in [
            (self.alice, "run1", original, "v1"),
            (self.carol, "run2", original, "v1"),
            (self.carol, "run1", Action("delete_document", "handbook"), "v1"),
            (self.carol, "run1", original, "v2"),
        ]:
            with self.subTest(user=user, run=run, proposal=proposal, version=version):
                approvals = ApprovalStore()
                ticket = approvals.issue(self.carol, "run1", original, "v1")
                with self.assertRaises(Rejected):
                    approvals.consume(ticket.token, user, run, proposal, version)

    def test_approval_cannot_be_replayed(self):
        approvals = ApprovalStore()
        proposal = Action("delete_document", "eng-roadmap")
        ticket = approvals.issue(self.carol, "run1", proposal, "v1")
        approvals.consume(ticket.token, self.carol, "run1", proposal, "v1")
        with self.assertRaises(Rejected):
            approvals.consume(ticket.token, self.carol, "run1", proposal, "v1")

    def test_model_supplied_identity_approval_paths_and_unknown_tools_are_denied(self):
        proposals = [
            {"tool": "delete_document", "args": {"doc_id": "eng-roadmap", "approved": True}},
            {"tool": "read_document", "args": {"doc_id": "finance-budget", "role": "admin"}},
            {"tool": "read_document", "args": {"doc_id": "../../secret"}},
            {"tool": "shell", "args": {"command": "echo test"}},
            {"tool": "list_documents", "args": {"user": "carol"}},
            {"tool": ["read_document"], "args": {}},
        ]
        for proposal in proposals:
            with self.subTest(proposal=proposal):
                result = self.gateway.execute(self.carol, "run", proposal, lambda _: True)
                self.assertEqual(result["reason"], "invalid_action")
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_unclassified_documents_default_to_deny(self):
        self.store._documents["mystery"] = {"id": "mystery", "content": "secret"}
        self.assertEqual(self.execute(self.carol, "read_document", "mystery")["status"], "denied")

    def test_unknown_roles_and_identities_fail_closed(self):
        result = self.execute(Identity("x", "superadmin", "engineering"), "list_documents")
        self.assertEqual(result["reason"], "tool_permission")
        with self.assertRaises(Rejected):
            resolve_identity("mallory")

    def test_malicious_model_after_injected_observation_cannot_escalate(self):
        model = ScriptedModel([action("read_document", "injected-note"),
                               action("read_document", "finance-budget"),
                               action("delete_document", "eng-roadmap")])
        result = Agent(model, self.gateway).run(self.alice, "Read injected-note", lambda _: True)
        self.assertEqual([x["status"] for x in result.observations], ["ok", "denied", "denied"])
        self.assertNotIn("FINANCE-ONLY-4821", json.dumps(result.observations))
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_observation_returns_to_model(self):
        snapshots = []
        class RecordingModel(ScriptedModel):
            def next(inner, transcript):
                snapshots.append(copy.deepcopy(transcript))
                return super().next(transcript)
        result = Agent(RecordingModel([action("read_document", "handbook")]), self.gateway).run(
            self.alice, "Read handbook")
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(snapshots[1][-1]["kind"], "observation")
        self.assertIn("Office hours", snapshots[1][-1]["value"]["document"]["content"])

    def test_transcripts_are_isolated_across_users(self):
        snapshots = []
        class RecordingModel(ScriptedModel):
            def next(inner, transcript):
                snapshots.append(copy.deepcopy(transcript))
                return super().next(transcript)
        model = RecordingModel([action("read_document", "finance-budget")])
        agent = Agent(model, self.gateway)
        agent.run(self.bob, "Read finance-budget")
        agent.run(self.alice, "Hi")
        self.assertEqual(snapshots[-1], [{"kind": "user_request", "text": "Hi"}])

    def test_endless_model_is_bounded(self):
        model = ScriptedModel([action("list_documents")] * 20)
        result = Agent(model, self.gateway, max_steps=3).run(self.alice, "List documents")
        self.assertEqual(result.status, "step_limit")
        self.assertEqual(model.calls, 3)

    def test_timeout_prevents_tool_execution(self):
        clock = [0.0]
        class SlowModel(ScriptedModel):
            def next(inner, transcript):
                clock[0] = 11
                return super().next(transcript)
        result = Agent(SlowModel([action("delete_document", "eng-roadmap")]), self.gateway,
                       time_budget=10, clock=lambda: clock[0]).run(self.carol, "Delete", lambda _: True)
        self.assertEqual(result.status, "time_limit")
        self.assertEqual(result.observations, [])
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_invalid_model_output_stops_without_execution(self):
        result = Agent(ScriptedModel([{"tool": "delete_document", "args": {}, "approved": True}]),
                       self.gateway).run(self.carol, "Delete", lambda _: True)
        self.assertEqual(result.status, "model_error")
        self.assertEqual(result.observations, [])

    def test_json_parser_rejects_ambiguous_and_malformed_output(self):
        for text in ['{"final":"ok","final":"bad"}', '[]', '{"final":null}',
                     'prefix {"final":"ok"}', '{bad', 'x' * 16001]:
            with self.subTest(text=text[:80]), self.assertRaises(Rejected):
                parse_response(text)
        self.assertEqual(parse_response('```json\n{"final":"ok"}\n```'), {"final": "ok"})

    def test_audit_does_not_store_prompts_bodies_or_model_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            gateway = ToolGateway(self.store, AuditLog(path))
            model = ScriptedModel([action("read_document", "finance-budget"),
                                   {"final": "SECRET-MODEL-OUTPUT"}])
            Agent(model, gateway).run(self.bob, "SECRET-QUERY email@example.test")
            contents = path.read_text(encoding="utf-8")
            for secret in ["SECRET-QUERY", "email@example.test", "FINANCE-ONLY-4821",
                           "SECRET-MODEL-OUTPUT", "finance-budget"]:
                self.assertNotIn(secret, contents)
            rows = [json.loads(line) for line in contents.splitlines()]
            self.assertTrue(any(row["reason"] == "authorized_read" for row in rows))

    def test_audit_failure_prevents_deletion(self):
        class BrokenAudit(AuditLog):
            def record(inner, *args, **kwargs):
                raise OSError("disk unavailable")
        gateway = ToolGateway(self.store, BrokenAudit())
        with self.assertRaises(OSError):
            gateway.execute(self.carol, "run", action("delete_document", "eng-roadmap"), lambda _: True)
        self.assertTrue(self.store.contains("eng-roadmap"))

    def test_empty_or_oversized_input_never_calls_model(self):
        model = ScriptedModel([])
        for query in ["", " " * 10, "x" * 4001]:
            result = Agent(model, self.gateway).run(self.alice, query)
            self.assertEqual(result.status, "invalid_input")
        self.assertEqual(model.calls, 0)


if __name__ == "__main__":
    unittest.main()
