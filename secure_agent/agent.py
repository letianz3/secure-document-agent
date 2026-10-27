"""Bounded reasoning -> policy/tool -> observation -> reasoning loop."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from .models import parse_response
from .guardrails import PromptInjectionGuard, GuardUnavailable, observation_text
from .security import Identity, Rejected
from .tools import ApprovalPrompt, ToolGateway
import json


@dataclass
class RunResult:
    run_id: str
    mode: str
    status: str
    answer: str
    observations: list[dict]
    model_calls: int


class Agent:
    def __init__(self, model, gateway: ToolGateway, max_steps: int = 6,
                 time_budget: float = 240, clock=time.monotonic, guard=None):
        if not 1 <= max_steps <= 20 or time_budget <= 0:
            raise ValueError("Invalid run limits")
        self.model, self.gateway = model, gateway
        self.max_steps, self.time_budget, self.clock = max_steps, time_budget, clock
        self.guard = PromptInjectionGuard() if guard is None else guard

    def run(self, user: Identity, query: str, approve: ApprovalPrompt | None = None) -> RunResult:
        run_id = secrets.token_hex(8)
        started = self.clock()
        observations, transcript = [], []
        calls = 0

        def finish(status: str, answer: str) -> RunResult:
            self.gateway.audit.record(run_id, user, "run", status, status)
            return RunResult(run_id, self.model.mode, status, answer, observations, calls)

        if not isinstance(query, str) or not query.strip() or len(query) > 4000:
            return finish("invalid_input", "Request must contain 1-4000 characters.")
        self.gateway.audit.record(run_id, user, "run", "started", "request_accepted")
        try:
            scan = self.guard.scan(query)
            self.gateway.audit.record(run_id, user, "input_guard",
                                      "blocked" if scan.blocked else "passed", "injection_scan")
            if scan.blocked:
                return finish("injection_blocked", "Request blocked: possible prompt injection.")
            # New transcript on EVERY run; never reuse another user's observations.
            transcript.append({"kind": "user_request", "text": query})
            for _ in range(self.max_steps):
                if self.clock() - started >= self.time_budget:
                    return finish("time_limit", "Run time budget reached.")
                calls += 1
                # Validate even custom model adapters at the boundary.
                decision = parse_response(json.dumps(self.model.next(transcript)))
                if self.clock() - started >= self.time_budget:
                    return finish("time_limit", "Run time budget reached before tool execution.")
                if "final" in decision:
                    return finish("completed", decision["final"])
                result = self.gateway.execute(user, run_id, decision, approve)
                scan = self.guard.scan(observation_text(result))
                self.gateway.audit.record(run_id, user, "observation_guard",
                                          "blocked" if scan.blocked else "passed", "injection_scan")
                if scan.blocked:
                    # Do not show or append a rejected document payload to the transcript.
                    observations.append({"status": "denied", "reason": "observation_injection"})
                    return finish("injection_blocked", "Tool result blocked: possible prompt injection.")
                observations.append(result)
                transcript.extend([{"kind": "proposed_action", "value": decision},
                                   {"kind": "observation", "trust": "untrusted_data", "value": result}])
            return finish("step_limit", "Maximum reasoning steps reached.")
        except GuardUnavailable:
            return finish("guard_error", "Injection scanner unavailable; request stopped. Check setup instructions.")
        except Rejected:
            return finish("model_error", "Model response failed validation or the provider was unavailable.")
