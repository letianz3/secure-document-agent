"""Run from the project root: python -m secure_agent --help."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .agent import Agent
from .models import DEFAULT_MODEL, GoogleModel
from .credentials import configured_key
from .security import AuditLog, Rejected, USERS, resolve_identity
from .tools import DocumentStore, ToolGateway


def terminal_approval(proposal: dict) -> bool:
    print("\nHUMAN APPROVAL REQUIRED (trusted terminal; expires after 120 seconds)")
    print(json.dumps(proposal, indent=2))
    try:
        return input("Type 'yes' or 'approve' to confirm; anything else rejects: ").strip().lower() in {"yes", "approve"}
    except (EOFError, KeyboardInterrupt):
        print("\nApproval rejected.")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="HW1 secure document agent (synthetic data only)")
    parser.add_argument("--user", choices=sorted(USERS), default="alice",
                        help="Trusted demo identity selection, not production login")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="Google model ID; default is the validated Gemma 4 free-tier model")
    parser.add_argument("--query", help="One request; otherwise enter an interactive session")
    parser.add_argument("--audit", type=Path, default=Path("runtime/audit.jsonl"))
    parser.add_argument("--demo", action="store_true", help="Run deterministic OFFLINE scenarios, no LLM/key")
    args = parser.parse_args()
    if args.demo:
        from .demo import run_demo
        return run_demo()
    try:
        key = configured_key()
        if not key:
            key = getpass.getpass("Google API key (hidden, not saved): ").strip()
        user = resolve_identity(args.user)
        model = GoogleModel(key, args.model)
        agent = Agent(model, ToolGateway(DocumentStore.from_fixture(), AuditLog(args.audit)))
        print(f"LIVE GOOGLE MODEL | model={args.model} | user={user.user_id} | "
              f"role={user.role} | department={user.department}")
        print("Synthetic documents only. Changes last until this process exits. Type /quit to exit.")
        print("Injection guard: ON (rule-based; no model download or extra dependencies).")
        while True:
            query = args.query if args.query is not None else input("\nRequest> ")
            if query == "/quit":
                return 0
            result = agent.run(user, query, terminal_approval)
            # Terminal observations are intentionally visible for the authorized demo user;
            # the persistent audit logger records only metadata.
            print(json.dumps(asdict(result), indent=2, ensure_ascii=True))
            if args.query is not None:
                return 0 if result.status == "completed" else 1
    except (EOFError, KeyboardInterrupt):
        print("\nSession ended.")
        return 0
    except Rejected as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("I/O failed; run stopped. Check the audit destination and connection.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
