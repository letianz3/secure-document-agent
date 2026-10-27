"""Bounded, deterministic injection-pattern screening using only Python's standard library.

This is a rule-based detector, not a learned classifier or a general jailbreak defense.
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass

RULESET_VERSION = "document-agent-rules-v1"

class GuardUnavailable(RuntimeError):
    """Stop when screening cannot be completed."""

@dataclass(frozen=True)
class ScanResult:
    blocked: bool
    matched_rules: tuple[str, ...] = ()

def observation_text(result: dict) -> str:
    """Scan returned document fields, not trusted gateway status/reason constants."""
    documents = result.get("documents", [])
    if "document" in result:
        documents = [result["document"]]
    return "\n".join(str(d[key]) for d in documents
                     for key in ("id", "title", "content") if key in d)


# Rules target explicit attempts to change the agent's instructions or authority.
# Ordinary read/delete commands are not injection patterns; policy handles those.
RULES = tuple((name, re.compile(pattern)) for name, pattern in [
    ("instruction_override", r"\b(?:ignore|disregard|forget|override)\b.{0,60}\b(?:instructions?|rules?|polic(?:y|ies)|system prompt)\b"),
    ("role_spoofing", r"\b(?:you are|i am|act as|pretend to be)\s+(?:(?:now|an?|the)\s+){0,3}(?:admin(?:istrator)?|root|system)\b"),
    ("approval_bypass", r"\b(?:without|skip|bypass|disable)\b.{0,50}\b(?:approval|confirmation|permission|asking(?: the user)?)\b"),
    ("secret_request", r"\b(?:reveal|print|show|send|expose|output)\b.{0,60}\b(?:system prompt|api keys?|secret keys?|credentials)\b"),
    ("forged_message", r"(?:<\|(?:im_start|start_header_id)\|>\s*(?:system|developer)|\[(?:system|developer)\])"),
    ("instruction_override_zh", r"(?:忽略|无视|覆盖).{0,20}(?:指令|规则|系统提示|限制)"),
    ("approval_bypass_zh", r"(?:跳过|绕过|无需|不需要).{0,12}(?:审批|批准|确认|权限)"),
])

class PromptInjectionGuard:
    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str) or len(text) > 32000:
            raise GuardUnavailable("Scanner input exceeds supported size")
        try:
            normalized = unicodedata.normalize("NFKC", text).casefold()
            normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
            normalized = " ".join(normalized.split())
            matches = tuple(name for name, pattern in RULES if pattern.search(normalized))
            return ScanResult(bool(matches), matches)
        except Exception:
            raise GuardUnavailable("Injection screening failed; request stopped") from None

class TestOnlyAllowGuard:
    """Test double used to verify downstream policies even when screening misses."""
    def scan(self, text: str) -> ScanResult:
        return ScanResult(False)
