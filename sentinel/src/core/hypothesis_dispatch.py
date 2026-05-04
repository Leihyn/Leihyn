"""
Hypothesis -> specialist dispatcher (Point 5 of the Sentinel improvement plan).

Thinkers emit `Hypothesis` records (cheap, no LLM, generic mental operations).
Specialists are LLM-driven and expensive. Without coordination they re-survey
the entire surface; with coordination they fire ONLY when a thinker hypothesis
matches their bug-class shape.

This module is the bridge. It maps each thinker's hypothesis into a list of
candidate specialists whose required surface tags AND hypothesis-shape
predicate both match, then deduplicates the union by specialist name.

Design notes:
- A hypothesis can map to zero specialists (most thinker output should be
  human-walked, not LLM-walked).
- A hypothesis can map to multiple specialists (denominator-pool-shaped trust
  asymmetry on a governance surface fires both denominator_pool and
  governance_specialist).
- Specialists not in the cap-of-5 selected list are dropped here too.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .surface_tags import SPECIALIST_TAGS, SurfaceProfile


@dataclass
class DispatchEntry:
    specialist: str
    hypothesis_id: str
    contract: str
    function: str | None
    reason: str


# Each predicate takes a Hypothesis dict (as produced by Thinker.walk()) and
# returns True if the hypothesis is shaped like the specialist's bug-class.
# Predicates are deliberately conservative: false negatives are fine
# (specialist doesn't fire), false positives are not (specialist burns LLM
# budget on irrelevant code).
_SHAPE_PREDICATES = {
    "denominator_pool": lambda h: (
        h.get("thinker") == "trust_mapper"
        and "totalSupply" in (h.get("metadata", {}).get("var") or "").lower()
    ) or (
        h.get("thinker") == "spec_skeptic"
        and "vetoThreshold" in h.get("metadata", {}).get("sentence", "")
    ),
    "token_bucket": lambda h: (
        h.get("thinker") == "value_flow"
        and any("throttle" in t or "rate" in t.lower() or "bucket" in t.lower()
                for t in h.get("surface_tags", []))
    ),
    "slippage": lambda h: (
        h.get("thinker") == "value_flow"
        and "external-call" in h.get("surface_tags", [])
        and any(k in (h.get("function") or "").lower()
                for k in ("swap", "trade", "exchange", "buy", "sell", "deposit"))
    ),
    "math_verification": lambda h: (
        h.get("thinker") == "boundary_prober"
        and h.get("metadata", {}).get("substitution") == "MAX"
    ) or (
        h.get("thinker") == "value_flow"
        and "reads-price" in h.get("surface_tags", [])
    ) or (
        h.get("thinker") == "invariant_inferrer"
    ),
    "role_privilege_diff": lambda h: (
        h.get("thinker") == "trust_mapper"
        and any(c.startswith("role:") or "Owner" in c
                for c in h.get("metadata", {}).get("classes", []))
    ),
    "parameter_validation": lambda h: (
        h.get("thinker") == "trust_mapper"
        and any("init" in fn.lower()
                for fn in re.findall(r"\b\w+(?=@)", h.get("suggested_check", "")))
    ) or (
        # Initializer with array param + length=0 OR duplicate-element shape.
        h.get("thinker") == "boundary_prober"
        and h.get("metadata", {}).get("substitution") in ("len=0", "duplicate-element")
        and "init" in (h.get("function") or "").lower()
    ),
    "spec_divergence": lambda h: (
        # NatSpec exclusivity / role / revert-condition claims point at
        # spec-vs-code divergence. These already passed the identifier-anchor
        # check in spec_skeptic; let the LLM specialist verify.
        h.get("thinker") == "spec_skeptic"
        and h.get("metadata", {}).get("claim_kind") in ("exclusivity", "role", "revert-condition", "rfc-mandate")
    ),
    "signature_replay": lambda h: (
        h.get("thinker") == "spec_skeptic"
        and "sign" in h.get("metadata", {}).get("sentence", "").lower()
    ) or (
        # Duplicate-element on signers/proposers/owners/operators arrays =
        # the NAVI ASTROSSC-290 shape (Critical/High in past wins).
        h.get("thinker") == "boundary_prober"
        and h.get("metadata", {}).get("substitution") == "duplicate-element"
        and any(k in (h.get("metadata", {}).get("param") or "").lower()
                for k in ("signer", "proposer", "owner", "operator", "validator"))
    ),
    "reentrancy": lambda h: (
        h.get("thinker") == "value_flow"
        and "external-call" in h.get("surface_tags", [])
        and "writes-value-state" in h.get("surface_tags", [])
        and not h.get("metadata", {}).get("guarded", False)
    ),
    "oracle": lambda h: (
        h.get("thinker") == "value_flow"
        and "reads-price" in h.get("surface_tags", [])
    ),
    "access_control": lambda h: (
        h.get("thinker") == "trust_mapper"
        and "anyone" in h.get("metadata", {}).get("classes", [])
    ),
    "flash_loan": lambda h: (
        h.get("thinker") == "value_flow"
        and "reads-price" in h.get("surface_tags", [])
        and "writes-value-state" in h.get("surface_tags", [])
    ),
}


def dispatch(
    hypotheses: Iterable[dict],
    profile: SurfaceProfile,
    selected_specialists: Iterable[str],
) -> list[DispatchEntry]:
    """For each hypothesis, return the specialists that should examine it.

    Only specialists in `selected_specialists` are eligible (cap-of-5 already
    applied upstream by surface_tags.select_specialists). Each pairing is
    one DispatchEntry; the orchestrator can group by specialist to build
    per-specialist work queues.
    """
    selected = set(selected_specialists)
    out: list[DispatchEntry] = []
    for h in hypotheses:
        for name, pred in _SHAPE_PREDICATES.items():
            if name not in selected:
                continue
            required = SPECIALIST_TAGS.get(name, []) or []
            if required and not profile.matches(required):
                continue
            try:
                if not pred(h):
                    continue
            except Exception:
                continue
            out.append(DispatchEntry(
                specialist=name,
                hypothesis_id=h.get("id", ""),
                contract=h.get("contract", ""),
                function=h.get("function"),
                reason=f"shape match for {name}",
            ))
    return out


def group_by_specialist(entries: list[DispatchEntry]) -> dict[str, list[DispatchEntry]]:
    """Bucket dispatch entries by specialist name for per-specialist queues."""
    out: dict[str, list[DispatchEntry]] = {}
    for e in entries:
        out.setdefault(e.specialist, []).append(e)
    return out


def render_dispatch_table(entries: list[DispatchEntry], profile: SurfaceProfile) -> str:
    if not entries:
        return "No hypothesis-to-specialist matches"
    grouped = group_by_specialist(entries)
    lines = [f"Surface tags: {', '.join(sorted(profile.tags)) or '(none)'}"]
    for name, group in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"\n## {name} ({len(group)} hypotheses)")
        for e in group[:10]:
            loc = f"{e.contract}.{e.function or '?'}"
            lines.append(f"  - {loc}  hyp={e.hypothesis_id}")
        if len(group) > 10:
            lines.append(f"  ... and {len(group) - 10} more")
    return "\n".join(lines)
