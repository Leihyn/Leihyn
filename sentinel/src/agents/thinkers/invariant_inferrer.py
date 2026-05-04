"""
Invariant inferrer — from variable names + storage groupings, propose
invariants and flag every function that writes the relevant slots without
preserving them.

Examples of inferred invariants:
- totalSupply == sum(balances) when both totalSupply and balances exist
- totalAssets >= totalShares * pricePerShare when those names co-occur
- sum(stakes) == totalStaked when both exist
- count == length(array) when count + array co-exist

The inferrer ONLY proposes; it never asserts. The audit-prep phase or the
fuzzing harness skill picks these up and writes Foundry invariant tests.
"""
from __future__ import annotations

import re

from ...core.types import AuditState
from .base import Hypothesis, ThinkerBase


# (vars-pattern -> invariant-template)
_INVARIANT_RULES: list[tuple[tuple[str, ...], str]] = [
    (("totalSupply", "balanceOf"),
     "totalSupply == sum(balanceOf[*])"),
    (("totalSupply", "balances"),
     "totalSupply == sum(balances[*])"),
    (("totalAssets", "totalShares"),
     "totalAssets >= 0 AND totalShares >= 0 AND (totalShares == 0 implies totalAssets == 0)"),
    (("totalStaked", "stakes"),
     "totalStaked == sum(stakes[*].amount)"),
    (("totalDebt", "debt"),
     "totalDebt == sum(debt[*])"),
    (("totalDeposits", "deposits"),
     "totalDeposits == sum(deposits[*])"),
    (("totalCollateral", "collateral"),
     "totalCollateral == sum(collateral[*])"),
    (("count", "length"),
     "count == array.length (every array push/pop must adjust count)"),
    (("threshold", "signers"),
     "signers.length >= threshold AND signers contains no duplicates"),
    (("totalOptimisticPower", "totalSupply"),
     "totalOptimisticPower <= totalSupply (delegation pool is a subset of total)"),
]


def _names_in_contract(contract) -> set[str]:
    out: set[str] = set()
    for sv in getattr(contract, "state_variables", []) or []:
        name = getattr(sv, "name", None) or (sv.get("name") if isinstance(sv, dict) else None)
        if name:
            out.add(name)
    return out


_WRITE = re.compile(r"\b([a-zA-Z_][a-zA-Z_0-9]*)\s*(?:\[[^\]]+\])?\s*(?:=(?!=)|\+=|-=|\*=|/=)\s*")
_TOTAL_PREFIX = re.compile(r"^total([A-Z]\w+)$")


def _auto_pair_rules_static(names: set[str]) -> list[tuple[tuple[str, ...], str]]:
    """For every `total<Stem>` state var, look for a same-stem partner
    (mapping/plural/singular) and emit an inferred invariant.
    """
    out: list[tuple[tuple[str, ...], str]] = []
    totals: dict[str, str] = {}
    for n in names:
        m = _TOTAL_PREFIX.match(n)
        if m:
            totals[m.group(1)] = n
    for stem, total_name in totals.items():
        # Find a candidate partner: stem itself (lowercased), or a -s plural
        candidates_lower = [stem.lower(), stem.lower() + "s",
                            stem.lower().rstrip("ed"),
                            stem.lower().rstrip("s")]
        partner = None
        for n in names:
            if n == total_name:
                continue
            nl = n.lower()
            if nl in candidates_lower or any(c and c == nl for c in candidates_lower):
                partner = n
                break
        if not partner:
            # Pair two `total*` siblings as a "running-total invariant" hint.
            siblings = [t for t in totals.values() if t != total_name]
            if siblings:
                partner = siblings[0]
        if partner:
            out.append(((total_name, partner),
                        f"every increment of {total_name} corresponds to a write to {partner} of the same magnitude"))
    return out


class InvariantInferrer(ThinkerBase):
    name = "invariant_inferrer"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for contract in state.contracts:
            names = _names_in_contract(contract)
            # Auto-derived invariants: any `total<Stem>` that pairs with a
            # same-stem mapping/plural state variable. Calibration
            # 2026-05-04: handcoded rule list missed Reserve.totalDeposited /
            # totalClaimed and Boba.totalDeposits / totalDisbursements
            # because the singular/past-tense names didn't match.
            auto_rules = _auto_pair_rules_static(names)
            for required, invariant in (*_INVARIANT_RULES, *auto_rules):
                if not all(any(r.lower() in n.lower() for n in names) for r in required):
                    continue
                # Functions that write any of the invariant's variables
                writers: list[tuple[str, int]] = []
                for fn in getattr(contract, "functions", []) or []:
                    body = getattr(fn, "body", "") or ""
                    if not body:
                        continue
                    written = {m.group(1) for m in _WRITE.finditer(body)}
                    if any(any(r.lower() in w.lower() for w in written) for r in required):
                        writers.append((fn.name, getattr(fn, "line_start", 0)))
                if not writers:
                    continue
                writer_summary = ", ".join(f"{n}@{ln}" for n, ln in writers[:8])
                out.append(Hypothesis(
                    id=self._hid("inv", contract.name, writers[0][1]),
                    thinker=self.name,
                    contract=contract.name,
                    function=None,
                    line_numbers=(0, 0),
                    question=f"Does every writer of {required} preserve `{invariant}`?",
                    fragility=f"invariant `{invariant}` is implied by the variable names but writers may break it",
                    must_hold_property=invariant,
                    suggested_check=f"audit each writer ({writer_summary}) for compensating updates; or write a Foundry stateful invariant test asserting the property",
                    confidence=0.55,
                    surface_tags=["inferred-invariant"],
                    metadata={"vars": list(required), "writers": writers},
                ))
        return out
