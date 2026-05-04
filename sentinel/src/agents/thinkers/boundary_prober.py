"""
Boundary prober — for every numeric input and array, force-substitute
{0, 1, MAX, type(uint256).max, len-1, len+1, len=0, dup-elt} and ask whether
the function still upholds its property.

This is the static analogue of "what if N=0/N=1/N=max" probing. The output is
one hypothesis per (function, parameter, boundary-substitution) tuple where
the function body shows no explicit bound check on that parameter.

It is deliberately noisy at the hypothesis level. The FP gate downstream will
demote any hypothesis whose parameter has a `require`/`if revert` immediately
checking the relevant bound.
"""
from __future__ import annotations

import re

from ...core.types import AuditState, FunctionInfo
from .base import Hypothesis, ThinkerBase


# Numeric / array-shaped Solidity types (informal).
_NUM_TYPES = re.compile(
    r"^(u?int(?:8|16|32|64|128|256)?|uint|int|bytes32)$"
)
_RUST_NUM_TYPES = re.compile(
    r"^(u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size)|f32|f64)$"
)
_ARRAY_HINT = re.compile(r"\[\]")
_RUST_ARRAY_HINT = re.compile(r"^(?:Vec\s*<|&\s*\[|\[)|^(?:&\s*)?\[\s*\w+\s*[;,]")
_DUP_GUARD = re.compile(r"\bunique|seen|deduped|noDuplicate|distinct\b", re.IGNORECASE)

# Calibration 2026-05-04 (Dexalot/Reserve/Boba): boundary_prober was firing
# `sub=0` on every numeric-id getter (`getTradePair(_tradePairId)`,
# `getNBook(_nPrice)`) where 0 is either a no-op or harmless. Only flag
# zero/MAX hypotheses when the parameter is consumed in:
# - arithmetic that scales with it (`* p`, `/ p`, `+= p`, `p**...`)
# - a state write proportional to it (`balance[x] += p`)
# - an external transfer/mint/burn call
# View functions and pure id-lookup paths get skipped.
_SCALING_USE = re.compile(
    r"(?:\*\s*{p}|/\s*{p}|{p}\s*\*|{p}\s*/|"
    r"\+=\s*{p}\b|-=\s*{p}\b|"
    r"(?:transfer|safeTransfer|mint|burn|deposit|withdraw|stake|unstake)\s*\([^)]*{p}\b)"
)
_VIEW_OR_PURE = re.compile(r"\b(view|pure)\b")


def _params(fn: FunctionInfo) -> list[tuple[str, str]]:
    """Return [(type, name), ...] best-effort from the FunctionInfo."""
    raw = getattr(fn, "parameters", None)
    if not raw:
        return []
    out: list[tuple[str, str]] = []
    if isinstance(raw, str):
        for p in raw.split(","):
            p = p.strip()
            if not p:
                continue
            parts = p.split()
            if len(parts) >= 2:
                out.append((parts[0], parts[-1]))
        return out
    for p in raw:
        ptype = getattr(p, "type", None) or (p.get("type") if isinstance(p, dict) else "")
        pname = getattr(p, "name", None) or (p.get("name") if isinstance(p, dict) else "")
        if ptype:
            out.append((str(ptype), str(pname or "?")))
    return out


def _has_bound_check(body: str, param: str) -> bool:
    if not param or param == "?":
        return False
    pat = re.compile(
        rf"\b(require|if)\s*\([^)]*\b{re.escape(param)}\b[^)]*[<>=!]",
        re.IGNORECASE,
    )
    return bool(pat.search(body))


def _has_zero_check(body: str, param: str) -> bool:
    if not param or param == "?":
        return False
    pat = re.compile(
        rf"\b(require|if)\s*\([^)]*\b{re.escape(param)}\b[^)]*(?:!=\s*0|>\s*0|>\s*0x0)",
        re.IGNORECASE,
    )
    return bool(pat.search(body))


class BoundaryProber(ThinkerBase):
    name = "boundary_prober"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for contract in state.contracts:
            for fn in getattr(contract, "functions", []) or []:
                vis = (getattr(fn, "visibility", "") or "").lower()
                if vis not in ("public", "external"):
                    continue
                body = getattr(fn, "body", "") or ""
                if not body:
                    continue
                mut = (getattr(fn, "mutability", "") or "").lower()
                is_view_pure = mut in ("view", "pure") or _VIEW_OR_PURE.search(
                    " ".join(getattr(fn, "modifiers", []) or [])
                )
                language = getattr(contract, "language", "solidity") or "solidity"
                for ptype, pname in _params(fn):
                    ptype_norm = ptype.replace(" memory", "").replace(" calldata", "").strip()
                    if language == "rust":
                        # Strip references / mut prefixes for type matching.
                        rt = ptype_norm.lstrip("&").replace("mut ", "").strip()
                        is_num = bool(_RUST_NUM_TYPES.match(rt.split()[0] if rt else ""))
                        is_arr = bool(_RUST_ARRAY_HINT.match(rt))
                        if not (is_num or is_arr):
                            continue
                        ptype_norm = rt
                    else:
                        is_num = bool(_NUM_TYPES.match(ptype_norm))
                        is_arr = bool(_ARRAY_HINT.search(ptype_norm))
                        if not (is_num or is_arr):
                            continue

                    if is_view_pure:
                        # View/pure functions cannot have value-flow impact
                        # from boundary substitutions; skip the numeric chain.
                        continue
                    # Build a per-param "is this scaling-used" predicate.
                    scale_pat = re.compile(
                        _SCALING_USE.pattern.replace("{p}", re.escape(pname))
                    )
                    scaling_used = bool(scale_pat.search(body))

                    if is_num and not _has_zero_check(body, pname) and scaling_used:
                        out.append(self._mk(
                            contract.name, fn, pname, "0",
                            f"What if {pname} == 0 in a scaling consumer?",
                            "numeric input scales a write/transfer with no non-zero guard",
                            f"the scaling path is safe with {pname} == 0 OR a require rejects it",
                        ))
                    upper_bound_relevant = (
                        "uint256" in ptype_norm
                        or (language == "rust" and ptype_norm.startswith(("u128", "u64", "usize")))
                    )
                    if is_num and upper_bound_relevant and not _has_bound_check(body, pname) and scaling_used:
                        out.append(self._mk(
                            contract.name, fn, pname, "MAX",
                            f"What if {pname} == type(uint256).max (overflow under arithmetic)?",
                            "uint256 input scales arithmetic with no upper-bound guard",
                            f"the arithmetic that consumes {pname} cannot overflow OR a require enforces an upper bound",
                        ))
                    if is_arr:
                        out.append(self._mk(
                            contract.name, fn, pname, "len=0",
                            f"What if {pname}.length == 0?",
                            "array input lacks length guard",
                            f"empty {pname} either reverts or is a no-op consistent with the spec",
                        ))
                        if not _DUP_GUARD.search(body):
                            out.append(self._mk(
                                contract.name, fn, pname, "duplicate-element",
                                f"What if {pname} contains a duplicate element (dup-key / dup-signer / dup-id)?",
                                "array input lacks dedup guard",
                                f"{pname} is verified to be a set OR the consumer is dup-tolerant by design",
                            ))
        return out

    def _mk(
        self,
        contract: str,
        fn: FunctionInfo,
        pname: str,
        substitution: str,
        question: str,
        fragility: str,
        prop: str,
    ) -> Hypothesis:
        return Hypothesis(
            id=self._hid(f"bp-{substitution}", contract, getattr(fn, "line_start", 0)),
            thinker=self.name,
            contract=contract,
            function=fn.name,
            line_numbers=(getattr(fn, "line_start", 0), getattr(fn, "line_end", 0)),
            question=question,
            fragility=fragility,
            must_hold_property=prop,
            suggested_check=(
                f"grep -nE '\\b(require|if)\\s*\\(.*{re.escape(pname)}.*' on the function body; "
                f"if no guard, write a Foundry test that calls with {substitution}"
            ),
            confidence=0.5,
            surface_tags=["param-boundary"],
            metadata={"param": pname, "substitution": substitution},
        )
