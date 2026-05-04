"""
Value-flow walker — for every externally-callable function, walk:

    value -> state -> assumptions -> edges -> exploit

This is the lens captured in feedback_value_flow.md (memory rule). It is
intentionally agnostic to bug class. The walker emits one hypothesis per
external function whose body either (a) writes balance/share/debt-shaped
state, (b) calls an external contract, or (c) reads a price/oracle.

The output is structural: it tells the specialist phase WHERE to look. It
does NOT decide whether the function is exploitable.
"""
from __future__ import annotations

import re
from typing import Iterable

from ...core.types import AuditState, FunctionInfo
from .base import Hypothesis, ThinkerBase


_VALUE_NAMES = re.compile(
    r"\b(balance|balances|deposit|deposits|share|shares|debt|owe|owed|"
    r"collateral|principal|reserve|reserves|pool|liquidity|stake|staked|"
    r"reward|rewards|allowance|locked|borrowed|supplied|asset|assets|"
    r"yield|fee|fees|profit)\b",
    re.IGNORECASE,
)
_PRICE_NAMES = re.compile(
    r"\b(price|oracle|getPrice|latestAnswer|latestRoundData|"
    r"getQuote|getRate|exchangeRate|twap|cumulative|consult)\b",
    re.IGNORECASE,
)
_EXTERNAL_CALL = re.compile(r"\.(call|delegatecall|staticcall|transfer|send)\b|"
                            r"\b(safeTransfer|safeTransferFrom|transferFrom)\(")

# Rust analogs: Solana CPI (`invoke(`, `invoke_signed(`, `::cpi::`),
# token-program calls, system_program calls, raw .send/.call on RPC clients,
# any `.await` on a network future, `tokio::spawn`, etc. Calibration scope is
# Solana-Anchor + general Rust, not perfect.
_RUST_EXTERNAL_CALL = re.compile(
    r"\b(invoke|invoke_signed|invoke_unchecked)\s*\("
    r"|::cpi::\w+\s*\("
    r"|\btoken::\w+\s*\("
    r"|\bsystem_program::\w+\s*\("
    r"|\.send\s*\("
    r"|\.transfer\s*\("
    r"|\.transfer_from\s*\("
    r"|\.call\s*\("
    r"|\.await\b"
)
_RUST_VALUE_NAMES = re.compile(
    r"\b(balance|amount|deposit|share|debt|collateral|reserve|"
    r"liquidity|stake|reward|allowance|locked|borrowed|supplied|"
    r"asset|yield|fee|profit|lamports|tokens)\b",
    re.IGNORECASE,
)
_RUST_NONREENTRANT = re.compile(
    r"\b(reentrancy_guard|nonreentrant|no_reentrant|with_lock|locked)\b",
    re.IGNORECASE,
)

# Calibration 2026-05-04 (Dexalot Portfolio + Boba StandardBridge):
# value_flow was firing HIGH (0.70) reentrancy hypotheses on well-known
# nonReentrant + CEI functions. Skip the reentrancy chain when either guard
# is present.
_NONREENTRANT_MOD = re.compile(r"\bnonReentrant\b|\bnoReentrancy\b|\bnoReentry\b")
# Pattern matches a state-mutation followed by an external call WITHIN the
# same function body, i.e. NOT CEI. If the only mutations come BEFORE the
# external call we treat it as CEI.
_STATE_MUTATION = re.compile(
    r"\b(balance|balances|deposit|share|debt|reserve|pool|stake|"
    r"reward|allowance|locked|asset|fee|totalSupply)\w*\s*\[?[^=;{}]*=(?!=)",
    re.IGNORECASE,
)


def _has_nonreentrant(fn) -> bool:
    mods = " ".join(getattr(fn, "modifiers", []) or [])
    return bool(_NONREENTRANT_MOD.search(mods))


def _is_cei(body: str) -> bool:
    """True when no state mutation occurs after the LAST external call."""
    if not body:
        return False
    last_call = -1
    for m in _EXTERNAL_CALL.finditer(body):
        if m.start() > last_call:
            last_call = m.start()
    if last_call == -1:
        return True                            # no external call -> trivially CEI
    tail = body[last_call:]
    return not _STATE_MUTATION.search(tail)


def _is_external(fn: FunctionInfo) -> bool:
    vis = (getattr(fn, "visibility", "") or "").lower()
    # Solidity: public/external. Rust: external (= `pub fn`). Move: external
    # via `public fun` or `entry fun` set during read; private via `fun` only.
    return vis in ("public", "external") and not getattr(fn, "is_constructor", False)


def _is_move_view_function(fn: FunctionInfo) -> bool:
    """Move read-only function detector. Calibration 2026-05-04 PM (Astros):
    `balance_value(vault: &ActiveVault<T>)` was firing value_flow because Move
    has no `view` keyword. A Move function is read-only when:
    - No parameter is taken by `&mut T` (mutable reference)
    - The `entry` modifier is absent (entry funs can mutate via &mut shared)
    - Visibility is `public` (not `entry`)
    Heuristic: if the BODY does not contain any of `&mut`, `transfer::`,
    `coin::join`, `balance::join`, the fn is treated as read-only.
    """
    body = getattr(fn, "body", "") or ""
    if not body:
        return False
    mods = " ".join(getattr(fn, "modifiers", []) or [])
    if "entry" in mods.lower():
        return False
    # Quick negative signals: function clearly mutates state.
    if any(s in body for s in ("&mut self", "transfer::", "::join(", "::split(",
                                "push_back", "remove(", "borrow_mut",
                                ".add(", "destroy_zero", "destroy_some")):
        return False
    # If params don't include any &mut, it's read-only.
    params = getattr(fn, "parameters", []) or []
    for p in params:
        ptype = (p.get("type") if isinstance(p, dict) else getattr(p, "type", "")) or ""
        if "&mut" in ptype or "&mut " in ptype:
            return False
    return True


def _classify(body: str, language: str = "solidity") -> list[str]:
    tags: list[str] = []
    if language == "rust":
        if _RUST_VALUE_NAMES.search(body):
            tags.append("writes-value-state")
        if _RUST_EXTERNAL_CALL.search(body):
            tags.append("external-call")
        if _PRICE_NAMES.search(body):
            tags.append("reads-price")
        return tags
    if _VALUE_NAMES.search(body):
        tags.append("writes-value-state")
    if _EXTERNAL_CALL.search(body):
        tags.append("external-call")
    if _PRICE_NAMES.search(body):
        tags.append("reads-price")
    return tags


class ValueFlowWalker(ThinkerBase):
    name = "value_flow"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for contract in state.contracts:
            language = getattr(contract, "language", "solidity") or "solidity"
            for fn in getattr(contract, "functions", []) or []:
                if not _is_external(fn):
                    continue
                # Move-specific: filter out read-only functions (no `view` kw
                # in Move; detect via &mut param absence + body inspection).
                if language == "move" and _is_move_view_function(fn):
                    continue
                body = getattr(fn, "body", "") or ""
                if not body:
                    continue
                tags = _classify(body, language)
                if not tags:
                    continue

                # Demote the reentrancy chain when guarded by nonReentrant
                # modifier OR when the function follows CEI ordering. Both
                # checks are syntactic; LLM-grade reasoning happens later.
                if language == "rust":
                    mods = " ".join(getattr(fn, "modifiers", []) or [])
                    guarded = bool(_RUST_NONREENTRANT.search(mods)) or _is_cei(body)
                else:
                    guarded = _has_nonreentrant(fn) or _is_cei(body)
                if guarded and "external-call" in tags and "writes-value-state" in tags:
                    # Drop the strongest "reentrancy" framing; downgrade to the
                    # external-call-only chain or skip if the only signal was
                    # reentrancy-shaped.
                    tags = [t for t in tags if t != "writes-value-state"]
                    if not tags:
                        continue

                question, fragility, must_hold = self._chain(tags, fn.name)
                out.append(Hypothesis(
                    id=self._hid("vf", contract.name, getattr(fn, "line_start", 0)),
                    thinker=self.name,
                    contract=contract.name,
                    function=fn.name,
                    line_numbers=(getattr(fn, "line_start", 0), getattr(fn, "line_end", 0)),
                    question=question,
                    fragility=fragility,
                    must_hold_property=must_hold,
                    suggested_check=self._suggest(tags, contract.name, fn.name),
                    confidence=self._prior(tags) - (0.15 if guarded else 0.0),
                    surface_tags=tags + (["nonReentrant-or-cei"] if guarded else []),
                    metadata={"flow_tags": tags, "guarded": guarded},
                ))
        return out

    @staticmethod
    def _chain(tags: list[str], fn_name: str) -> tuple[str, str, str]:
        head = "writes-value-state" in tags
        ext = "external-call" in tags
        price = "reads-price" in tags

        if head and ext:
            return (
                f"What if the external call in {fn_name}() reenters or returns false silently before the value-state write commits?",
                "value-state mutation interleaved with external call",
                "either CEI ordering OR a non-reentrant guard MUST hold across this function",
            )
        if head and price:
            return (
                f"What if the price read by {fn_name}() is stale, manipulated, or returns 0?",
                "value-state mutation gated by price",
                "price read MUST be sanity-checked (staleness, deviation, non-zero) before being used to compute the write",
            )
        if head:
            return (
                f"What if the inputs to {fn_name}() are 0, MAX, or unequal between mirrored fields?",
                "value-state mutation under attacker-controlled input",
                "every input that scales the write MUST have a bound enforced before the write",
            )
        if ext:
            return (
                f"What if the external call in {fn_name}() reverts, returns false, or returns malicious data?",
                "external-call result trusted",
                "return value MUST be checked AND callee address MUST be validated against an allowlist or factory",
            )
        if price:
            return (
                f"What if the price feed used in {fn_name}() is stale or sequencer is down (L2)?",
                "price read without freshness check",
                "answer MUST be checked for staleness AND L2 sequencer uptime feed MUST be consulted",
            )
        return ("", "", "")

    @staticmethod
    def _suggest(tags: list[str], contract: str, fn: str) -> str:
        bits = []
        if "external-call" in tags:
            bits.append(f"grep -nE '\\.(call|delegatecall)' against {contract}.{fn}")
        if "reads-price" in tags:
            bits.append(f"check for staleness/sequencer guard around price read in {fn}")
        if "writes-value-state" in tags:
            bits.append(f"locate every write site of the touched storage var; ensure invariant holds post-call")
        return "; ".join(bits) if bits else "spec-skeptic pass"

    @staticmethod
    def _prior(tags: list[str]) -> float:
        score = 0.4
        if "external-call" in tags:
            score += 0.2
        if "reads-price" in tags:
            score += 0.15
        if "writes-value-state" in tags:
            score += 0.1
        return min(score, 0.85)
