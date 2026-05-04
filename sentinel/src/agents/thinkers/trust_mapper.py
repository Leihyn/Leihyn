"""
Trust-boundary mapper — for each function, list:

    (caller class, what they assume, what breaks if they lie)

This thinker's value is not the per-function output but the cross-function
matrix it produces. Two functions both gated by `onlyOwner` are NOT one trust
boundary if the threshold checks differ; two functions gated by different
roles but writing the same storage var are a trust mismatch waiting to happen.

Output: hypotheses where the same storage var is written from >= 2 distinct
caller classes (anyone, role-A, role-B, owner). Those are flagged with
"trust-asymmetry" and inherit the strictest assumption from any write site.
"""
from __future__ import annotations

import re
from collections import defaultdict

from ...core.types import AuditState, FunctionInfo
from .base import Hypothesis, ThinkerBase


_ROLE_MODIFIERS = re.compile(
    # Any custom modifier prefixed `only*` (onlyOwner, onlyOwnerOrRevoker,
    # onlyProposer, onlyAdminOrManager, etc.) plus a few non-`only`-prefixed
    # access-control modifier names commonly seen in OZ + solady codebases,
    # plus the OZ initializer family which gates re-entry not who-can-call
    # but DOES restrict to a one-shot trusted-deployer call.
    r"\b(only[A-Z][A-Za-z0-9_]*|requiresAuth|hasAccess|whenAuthorized|"
    r"initializer|reinitializer|onlyInitializing)\b"
)
_ROLE_KEYWORD = re.compile(
    r"\b(_grantRole|hasRole|onlyRole)\(\s*([A-Z_][A-Z_0-9]*)\b"
)
_STATE_WRITE = re.compile(
    r"\b([a-zA-Z_][a-zA-Z_0-9]*)\s*"
    r"(?:\[[^\]]+\])?\s*"
    # Critical: negative lookahead `(?!=)` after the bare `=` so we don't
    # match equality `==` as an assignment. `signerImageHash[s] == h` was
    # being flagged as a write to signerImageHash from isValidSigner (a
    # view function). Found on Base Azul TEEProverRegistry, 2026-05-04.
    r"(?:=(?!=)|\+=|-=|\*=|/=)\s*"
)

# Rust state writes: REQUIRE a `self.`/`state.`/`ctx.accounts.<X>.` prefix.
# Without the prefix we'd match every local `let name = ...;` declaration as a
# state write. Calibration 2026-05-04 (Base proof crate): naive regex picked
# up locals like `new_prefix` and enum variants like `Empty`. Tighter prefix
# requirement reduces those FPs.
_RUST_STATE_WRITE = re.compile(
    r"(?:self|state|ctx\.accounts\.[A-Za-z_]\w*)\s*\.\s*"
    r"([a-zA-Z_][a-zA-Z_0-9]*)\s*"
    r"(?:\[[^\]]+\])?\s*"
    r"(?:=(?!=)|\+=|-=|\*=|/=)\s*"
)

# 2026-05-04 calibration on Base Azul multiproof: prior version classified
# functions like `challenge()` / `nullify()` / `resolve()` as "anyone" because
# their access guards are INLINE (`if (status != IN_PROGRESS) revert`) rather
# than modifier-based. This produced 11 false-alarm hypotheses on
# AggregateVerifier alone. The fix: scan the first ~512 bytes of body for
# state-machine / sender / pause guards and treat the function as
# effectively-restricted when one is present.
_INLINE_SENDER_GUARD = re.compile(
    r"\b(require|if)\s*\([^)]*msg\.sender\b[^)]*[!=]=\s*[a-zA-Z_]"
)
_INLINE_STATE_GUARD = re.compile(
    r"\b(require|if)\s*\([^)]*\b(status|paused|initialized|nullified|"
    r"frozen|locked|finalized|resolved|gameOver|isOver)\b"
)
_INLINE_REVERT = re.compile(r"\brevert\s+[A-Z][A-Za-z0-9_]*")

# Rust analog: require! / require_keys_eq! / assert! macros AND Anchor's
# #[access_control(...)] attribute macros recognized via _ROLE_MODIFIERS.
_RUST_INLINE_GUARD = re.compile(
    r"\b(require|require_keys_eq|require_eq|require_neq|assert|assert_eq|"
    r"ensure|verify|check)!\s*\("
)
_RUST_PANIC_GUARD = re.compile(r"\b(panic|unimplemented|todo)!\s*\(|\.unwrap\(\)|\.expect\(")


def _has_inline_guard(body: str, language: str = "solidity") -> bool:
    head = body[:512] if body else ""
    if not head:
        return False
    if language == "rust":
        if _RUST_INLINE_GUARD.search(head):
            return True
        return False
    if _INLINE_SENDER_GUARD.search(head):
        return True
    if _INLINE_STATE_GUARD.search(head) and _INLINE_REVERT.search(head):
        return True
    return False


def _caller_class(fn: FunctionInfo, language: str = "solidity") -> str:
    body = getattr(fn, "body", "") or ""
    mods = " ".join(getattr(fn, "modifiers", []) or [])
    blob = f"{mods} {body}"
    if language == "rust":
        # Rust attribute-macro analog: `#[access_control(...)]`,
        # `#[only_admin]`, `#[admin_only]`, etc. We treat any access_control,
        # only_*, admin, governance attribute as a role gate.
        attr_match = re.search(
            r"\b(access_control|only_owner|only_admin|only_governance|"
            r"admin_only|owner_only|governance_only|only_[a-z_]+)\b", mods
        )
        if attr_match:
            return f"mod:{attr_match.group(1)}"
        vis = (getattr(fn, "visibility", "") or "").lower()
        if vis == "external":                                       # `pub fn`
            if _has_inline_guard(body, language):
                return "inline-guarded"
            return "anyone"
        return "internal"
    role_match = _ROLE_KEYWORD.search(blob)
    if role_match:
        return f"role:{role_match.group(2)}"
    mod_match = _ROLE_MODIFIERS.search(blob)
    if mod_match:
        return f"mod:{mod_match.group(1)}"
    if (getattr(fn, "visibility", "") or "").lower() in ("public", "external"):
        if _has_inline_guard(body, language):
            return "inline-guarded"
        return "anyone"
    return "internal"


def _writes(body: str, language: str = "solidity") -> set[str]:
    pattern = _RUST_STATE_WRITE if language == "rust" else _STATE_WRITE
    return {m.group(1) for m in pattern.finditer(body)}


def _state_var_names(contract) -> set[str]:
    """Extract the actual state variable names declared by the contract.

    Filters out locals/params/temporaries that share the regex shape with
    state writes. Without this, `address verifier = ...;` and `uint256 expiry
    = ...;` in function bodies pollute trust_mapper's writers list with
    non-state identifiers and produce hypotheses on stack data.
    """
    out: set[str] = set()
    for sv in getattr(contract, "state_variables", []) or []:
        name = getattr(sv, "name", None) or (sv.get("name") if isinstance(sv, dict) else None)
        if name:
            out.add(name)
    return out


class TrustBoundaryMapper(ThinkerBase):
    name = "trust_mapper"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        # contract -> var -> {caller_class: [(fn_name, line)]}
        matrix: dict[str, dict[str, dict[str, list[tuple[str, int]]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )
        for contract in state.contracts:
            language = getattr(contract, "language", "solidity") or "solidity"
            state_vars = _state_var_names(contract)
            for fn in getattr(contract, "functions", []) or []:
                body = getattr(fn, "body", "") or ""
                if not body:
                    continue
                klass = _caller_class(fn, language)
                for var in _writes(body, language):
                    if var in {"_", "i", "j", "k", "tmp", "x", "y"} or var.startswith("_"):
                        continue
                    # Filter out locals/params: only report writes to declared
                    # state variables. If the contract has no parsed state vars
                    # (e.g., interface-only or unparsed), fall through (best-effort).
                    if state_vars and var not in state_vars:
                        continue
                    matrix[contract.name][var][klass].append(
                        (fn.name, getattr(fn, "line_start", 0))
                    )

        out: list[Hypothesis] = []
        for contract, var_map in matrix.items():
            for var, classes in var_map.items():
                if len(classes) < 2:
                    continue
                # Asymmetric writers; "anyone" + "role:X" is the most dangerous combo.
                klass_set = set(classes.keys())
                strictest = self._strictest(klass_set)
                weakest = self._weakest(klass_set)
                if strictest == weakest:
                    continue
                example_lines = [(c, fn, ln) for c, sites in classes.items() for fn, ln in sites][:6]
                callers_summary = ", ".join(
                    f"{c}:{fn}@{ln}" for c, fn, ln in example_lines
                )
                out.append(Hypothesis(
                    id=self._hid("tm", contract, example_lines[0][2] if example_lines else 0),
                    thinker=self.name,
                    contract=contract,
                    function=None,
                    line_numbers=(0, 0),
                    question=(
                        f"What if a {weakest} caller writes {var} via one path while another path "
                        f"requires {strictest}? Are the post-conditions on {var} the same?"
                    ),
                    fragility=f"{var} is written by both {weakest} and {strictest} callers",
                    must_hold_property=(
                        f"every write to {var} from {weakest} MUST satisfy the same invariant "
                        f"that the {strictest}-gated path enforces, OR {var} is partitioned per-caller"
                    ),
                    suggested_check=f"diff the bound checks across the writers: {callers_summary}",
                    confidence=0.6 if "anyone" in klass_set else 0.45,
                    surface_tags=["trust-asymmetry"],
                    metadata={"var": var, "classes": list(klass_set)},
                ))
        return out

    @staticmethod
    def _strictest(classes: set[str]) -> str:
        order = ["role:DEFAULT_ADMIN_ROLE", "mod:onlyOwner", "mod:onlyAdmin", "mod:onlyGovernance"]
        for o in order:
            if o in classes:
                return o
        for c in classes:
            if c.startswith("role:") or c.startswith("mod:"):
                return c
        return "internal" if "internal" in classes else next(iter(classes))

    @staticmethod
    def _weakest(classes: set[str]) -> str:
        if "anyone" in classes:
            return "anyone"
        if "internal" in classes:
            return "internal"
        return next(iter(classes))
