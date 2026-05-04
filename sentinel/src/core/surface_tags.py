"""
Surface-tag dispatch (Point 3).

Classifies a codebase into a tag set the orchestrator can use to dispatch
specialist hunters only when their pattern is plausibly present. Stops the
"fire all 11 hunters on every contest" anti-pattern that burned 6h of
subagent budget on Base Azul for zero new findings beyond F-22.

Always-on (no tag required): the 5 thinkers + fresh-eyes + spec-divergence.
Tag-gated: every other specialist.

Rule of thumb: cap concurrent specialist dispatch at MAX_CONCURRENT_SPECIALISTS.
Always-on agents do not count against the cap.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .types import AuditState


MAX_CONCURRENT_SPECIALISTS = 5


# Surface-tag taxonomy. Tags are deliberately coarse so audit-intel can detect
# them with a regex sweep instead of an LLM call. Add tags as new specialists
# are added; the matrix below maps specialists to required tags.
SURFACE_TAGS: dict[str, list[re.Pattern]] = {
    "dex": [re.compile(r"\b(swap|getAmountsOut|liquidity|pool|pair|tickSpacing|sqrtPrice)\b", re.I)],
    "lending": [re.compile(r"\b(borrow|repay|liquidate|collateral|healthFactor|debt)\b", re.I)],
    "vault": [re.compile(r"\b(deposit|withdraw|redeem|share|totalAssets|previewDeposit)\b", re.I)],
    "staking": [re.compile(r"\b(stake|unstake|reward|earned|rewardRate|notifyReward)\b", re.I)],
    "governance": [re.compile(r"\b(propose|veto|quorum|timelock|castVote|execute)\b", re.I)],
    "oracle": [re.compile(r"\b(latestAnswer|latestRoundData|getPrice|getQuote|consult|twap)\b", re.I)],
    "bridge": [re.compile(r"\b(deposit|withdraw|relay|message|crossChain|outbox|inbox)\b", re.I)],
    "proxy": [re.compile(r"\b(initialize|delegatecall|implementation|upgradeTo)\b", re.I)],
    "signature": [re.compile(r"\b(ecrecover|isValidSignature|EIP712|domainSeparator|signTypedData)\b")],
    "multisig": [re.compile(r"\b(threshold|signers|owners|confirmation|isOwner)\b", re.I)],
    "throttle": [re.compile(r"\b(rateLimit|charge|capacity|lastUpdated|bucket|throttle)\b", re.I)],
    "auction": [re.compile(r"\b(auction|bid|placeBid|settle|highest|reservePrice)\b", re.I)],
    "amm": [re.compile(r"\b(invariant|kLast|getReserves|swapExactTokens|sync)\b", re.I)],
    "l2-client": [re.compile(r"\b(sequencer|batcher|L1Block|deposit|miner|forkchoice)\b", re.I)],
    "rebasing": [re.compile(r"\b(rebase|pooledEth|sharesOf|getPooledEth)\b", re.I)],
    "veToken": [re.compile(r"\b(veToken|locked|votingPower|gauge|boost)\b", re.I)],
    "denominator-pool": [re.compile(r"\b(getPastTotalSupply|optimisticDelegate|vetoDelegate|subscribers)\b")],
    "slippage": [re.compile(r"\b(amountOutMin|minAmountOut|deadline|slippage|maxSlippage)\b", re.I)],
}


# Specialist -> required tags (any-of). An empty list means always-on.
SPECIALIST_TAGS: dict[str, list[str]] = {
    # always-on
    "fresh_eyes": [],
    "spec_divergence": [],
    "value_flow": [],
    "spec_skeptic": [],
    "boundary_prober": [],
    "trust_mapper": [],
    "invariant_inferrer": [],
    # tag-gated
    "denominator_pool": ["denominator-pool", "governance"],
    "token_bucket": ["throttle"],
    "slippage": ["dex", "amm", "slippage"],
    "math_verification": ["amm", "vault", "lending", "oracle"],
    "role_privilege_diff": ["governance", "multisig"],
    "parameter_validation": ["proxy", "vault", "lending"],
    "governance_specialist": ["governance"],
    "oracle": ["oracle"],
    "reentrancy": ["dex", "vault", "lending", "bridge"],
    "access_control": ["governance", "proxy", "multisig"],
    "flash_loan": ["lending", "amm"],
    "signature_replay": ["signature", "multisig", "bridge"],
}


@dataclass
class SurfaceProfile:
    tags: set[str] = field(default_factory=set)
    evidence: dict[str, list[str]] = field(default_factory=dict)  # tag -> [hits]

    def matches(self, required: Iterable[str]) -> bool:
        required = list(required)
        if not required:
            return True
        return any(t in self.tags for t in required)


def classify_surface(state: AuditState, max_files: int = 200) -> SurfaceProfile:
    """Walk the contracts (or fall back to file globs) and tag the surface."""
    profile = SurfaceProfile()
    seen_blob: list[str] = []

    # Prefer parsed contracts for accuracy; fall back to ripgrep across files.
    for c in state.contracts[:max_files]:
        for fn in getattr(c, "functions", []) or []:
            sig = f"{fn.name}"
            body = getattr(fn, "body", "") or ""
            seen_blob.append(sig + " " + body[:1500])
        names = " ".join(getattr(sv, "name", "") or "" for sv in (getattr(c, "state_variables", []) or []))
        seen_blob.append(names)

    if not seen_blob:
        target = Path(getattr(state, "target_path", "."))
        for p in list(target.rglob("*.sol"))[:max_files]:
            try:
                seen_blob.append(p.read_text(errors="ignore")[:4000])
            except OSError:
                continue

    blob = "\n".join(seen_blob)
    for tag, patterns in SURFACE_TAGS.items():
        hits: list[str] = []
        for pat in patterns:
            for m in pat.finditer(blob):
                hits.append(m.group(0))
                if len(hits) >= 3:
                    break
            if len(hits) >= 3:
                break
        if hits:
            profile.tags.add(tag)
            profile.evidence[tag] = hits
    return profile


def select_specialists(
    profile: SurfaceProfile,
    requested: Iterable[str],
    cap: int = MAX_CONCURRENT_SPECIALISTS,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Split a requested specialist list into (selected, dropped_with_reason).

    Always-on specialists pass regardless of cap. Tag-gated specialists are
    ranked by surface-affinity before the cap is applied, so the most-
    relevant specialists win the cap-of-5 ties. Without this, on a bridge
    surface `signature_replay` (highly relevant) was being dropped while
    `access_control` (general-purpose) survived purely by request order.

    Affinity heuristic:
    - Match strength = number of overlapping tags between specialist's
      required-tags and the surface profile tags.
    - Tie-break by SURFACE_AFFINITY priority (specialist-name -> surface-tag),
      higher = more relevant for that surface.
    - Final tie-break by original request order.
    """
    requested = list(requested)
    selected: list[str] = []
    dropped: list[tuple[str, str]] = []

    # Always-on specialists: take first (free, no cap).
    tag_gated: list[str] = []
    for name in requested:
        required = SPECIALIST_TAGS.get(name, None)
        if required is None:
            dropped.append((name, "unknown specialist; add to SPECIALIST_TAGS"))
            continue
        if not required:
            selected.append(name)
            continue
        if not profile.matches(required):
            dropped.append((name, f"surface lacks any of {required}; tags present: {sorted(profile.tags)}"))
            continue
        tag_gated.append(name)

    # Rank tag-gated by affinity descending. Ties broken by request order.
    def affinity(name: str) -> tuple[int, int]:
        required = SPECIALIST_TAGS.get(name, []) or []
        overlap = sum(1 for t in required if t in profile.tags)
        priority = max(
            (SURFACE_AFFINITY.get((name, t), 0) for t in profile.tags),
            default=0,
        )
        return (overlap, priority)

    tag_gated.sort(key=lambda n: (-affinity(n)[0], -affinity(n)[1], requested.index(n)))

    cap_used = 0
    for name in tag_gated:
        if cap_used >= cap:
            dropped.append((name, f"specialist cap of {cap} reached (after affinity ranking)"))
            continue
        selected.append(name)
        cap_used += 1

    return selected, dropped


# Specialist-to-surface affinity. Higher score = more relevant for that
# surface, used to break ties when more specialists match a profile than the
# cap allows. Calibrated against the Base Azul lesson: signature_replay
# should beat access_control on a bridge; oracle should beat math_verification
# on an oracle-heavy DEX.
SURFACE_AFFINITY: dict[tuple[str, str], int] = {
    # bridges
    ("signature_replay", "bridge"): 10,
    ("reentrancy", "bridge"): 7,
    ("access_control", "bridge"): 4,
    # governance
    ("denominator_pool", "governance"): 10,
    ("governance_specialist", "governance"): 9,
    ("role_privilege_diff", "governance"): 8,
    ("access_control", "governance"): 5,
    # oracle
    ("oracle", "oracle"): 10,
    ("math_verification", "oracle"): 6,
    # dex / amm
    ("slippage", "dex"): 10,
    ("slippage", "amm"): 10,
    ("flash_loan", "amm"): 9,
    ("math_verification", "amm"): 7,
    ("reentrancy", "dex"): 6,
    # vault
    ("math_verification", "vault"): 9,
    ("parameter_validation", "vault"): 7,
    ("reentrancy", "vault"): 6,
    # lending
    ("flash_loan", "lending"): 10,
    ("oracle", "lending"): 9,
    ("math_verification", "lending"): 8,
    # multisig
    ("signature_replay", "multisig"): 10,
    ("role_privilege_diff", "multisig"): 8,
    # throttle
    ("token_bucket", "throttle"): 10,
    # proxy
    ("parameter_validation", "proxy"): 9,
    ("access_control", "proxy"): 7,
}


def render_dispatch_summary(profile: SurfaceProfile, selected: list[str], dropped: list[tuple[str, str]]) -> str:
    lines = [
        "Surface profile:",
        f"  tags: {', '.join(sorted(profile.tags)) or '(none detected)'}",
        "Selected specialists:",
        *[f"  + {n}" for n in selected],
        "Dropped specialists:",
        *[f"  - {n}: {reason}" for n, reason in dropped],
    ]
    return "\n".join(lines)
