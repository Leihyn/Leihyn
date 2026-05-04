"""
Thinker base — mental-operation agents that emit hypotheses, not findings.

Distinction from hunters: hunters detect a known bug class (denominator-pool,
token-bucket, slippage, etc.) which generalizes only to codebases that contain
that pattern. Thinkers run a generic mental operation (value-flow walk,
spec-skeptic, boundary probe, trust-boundary mapping, invariant inference) on
any codebase. They emit Hypothesis records that downstream specialists or
finding_confirmer.py can promote into Findings if confirmed.

Hypotheses are intentionally cheaper than Findings: a hypothesis says "this
function looks fragile if X happens"; the confirmer answers "does X actually
happen and does it actually break a property". Promoting hypothesis -> finding
goes through the FP gate (src/core/fp_gate.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ...core.types import AuditState


@dataclass
class Hypothesis:
    """A "what-if" hypothesis emitted by a thinker.

    A Finding answers "this is a bug because X". A Hypothesis answers "X looks
    fragile, here is the property that would have to hold for it to be safe".
    The confirmer/specialist phase decides if the property fails.
    """
    id: str
    thinker: str                       # which thinker emitted it
    contract: str
    function: Optional[str] = None
    line_numbers: tuple[int, int] = (0, 0)

    # The "what-if" itself
    question: str = ""                 # "what if msg.sender lies about X?"
    fragility: str = ""                # one-line description of the fragile assumption
    must_hold_property: str = ""       # the property that would have to hold for safety
    suggested_check: str = ""          # how to confirm/refute (grep, fork test, etc.)

    # Triage
    confidence: float = 0.0            # thinker's own prior, 0-1
    surface_tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    metadata: dict = field(default_factory=dict)


class ThinkerBase:
    """Base class for the 5 mental-operation thinkers.

    Subclasses implement `walk(state) -> list[Hypothesis]`. They MUST NOT call
    the LLM in the hot loop. The thinker's job is structural: walk the
    audit state (contracts, functions, intents, x-ray context) and emit
    structured hypotheses cheaply. LLM enrichment, if any, is done by the
    confirmer phase, not here.

    This split matters because thinkers fire on every codebase regardless of
    surface, while specialists are gated by surface_tags. Thinkers must stay
    cheap or they become the bottleneck.
    """
    name: str = "thinker"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        raise NotImplementedError

    def _hid(self, prefix: str, contract: str, line: int = 0) -> str:
        return f"{prefix}-{contract}-{line}-{datetime.now().strftime('%H%M%S%f')}"
