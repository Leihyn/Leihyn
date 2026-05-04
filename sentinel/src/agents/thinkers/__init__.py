"""
Mental-operation thinkers (Point 1 of the Sentinel improvement plan).

Each thinker runs a generic mental operation that generalizes to any
codebase, in contrast to specialist hunters which detect a specific bug
class. Thinkers emit Hypothesis records, not Findings; the FP gate and
finding_confirmer decide which hypotheses are promoted.
"""
from .base import Hypothesis, ThinkerBase
from .value_flow import ValueFlowWalker
from .spec_skeptic import SpecSkeptic
from .boundary_prober import BoundaryProber
from .trust_mapper import TrustBoundaryMapper
from .invariant_inferrer import InvariantInferrer


THINKERS: list[type[ThinkerBase]] = [
    ValueFlowWalker,
    SpecSkeptic,
    BoundaryProber,
    TrustBoundaryMapper,
    InvariantInferrer,
]


def run_all(state) -> list[Hypothesis]:
    """Convenience: instantiate every thinker, walk, and return the union."""
    out: list[Hypothesis] = []
    for cls in THINKERS:
        try:
            out.extend(cls().walk(state))
        except Exception as exc:
            # A thinker failure must never abort an audit. Log once and move on.
            out.append(Hypothesis(
                id=f"thinker-error-{cls.__name__}",
                thinker=cls.__name__,
                contract="<error>",
                question=f"thinker {cls.__name__} raised: {exc}",
                fragility="thinker crash",
                must_hold_property="",
                suggested_check="",
                confidence=0.0,
                surface_tags=["thinker-error"],
            ))
    return out


__all__ = [
    "Hypothesis",
    "ThinkerBase",
    "ValueFlowWalker",
    "SpecSkeptic",
    "BoundaryProber",
    "TrustBoundaryMapper",
    "InvariantInferrer",
    "THINKERS",
    "run_all",
]
