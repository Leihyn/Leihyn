"""
Spec-skeptic — every README/NatSpec claim is a hypothesis to test.

Reads the codebase's documentation strings and pulls "hard claims" (formulas,
exclusivity statements, role/access claims, parameter bounds) out of them.
Each claim becomes a hypothesis: "the docs say X; verify the code does X".

This thinker is the static-pass equivalent of the Reserve-M-02 lesson: before
filing OZ-divergence, check README + git history. We do that PROACTIVELY here
by surfacing every doc claim that the code might or might not honor.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...core.types import AuditState
from .base import Hypothesis, ThinkerBase


# Hard-claim keywords. Calibration 2026-05-04 (Dexalot/Boba/Reserve walks):
# the original "only/always/never" exclusivity regex matched generic NatSpec
# prose like "LIMIT is always available by default" — not falsifiable and
# noise-dominant. New patterns require either a prescriptive verb ("MUST",
# "only X can Y") or a structural anchor (formula/bound/role) AND a
# code-anchorable identifier (camelCase or snake_case word) in the same
# sentence so the grep / git log step has somewhere to land.
_CLAIM_PATTERNS = [
    # "only X can/may/MUST/will" OR "only callable/triggered/modifiable by"
    # OR "X can only be ..." — covers Reserve's "Only callable by ROLE" and
    # Boba's "Can only be triggered by the other StandardBridge".
    (re.compile(
        r"\bonly\s+(?:\w+\s+)?(?:can|may|MUST|will|callable|triggered|"
        r"invoked|modifiable|settable|changeable)\b",
        re.IGNORECASE,
    ), "exclusivity"),
    (re.compile(r"\b\w+\s+can\s+only\s+be\b", re.IGNORECASE), "exclusivity"),
    (re.compile(r"\bcannot\s+be\s+(?:called|invoked|set|changed|modified)\b", re.IGNORECASE), "exclusivity"),
    (re.compile(r"\b(formula|computed as|calculated as|equal to|equals)\s+\S", re.IGNORECASE), "formula"),
    (re.compile(r"\b(role|admin|owner|guardian|operator|manager)\s+(can|may|will|cannot|MUST)\b", re.IGNORECASE), "role"),
    (re.compile(r"\b(reverts?|fails?|throws?)\s+(when|if|unless)\b", re.IGNORECASE), "revert-condition"),
    (re.compile(r"\b(at most|at least|no more than|no less than|bounded by|capped at)\s+\S", re.IGNORECASE), "bound"),
    (re.compile(r"\b(MUST|SHALL)(?:\s+(?:NOT|always|never))?\b"), "rfc-mandate"),
]

# Sentences containing any of these strongly signal "documented behavior" or
# "explanatory prose" rather than a tight invariant. Skip them.
_NOISE_MARKERS = re.compile(
    r"\b(by default|see (above|below|the spec)|for example|"
    r"e\.g\.|i\.e\.|note that|in other words|for completeness|"
    r"average|approximately|generally|typically|usually|"
    r"may be (different|the same)|could be|might be)\b",
    re.IGNORECASE,
)

# Anchor: a sentence must mention at least one identifier-shaped word so the
# downstream confirmer has somewhere to grep. Covers camelCase
# (`addToken`), snake_case (`gas_limit_cap`), SCREAMING_SNAKE
# (`OPTIMISTIC_PROPOSER_ROLE`), AND PascalCase contract names
# (`StandardBridge`, `TEEProverRegistry`). Single capitalized words like
# "Can" or "Finalizes" don't match because they require >= 1 internal cap
# transition or >= 2 caps in a row.
_IDENTIFIER = re.compile(
    r"\b[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]+\b"        # camelCase
    r"|\b[a-z]+_[a-z_0-9]+\b"                         # snake_case
    r"|\b[A-Z][A-Z_0-9]{3,}\b"                        # SCREAMING_SNAKE
    r"|\b[A-Z][a-z]+(?:[A-Z][a-z]+){1,}\b"            # PascalCase (>= 2 segments)
)

_DOC_FILES = ("README.md", "SPEC.md", "ARCHITECTURE.md", "DESIGN.md", "INVARIANTS.md")


class SpecSkeptic(ThinkerBase):
    name = "spec_skeptic"

    def walk(self, state: AuditState) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        target = Path(getattr(state, "target_path", "."))

        # 1. Top-level docs
        for fname in _DOC_FILES:
            doc = target / fname
            if doc.exists():
                out.extend(self._scan_doc(doc, top_level=True))

        # subfolder docs (one level)
        for child in target.glob("*/"):
            for fname in _DOC_FILES:
                doc = child / fname
                if doc.exists():
                    out.extend(self._scan_doc(doc, top_level=False))

        # 2. Inline NatSpec / doc-comments on contracts
        for contract in state.contracts:
            doc = (getattr(contract, "documentation", "") or "").strip()
            if doc:
                out.extend(self._scan_text(
                    doc, source=f"{contract.name} (NatSpec)", contract=contract.name,
                ))
            for fn in getattr(contract, "functions", []) or []:
                fdoc = (getattr(fn, "documentation", "") or "").strip()
                if not fdoc:
                    continue
                out.extend(self._scan_text(
                    fdoc, source=f"{contract.name}.{fn.name} (NatSpec)",
                    contract=contract.name, function=fn.name,
                    line=getattr(fn, "line_start", 0),
                ))
        return out

    def _scan_doc(self, path: Path, top_level: bool) -> list[Hypothesis]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        return self._scan_text(text, source=str(path.name), contract="<docs>")

    def _scan_text(
        self,
        text: str,
        source: str,
        contract: str,
        function: str | None = None,
        line: int = 0,
    ) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        # one hypothesis per (sentence, claim-kind) pair, deduped by sentence+kind
        seen: set[tuple[str, str]] = set()
        # Pre-normalize NatSpec block prose: collapse leading `///`, `*`, and
        # internal newlines into spaces so multi-line claims like "Can only
        # be triggered by the other\nStandardBridge contract" are scanned as
        # a single sentence. Without this, sentence-splitting on `.!?` keeps
        # them broken across lines and the identifier-anchor check fails.
        normalized = re.sub(r"^\s*(?:///|\*|//)\s?", " ", text, flags=re.MULTILINE)
        normalized = re.sub(r"\s+", " ", normalized)
        for raw_sentence in re.split(r"(?<=[.!?])\s+", normalized):
            sentence = raw_sentence.strip()
            if not sentence or len(sentence) > 400:
                continue
            if _NOISE_MARKERS.search(sentence):
                continue
            if not _IDENTIFIER.search(sentence):
                # No code-anchorable identifier: skip.
                continue
            for pat, kind in _CLAIM_PATTERNS:
                if pat.search(sentence):
                    key = (sentence[:120].lower(), kind)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Hypothesis(
                        id=self._hid(f"sk-{kind}", contract, line),
                        thinker=self.name,
                        contract=contract,
                        function=function,
                        line_numbers=(line, line),
                        question=f"Does the code honor the {kind} claim in {source!r}: {sentence[:160]!r}?",
                        fragility=f"docs make a {kind} claim; code may diverge",
                        must_hold_property=sentence,
                        suggested_check=f"grep the relevant identifiers in {contract}; if README + git log -S over the symbol shows 2+ rewrites preserving the claim, divergence is intentional design (drop)",
                        confidence=0.55 if kind in ("formula", "rfc-mandate") else 0.45,
                        surface_tags=[f"claim:{kind}"],
                        metadata={"source": source, "sentence": sentence, "claim_kind": kind},
                    ))
                    break
        return out
