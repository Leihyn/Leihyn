"""
Exemplar capture loop (Point 5).

Closes the feedback loop between submission outcomes and hunter prompts. The
recipe:

- Each accepted submission writes a structured record to
  knowledge_base/exemplars_accepted/{platform}/{program}/...json
- Each rejected submission writes to knowledge_base/exemplars_rejected/...
  with a structured rejection_reason field.
- Before a hunter or thinker fires on a new contest, we inject:
    - top-K most-similar accepted exemplars as positive few-shot
    - top-K most-similar rejected exemplars as NEGATIVE few-shot
      ("this shape looked filable on Reserve and wasn't")

Similarity is cheap-bag-of-words: surface-tag overlap + bug-class overlap +
language match. No embedding service needed; we deliberately avoid that
dependency until there's a year of data to make it worth the complexity.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


# Resolve knowledge_base path relative to the repo root. We don't import
# anything from src.core to keep this loadable from CLI without spinning up
# the orchestrator.
_REPO_ROOT = Path(__file__).resolve().parents[2]
KB_ROOT = _REPO_ROOT / "knowledge_base"
ACCEPTED_DIR = KB_ROOT / "exemplars_accepted"
REJECTED_DIR = KB_ROOT / "exemplars_rejected"


REJECTION_REASONS = (
    "documented-design",
    "default-state-missed",
    "dupe-of-public",
    "dupe-of-other-finding",
    "admin-recoverable",
    "out-of-scope",
    "no-impact",
    "unfileable-tier",
    "fixed-in-pr",
    "other",
)


@dataclass
class Exemplar:
    """A submission outcome captured for cross-contest learning."""
    title: str
    platform: str                          # cantina, immunefi, sherlock, code4rena, hackenproof, remedy
    program: str                           # protocol/program slug
    severity_filed: str
    severity_awarded: Optional[str] = None
    status: str = "accepted"               # accepted | rejected | duplicate | escalated
    rejection_reason: Optional[str] = None # one of REJECTION_REASONS

    # Surface
    surface_tags: list[str] = field(default_factory=list)
    bug_class: Optional[str] = None        # taxonomy bucket (denominator-pool, slippage, signature-replay, etc.)
    mental_operation: Optional[str] = None # which thinker would have surfaced it (value_flow, spec_skeptic, ...)
    language: str = "solidity"

    # Locus and rationale
    file_paths: list[str] = field(default_factory=list)
    summary: str = ""                      # one-paragraph human prose
    key_lesson: str = ""                   # the rule this contest taught us

    # Provenance
    contest_url: Optional[str] = None
    submission_url: Optional[str] = None
    captured_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_path(self, root: Path) -> Path:
        slug = re.sub(r"[^a-z0-9]+", "-", (self.platform + "-" + self.program + "-" + self.title).lower()).strip("-")[:80]
        sub = root / self.platform / self.program
        sub.mkdir(parents=True, exist_ok=True)
        return sub / f"{slug}.json"


def write_exemplar(ex: Exemplar) -> Path:
    if ex.status == "accepted":
        root = ACCEPTED_DIR
    elif ex.status in ("rejected", "duplicate"):
        root = REJECTED_DIR
    elif ex.status == "escalated":
        root = ACCEPTED_DIR              # treat escalations as positive signal
    else:
        root = REJECTED_DIR
    if ex.status == "rejected" and ex.rejection_reason not in (None, *REJECTION_REASONS):
        ex.rejection_reason = "other"
    path = ex.to_path(root)
    path.write_text(json.dumps(asdict(ex), indent=2))
    return path


def load_all(root: Path) -> list[Exemplar]:
    if not root.exists():
        return []
    out: list[Exemplar] = []
    for p in root.rglob("*.json"):
        try:
            data = json.loads(p.read_text())
            out.append(Exemplar(**data))
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    return out


def load_accepted() -> list[Exemplar]:
    return load_all(ACCEPTED_DIR)


def load_rejected() -> list[Exemplar]:
    return load_all(REJECTED_DIR)


def _score(target_tags: set[str], target_lang: str, exemplar: Exemplar) -> float:
    tag_overlap = len(set(exemplar.surface_tags) & target_tags)
    lang_match = 1.0 if exemplar.language.lower() == target_lang.lower() else 0.0
    bug_class_bonus = 0.5 if exemplar.bug_class else 0.0
    return tag_overlap + lang_match + bug_class_bonus


def topk(
    candidates: list[Exemplar],
    target_tags: Iterable[str],
    target_lang: str = "solidity",
    k: int = 5,
) -> list[Exemplar]:
    target_tags_set = set(target_tags)
    if not candidates:
        return []
    ranked = sorted(
        candidates,
        key=lambda ex: _score(target_tags_set, target_lang, ex),
        reverse=True,
    )
    return [ex for ex in ranked if _score(target_tags_set, target_lang, ex) > 0][:k]


def render_few_shot_block(positive: list[Exemplar], negative: list[Exemplar]) -> str:
    """Render an injection-ready text block: positive then negative examples."""
    lines: list[str] = []
    if positive:
        lines.append("# ACCEPTED EXEMPLARS (positive few-shot)")
        lines.append("# Bugs of this surface that have been awarded payouts.")
        for ex in positive:
            lines.append(f"\n## {ex.title}  [{ex.platform}/{ex.program}, {ex.severity_awarded or ex.severity_filed}]")
            if ex.bug_class:
                lines.append(f"bug-class: {ex.bug_class}")
            if ex.mental_operation:
                lines.append(f"surfaced-by: {ex.mental_operation}")
            if ex.summary:
                lines.append(ex.summary)
            if ex.key_lesson:
                lines.append(f"lesson: {ex.key_lesson}")
    if negative:
        lines.append("\n# REJECTED EXEMPLARS (negative few-shot)")
        lines.append("# Bugs of THIS shape that LOOKED filable but were dismissed.")
        lines.append("# Do NOT propose findings of this shape unless evidence overcomes the rejection reason.")
        for ex in negative:
            reason = ex.rejection_reason or "other"
            lines.append(f"\n## {ex.title}  [{ex.platform}/{ex.program}, REJECTED: {reason}]")
            if ex.bug_class:
                lines.append(f"bug-class: {ex.bug_class}")
            if ex.summary:
                lines.append(ex.summary)
            if ex.key_lesson:
                lines.append(f"lesson: {ex.key_lesson}")
    return "\n".join(lines)


def build_few_shot_for(
    target_tags: Iterable[str],
    target_lang: str = "solidity",
    k_pos: int = 5,
    k_neg: int = 5,
) -> str:
    pos = topk(load_accepted(), target_tags, target_lang, k=k_pos)
    neg = topk(load_rejected(), target_tags, target_lang, k=k_neg)
    return render_few_shot_block(pos, neg)


def stats() -> dict:
    acc = load_accepted()
    rej = load_rejected()
    by_reason: dict[str, int] = {}
    for ex in rej:
        key = ex.rejection_reason or "unspecified"
        by_reason[key] = by_reason.get(key, 0) + 1
    return {
        "accepted_count": len(acc),
        "rejected_count": len(rej),
        "rejection_reasons": by_reason,
        "platforms": sorted({ex.platform for ex in acc + rej}),
    }
