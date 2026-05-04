"""
Deterministic FP gate (Point 2 of the Sentinel improvement plan).

Four hard checks fire on every candidate finding before it reaches the
report writer. None require an LLM. Each one maps to a real dismissal
pattern in the bounty corpus (memory: feedback_submission_discipline.md):

1. documented_intent  -- README/SPEC/NatSpec or git-log shows the divergent
                         behavior is intentional design (Reserve M-02, F-12).
2. active_iteration   -- public PR/issue active on the symbol within the
                         contest window: file IMMEDIATELY (F-24 lesson) but
                         attach the PR# so triagers see independent discovery.
3. default_state      -- "default value is X, therefore bug" findings must
                         enumerate ALL write sites including constructor,
                         initialize, addX, factory (Dexalot M-01).
4. runnable_poc       -- finding without a Foundry-fork PoC or equivalent
                         is demoted to QA tier.

The gate is a function from `list[Finding] -> GateReport`. It mutates findings
in-place by setting metadata['fp_gate'] and `false_positive` / severity tags.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .types import Finding, Severity


# Documented-intent vocabulary: phrases that, when found near a finding's
# code locus in README/SPEC/NatSpec, indicate the divergent behavior is the
# protocol's design intent.
_INTENT_PHRASES = [
    "by design", "intentional", "intentionally", "documented", "see readme",
    "transition table", "as specified", "per spec", "this is expected",
    "wider than", "looser than", "stricter than", "deviation from",
    "trusted internal", "trust boundary", "skip signature verification",
]


@dataclass
class GateCheckResult:
    name: str
    passed: bool                           # True = no FP signal raised
    evidence: str = ""
    drop_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "evidence": self.evidence[:600],
            "drop_reason": self.drop_reason,
        }


@dataclass
class GateReport:
    finding_id: str
    checks: list[GateCheckResult] = field(default_factory=list)
    final_verdict: str = "PASS"            # PASS / DEMOTE / DROP
    severity_change: Optional[str] = None  # e.g. "Medium -> Low"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "checks": [c.to_dict() for c in self.checks],
            "final_verdict": self.final_verdict,
            "severity_change": self.severity_change,
            "notes": self.notes,
        }


def _read_text(p: Path) -> str:
    try:
        return p.read_text(errors="ignore")
    except OSError:
        return ""


def _grep_target_docs(target: Path, needle: str) -> list[tuple[Path, int, str]]:
    """Cheap recursive grep across docs at the target. Returns (path, line, snippet)."""
    if not needle or len(needle) > 80:
        return []
    out: list[tuple[Path, int, str]] = []
    pattern = re.compile(r"\b" + re.escape(needle) + r"\b", re.IGNORECASE)
    candidates: list[Path] = []
    for ext in ("md", "MD", "rst", "txt"):
        candidates.extend(target.rglob(f"*.{ext}"))
    for path in candidates[:200]:
        try:
            for i, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
                if pattern.search(line):
                    out.append((path, i, line.strip()[:200]))
                    if len(out) > 30:
                        return out
        except OSError:
            continue
    return out


def _looks_like_symbol(word: str) -> bool:
    """Identifier-ish words only: must contain underscore or internal capital,
    OR be a clearly non-English token. Filters out generic English ("lacks",
    "validation", "intended") that would otherwise match random doc text.
    """
    if not word or len(word) < 5:
        return False
    if "_" in word:
        return True
    if any(c.isupper() for c in word[1:]):           # camelCase
        return True
    return False


def _git_log_for_symbol(target: Path, symbol: str, since: str = "1.year.ago") -> list[str]:
    if not symbol or len(symbol) > 80:
        return []
    if not (target / ".git").exists():
        return []
    try:
        proc = subprocess.run(
            ["git", "log", f"--since={since}", "--pretty=%H %s", "-S", symbol],
            cwd=str(target), capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()][:20]


def _gh_search(target: Path, symbol: str) -> list[str]:
    """Active-iteration probe: gh issue/pr list with symbol as keyword."""
    if not shutil.which("gh") or not symbol or len(symbol) > 60:
        return []
    out: list[str] = []
    for kind in ("issue", "pr"):
        try:
            proc = subprocess.run(
                ["gh", kind, "list", "--state", "all", "--search", symbol,
                 "--json", "number,title,state,updatedAt,url",
                 "--limit", "10"],
                cwd=str(target), capture_output=True, text=True, timeout=20,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
        if proc.returncode != 0:
            continue
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            continue
        for row in rows:
            out.append(
                f"{kind} #{row.get('number')} [{row.get('state')}] {row.get('title','')[:80]} "
                f"({row.get('updatedAt','')}) {row.get('url','')}"
            )
    return out


def _check_documented_intent(target: Path, finding: Finding) -> GateCheckResult:
    """Pass if no documented-intent phrase appears near the finding's symbols.

    "Near" means SAME LINE as the symbol — co-occurrence on a line is the
    only signal cheap enough to compute and specific enough to avoid the
    false-positive observed on Base Azul (generic English title words like
    "validation" matching unrelated paragraphs that happened to contain
    "intended"). Identifier-ish words only; English filler is filtered.
    """
    symbols: list[str] = []
    if finding.function and _looks_like_symbol(finding.function):
        symbols.append(finding.function)
    if finding.contract and _looks_like_symbol(finding.contract):
        symbols.append(finding.contract)
    for w in re.findall(r"[A-Za-z_][A-Za-z_0-9]{4,}", finding.title):
        if _looks_like_symbol(w) and w not in symbols:
            symbols.append(w)
        if len(symbols) >= 5:
            break

    if not symbols:
        return GateCheckResult(
            name="documented_intent", passed=True,
            evidence="no identifier-shaped symbols extractable from finding; check skipped",
        )

    hits: list[str] = []
    for sym in symbols:
        for path, line, snippet in _grep_target_docs(target, sym):
            low = snippet.lower()
            if any(p in low for p in _INTENT_PHRASES):
                hits.append(f"{path.name}:{line}  symbol={sym!r}  {snippet}")
        log = _git_log_for_symbol(target, sym)
        if len(log) >= 3:
            hits.append(f"git: {len(log)} commits touch `{sym}` (history suggests iteration on documented design)")

    if hits:
        return GateCheckResult(
            name="documented_intent", passed=False,
            evidence="\n".join(hits[:8]),
            drop_reason=(
                "documented design intent: README/NatSpec or git history indicates the divergent "
                "behavior is intentional. Per Reserve-M-02 and F-12 lessons, do NOT file."
            ),
        )
    return GateCheckResult(name="documented_intent", passed=True)


def _check_active_iteration(target: Path, finding: Finding) -> GateCheckResult:
    """Surface (don't fail) any open/recent PR or issue on the symbol.

    The F-24 lesson: a public PR landing on the same surface during the
    contest window means file IMMEDIATELY with the PR# attached. We do not
    drop on a hit; we tag the finding with the matches so the report writer
    can include them.
    """
    symbols: list[str] = []
    if finding.function:
        symbols.append(finding.function)
    title_words = re.findall(r"[A-Za-z_][A-Za-z_0-9]{6,}", finding.title)
    symbols.extend(title_words[:2])

    matches: list[str] = []
    for sym in symbols:
        matches.extend(_gh_search(target, sym))

    if matches:
        return GateCheckResult(
            name="active_iteration",
            passed=True,                       # informational, never drops
            evidence="\n".join(matches[:10]),
            drop_reason="",
        )
    return GateCheckResult(name="active_iteration", passed=True, evidence="no public PR/issue found")


def _check_default_state(target: Path, finding: Finding) -> GateCheckResult:
    """For any finding whose narrative says "default is X, therefore bug",
    enumerate ALL writers of the storage variable. If a non-zero / non-default
    write exists in constructor/initialize/factory/addX, the finding is FP.
    """
    text = (finding.description + "\n" + finding.title + "\n" + finding.root_cause).lower()
    triggers = ("default is", "default value", "uninitialized", "zero by default",
                "default = 0", "starts at zero", "starts at 0")
    if not any(t in text for t in triggers):
        return GateCheckResult(name="default_state", passed=True, evidence="not a default-state claim")

    # Try to extract the variable name from the finding metadata or root_cause.
    var = (finding.metadata or {}).get("var") if isinstance(finding.metadata, dict) else None
    if not var:
        m = re.search(r"\b([a-z_][a-zA-Z_0-9]{3,})\s*(?:is|defaults to|starts at)", text)
        if m:
            var = m.group(1)
    if not var:
        return GateCheckResult(
            name="default_state", passed=True,
            evidence="default-state finding lacked a parseable variable name; leaving for human review",
        )

    write_pat = re.compile(
        rf"\b{re.escape(var)}\s*(?:\[[^\]]+\])?\s*=\s*([^;]+);", re.IGNORECASE,
    )
    init_writes: list[str] = []
    for sol in target.rglob("*.sol"):
        body = _read_text(sol)
        if not body:
            continue
        for m in write_pat.finditer(body):
            rhs = m.group(1).strip()
            if rhs in ("0", "false", "address(0)", "bytes32(0)"):
                continue
            line = body.count("\n", 0, m.start()) + 1
            ctx_start = max(0, m.start() - 200)
            ctx = body[ctx_start:m.start()].lower()
            if any(k in ctx for k in ("constructor", "initialize", "function add", "factory", "deploy")):
                init_writes.append(f"{sol.name}:{line}  {var} = {rhs[:60]}")

    if init_writes:
        return GateCheckResult(
            name="default_state", passed=False,
            evidence="\n".join(init_writes[:6]),
            drop_reason=(
                "non-zero default exists in constructor/initialize/factory; the only triggering case "
                "is an explicit set-to-zero. Severity is Low at best (Dexalot M-01 lesson)."
            ),
        )
    return GateCheckResult(name="default_state", passed=True, evidence="no init-time writers found; finding stands")


def _check_runnable_poc(target: Path, finding: Finding) -> GateCheckResult:
    """Pass if the finding has an attached PoC that has been executed
    successfully. Otherwise demote High/Critical to Medium and Medium to Low.
    """
    poc = getattr(finding, "poc", None)
    if poc and getattr(poc, "executed", False) and getattr(poc, "success", False):
        return GateCheckResult(
            name="runnable_poc", passed=True,
            evidence=f"PoC executed; profit={getattr(poc, 'profit', None)}",
        )
    if poc and getattr(poc, "code", "").strip():
        return GateCheckResult(
            name="runnable_poc", passed=False,
            evidence="PoC attached but not executed/successful",
            drop_reason="PoC present but did not pass; demote one severity tier",
        )
    return GateCheckResult(
        name="runnable_poc", passed=False,
        evidence="no PoC attached",
        drop_reason="no runnable PoC; demote one severity tier (QA at most for unprovable claims)",
    )


_DEMOTE_MAP = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


def run_fp_gate(
    findings: list[Finding],
    target: Path,
    require_poc_above: Severity = Severity.MEDIUM,
) -> list[GateReport]:
    """Run all four checks on every finding and tag in-place.

    Args:
        findings: live AuditState.findings list (mutated in-place).
        target: project root (for grep + git + gh).
        require_poc_above: severities at or above this require a runnable PoC.
                           Default = MEDIUM (so Medium and above must have a PoC
                           or get demoted).

    Returns:
        per-finding GateReport.
    """
    reports: list[GateReport] = []
    for f in findings:
        rep = GateReport(finding_id=f.id)
        intent = _check_documented_intent(target, f)
        active = _check_active_iteration(target, f)
        defstate = _check_default_state(target, f)
        rep.checks.extend([intent, active, defstate])

        if intent.evidence and not intent.passed:
            f.false_positive = True
            rep.final_verdict = "DROP"
            rep.notes.append(intent.drop_reason)

        if active.evidence and "issue #" in active.evidence or "pr #" in active.evidence:
            (f.metadata or {}).setdefault("fp_gate_pr_matches", active.evidence)
            rep.notes.append(
                "active public iteration detected; file IMMEDIATELY and attach the PR/issue numbers"
            )

        if not defstate.passed:
            f.false_positive = True
            rep.final_verdict = "DROP"
            rep.notes.append(defstate.drop_reason)

        # PoC check is gating only if severity warrants it.
        if rep.final_verdict != "DROP" and _severity_value(f.severity) >= _severity_value(require_poc_above):
            poc = _check_runnable_poc(target, f)
            rep.checks.append(poc)
            if not poc.passed:
                old = f.severity
                f.severity = _DEMOTE_MAP.get(f.severity, f.severity)
                rep.final_verdict = "DEMOTE"
                rep.severity_change = f"{old.value} -> {f.severity.value}"
                rep.notes.append(poc.drop_reason)

        # Stash the report on the finding so the report writer can render it.
        if isinstance(f.metadata, dict):
            f.metadata["fp_gate"] = rep.to_dict()
        reports.append(rep)
    return reports


def _severity_value(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFORMATIONAL: 0,
    }.get(sev, 0)


def write_gate_summary(reports: list[GateReport], out: Path) -> None:
    """Persist a JSONL gate summary next to the audit report."""
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for r in reports:
            fh.write(json.dumps(r.to_dict()) + "\n")
