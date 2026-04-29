"""
Audit intel: detect prior audit reports + extract their findings so hunters
can DEDUPE instead of re-reporting issues the team has already paid for.

Pipeline:
1. detect_audit_reports(target_path) - find /audits/, *.pdf with audit-related names
2. extract_known_findings(report_path) - PDF or markdown -> list[KnownFinding]
3. Orchestrator stores result on state.known_findings, hunters inject via
   state.get_known_findings_prompt() into their system prompt.

PDF parsing uses the system `pdftotext` binary (Poppler). Falls back gracefully
if absent — audit_intel is best-effort, not a hard requirement.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from .types import KnownFinding


# Common audit-report dir names checked under target_path
AUDIT_DIR_NAMES = (
    "audits",
    "audit",
    "audit-reports",
    "security",
    "reviews",
)


# Filename hints that suggest a file is an audit report
AUDIT_FILENAME_HINTS = (
    "audit",
    "review",
    "ottersec",
    "halborn",
    "trailofbits",
    "trail_of_bits",
    "tob",
    "adevar",
    "spearbit",
    "consensys",
    "openzeppelin",
    "certora",
    "sigma_prime",
    "sigmaprime",
    "asymmetric",
    "ackee",
    "zellic",
    "macro",
    "cantina",
    "code4rena",
    "sherlock",
)


def detect_audit_reports(target_path: Path) -> tuple[Path | None, list[Path]]:
    """Find the audit dir and all audit-report files (PDF/MD) inside the target.

    Returns (audit_dir, list_of_report_paths). audit_dir is None if no
    canonical audit directory is found.
    """
    target_path = Path(target_path).resolve()
    audit_dir: Path | None = None
    for name in AUDIT_DIR_NAMES:
        candidate = target_path / name
        if candidate.is_dir():
            audit_dir = candidate
            break

    reports: list[Path] = []
    if audit_dir:
        for ext in ("*.pdf", "*.md", "*.markdown"):
            reports.extend(sorted(audit_dir.rglob(ext)))

    # Also scan target root for stray audit files (small repos sometimes drop
    # the PDF at the top level instead of in /audits)
    for ext in ("*.pdf", "*.md"):
        for p in target_path.glob(ext):
            if any(hint in p.name.lower() for hint in AUDIT_FILENAME_HINTS):
                if p not in reports:
                    reports.append(p)

    return audit_dir, reports


def _pdf_to_text(pdf_path: Path) -> str:
    """Extract text from a PDF via the system `pdftotext` binary.

    Returns empty string if pdftotext is missing or extraction fails.
    """
    if not shutil.which("pdftotext"):
        return ""
    try:
        # `-layout` preserves table structure which helps regex-matching
        # finding tables. `-` writes to stdout.
        result = subprocess.run(
            ["pdftotext", "-layout", str(pdf_path), "-"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return ""


# Regex patterns for typical audit-report finding IDs.
# Each pattern captures (id, title) where title is the rest of the line.
FINDING_PATTERNS = [
    # Adevar/Halborn/typical: "L01: Title", "M02: Title", "H03: Title", "C01: Title"
    # also "L-01" / "M-1" forms
    re.compile(
        r"^\s*([CHMLI](?:RIT|IGH|ED|OW|NF)?[\- ]?\d{1,3})[:\.\)]\s+(.+?)$",
        re.MULTILINE,
    ),
    # Trail of Bits: "TOB-XXXX-1: Title"
    re.compile(r"^\s*(TOB-[A-Z0-9]+-\d+)[:\s]+(.+?)$", re.MULTILINE),
    # OtterSec: "OS-PROTO-ADV-01: Title", "OS-XYZ-MED-02"
    re.compile(r"^\s*(OS-[A-Z0-9\-]+-\d+)[:\s]+(.+?)$", re.MULTILINE),
    # Generic numbered: "Finding 1: Title"
    re.compile(r"^\s*Finding\s+(\d+)[:\.\)]\s+(.+?)$", re.MULTILINE | re.IGNORECASE),
    # Bracketed: "[L-01]: Title"
    re.compile(r"^\s*\[([CHMLI][\- ]?\d{1,3})\][:\s]+(.+?)$", re.MULTILINE),
]


# Severity keywords that often precede/follow a finding ID
SEVERITY_PATTERNS = [
    (re.compile(r"\b(critical)\b", re.IGNORECASE), "Critical"),
    (re.compile(r"\b(high)\b", re.IGNORECASE), "High"),
    (re.compile(r"\b(medium|med)\b", re.IGNORECASE), "Medium"),
    (re.compile(r"\b(low)\b", re.IGNORECASE), "Low"),
    (re.compile(r"\b(informational|info)\b", re.IGNORECASE), "Informational"),
]


# Status keywords near a finding
STATUS_PATTERNS = [
    (re.compile(r"\bResolved\b", re.IGNORECASE), "Resolved"),
    (re.compile(r"\bFixed\b", re.IGNORECASE), "Fixed"),
    (re.compile(r"\bAcknowledged\b", re.IGNORECASE), "Acknowledged"),
    (re.compile(r"\bMitigated\b", re.IGNORECASE), "Mitigated"),
    (re.compile(r"\bAddressed\b", re.IGNORECASE), "Addressed"),
    (re.compile(r"\bWill\s+fix\b", re.IGNORECASE), "Pending Fix"),
]


def _infer_severity(id_: str, surrounding_text: str) -> str:
    """Infer severity from the finding ID prefix or surrounding text."""
    upper = id_.upper().lstrip("[")
    if upper.startswith("C"):
        return "Critical"
    if upper.startswith("H"):
        return "High"
    if upper.startswith("M"):
        return "Medium"
    if upper.startswith("L"):
        return "Low"
    if upper.startswith("I"):
        return "Informational"
    for pat, sev in SEVERITY_PATTERNS:
        if pat.search(surrounding_text):
            return sev
    return ""


def _infer_status(surrounding_text: str) -> str:
    """Infer fix status from text near the finding."""
    for pat, status in STATUS_PATTERNS:
        if pat.search(surrounding_text):
            return status
    return ""


def _looks_like_real_finding_title(title: str) -> bool:
    """Filter out noise: TOC entries, page numbers, common false positives."""
    title = title.strip()
    if len(title) < 8 or len(title) > 240:
        return False
    # Reject pure page numbers / dotted leaders ("...... 12")
    if re.match(r"^[\.\s\d/]+$", title):
        return False
    # Reject lines that are clearly TOC dotted leaders
    if title.count(".") > 6:
        return False
    return True


# Trailing junk patterns to strip from extracted titles:
# - dotted leaders ("...... 12"), trailing page numbers ("Title    12"),
#   pipe-separated table cells ("| Title | 6"), trailing pipes
_TRAILING_JUNK = re.compile(
    r"(?:"
    r"\s*\|\s*\d+\s*$"               # "| 6"
    r"|\s+\d{1,3}\s*$"               # "Title   12"
    r"|\s*\.{3,}.*$"                 # ".... 12"
    r"|\s*\|\s*$"                    # trailing pipe
    r")+",
)


def _clean_title(title: str) -> str:
    """Strip TOC artifacts: trailing page numbers, dot leaders, table pipes."""
    title = title.strip()
    title = _TRAILING_JUNK.sub("", title).strip()
    # Collapse runs of whitespace
    title = re.sub(r"\s{2,}", " ", title)
    # Strip leading "| " from table-format extractions
    title = title.lstrip("| ").strip()
    return title


def _extract_findings_from_text(text: str, source: str) -> list[KnownFinding]:
    """Apply finding patterns to extracted text, dedupe by id."""
    seen_ids: set[str] = set()
    findings: list[KnownFinding] = []

    for pattern in FINDING_PATTERNS:
        for match in pattern.finditer(text):
            raw_id = match.group(1).strip().upper().replace(" ", "")
            # Normalize "L-01" → "L01"
            normalized = raw_id.replace("-", "")
            if normalized in seen_ids:
                continue
            title = _clean_title(match.group(2))
            if not _looks_like_real_finding_title(title):
                continue

            # Grab a wider window of surrounding text for severity/status
            # inference. Status badges in PDF tables can be far from the title
            # in pdftotext output, especially with -layout where columns split.
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 2000)
            window = text[start:end]

            findings.append(
                KnownFinding(
                    id=normalized,
                    title=title,
                    severity=_infer_severity(normalized, window),
                    status=_infer_status(window),
                    source=source,
                )
            )
            seen_ids.add(normalized)

    return findings


def extract_known_findings(report_path: Path) -> list[KnownFinding]:
    """Extract findings from a single audit report (PDF or markdown)."""
    report_path = Path(report_path)
    suffix = report_path.suffix.lower()

    if suffix == ".pdf":
        text = _pdf_to_text(report_path)
    elif suffix in (".md", ".markdown", ".txt"):
        try:
            text = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    else:
        return []

    if not text.strip():
        return []

    return _extract_findings_from_text(text, source=str(report_path.name))


def extract_all_known_findings(reports: Iterable[Path]) -> list[KnownFinding]:
    """Extract findings from every report, deduping by (id, title-prefix).

    Different audits often use the same prefix ("L01") for unrelated findings.
    We dedupe on (id, title-prefix) rather than id alone to avoid collisions.
    """
    seen: set[tuple[str, str]] = set()
    out: list[KnownFinding] = []
    for report in reports:
        for kf in extract_known_findings(report):
            key = (kf.id, kf.title[:60].lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(kf)
    return out


def _run_git(target_path: Path, *args: str, timeout: int = 15) -> str:
    """Run a git command in the target repo, return stdout (empty on failure)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(target_path), *args],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _commit_when_added(target_path: Path, file_path: Path) -> str | None:
    """Find the SHA of the commit that ADDED a tracked file (--diff-filter=A).

    Returns the commit hash (short form) or None if not tracked / not in git.
    """
    rel = file_path.relative_to(target_path) if file_path.is_absolute() else file_path
    out = _run_git(
        target_path,
        "log",
        "--diff-filter=A",
        "--follow",
        "--pretty=format:%H",
        "--",
        str(rel),
    )
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines:
        return None
    # The last entry is the original add (oldest), most recent is first.
    # Use most-recent-add to be robust against renames + re-adds.
    return lines[0]


def detect_post_audit_changes(
    target_path: Path,
    reports: list[Path],
) -> list[str]:
    """Identify files modified AFTER the most-recent audit report was committed.

    Strategy (git-based, robust to fresh clones):
    1. For each audit report, find the commit that ADDED it (`--diff-filter=A`)
    2. Pick the MOST RECENT of those add-commits as the audit cutoff
    3. List files changed in commits AFTER that cutoff

    Falls back to mtime-based detection when git is unavailable or the audit
    files are untracked.

    Returns a list of repo-relative file paths (most recently changed first).
    """
    if not reports:
        return []
    target_path = Path(target_path).resolve()
    if not (target_path / ".git").exists():
        return []

    # Step 1+2: find the most recent commit that added an audit report.
    # We use `git log -1` against each report and pick the latest by date.
    latest_cutoff_commit: str | None = None
    latest_cutoff_ts: int = 0
    for report in reports:
        sha = _commit_when_added(target_path, report)
        if not sha:
            continue
        ts_out = _run_git(target_path, "show", "-s", "--format=%ct", sha).strip()
        try:
            ts = int(ts_out)
        except ValueError:
            continue
        if ts > latest_cutoff_ts:
            latest_cutoff_ts = ts
            latest_cutoff_commit = sha

    if latest_cutoff_commit:
        # Step 3: files changed since cutoff (exclusive)
        out = _run_git(
            target_path,
            "log",
            f"{latest_cutoff_commit}..HEAD",
            "--name-only",
            "--pretty=format:",
        )
    else:
        # Fallback: mtime-based heuristic for untracked audits or shallow clones
        from datetime import datetime
        latest_audit_mtime = max(r.stat().st_mtime for r in reports)
        since = datetime.fromtimestamp(latest_audit_mtime).isoformat()
        out = _run_git(
            target_path, "log", f"--since={since}", "--name-only",
            "--pretty=format:",
        )

    files = [line.strip() for line in out.splitlines() if line.strip()]
    seen: set[str] = set()
    deduped: list[str] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped


def enumerate_github_known_issues(target_path: Path) -> list[KnownFinding]:
    """Pre-bounty git enumeration: list all GitHub issues + recently-merged PRs
    referencing fixes/security/audit topics. Treats them as known-issues so
    hunters don't waste cycles re-reporting things already filed by the team.

    Per the contest pre-filter rule: protocols dump their own known-issue lists
    in the 48h before bounty/contest start, often as GitHub issues. Enumerating
    them up front avoids burning hours on duplicates.

    Requires `gh` CLI to be available and authenticated. Returns empty list
    when `gh` is missing, the target isn't a GitHub-remoted repo, or auth fails.
    """
    target_path = Path(target_path).resolve()
    if not (target_path / ".git").exists() or not shutil.which("gh"):
        return []

    # Get the GitHub remote (owner/repo)
    remote = _run_git(target_path, "config", "--get", "remote.origin.url").strip()
    repo = _parse_github_repo_from_remote(remote)
    if not repo:
        return []

    findings: list[KnownFinding] = []

    # 1) ALL issues, any state. Even closed issues are valuable dedupe signal:
    #    "we already considered this" or "fixed".
    issues_json = _run_subprocess([
        "gh", "issue", "list", "--repo", repo, "--state", "all",
        "--limit", "100", "--json", "number,title,state,labels",
    ], cwd=target_path)
    if issues_json:
        try:
            import json
            for issue in json.loads(issues_json):
                title = issue.get("title", "").strip()
                if not title:
                    continue
                state = issue.get("state", "")
                findings.append(
                    KnownFinding(
                        id=f"#{issue['number']}",
                        title=title,
                        severity="",
                        status=state,
                        source=f"github:{repo} issue",
                    )
                )
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # 2) Recently-merged PRs (last 30) — title hints at what's been fixed.
    #    Fix PRs are strong signals: bugs that already shipped fixes are
    #    in the codebase but no longer findings.
    prs_json = _run_subprocess([
        "gh", "pr", "list", "--repo", repo, "--state", "merged",
        "--limit", "30", "--json", "number,title,mergedAt",
    ], cwd=target_path)
    if prs_json:
        try:
            import json
            for pr in json.loads(prs_json):
                title = pr.get("title", "").strip()
                if not title:
                    continue
                # Only include PRs that look fix-shaped
                lower = title.lower()
                if not any(kw in lower for kw in (
                    "fix", "patch", "audit", "security", "vuln",
                    "remediat", "bug", "exploit",
                )):
                    continue
                findings.append(
                    KnownFinding(
                        id=f"PR#{pr['number']}",
                        title=title,
                        severity="",
                        status="Merged",
                        source=f"github:{repo} pr",
                    )
                )
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    return findings


def _parse_github_repo_from_remote(remote_url: str) -> str | None:
    """Extract 'owner/repo' from a git remote URL (HTTPS or SSH)."""
    if not remote_url:
        return None
    # https://github.com/owner/repo.git or git@github.com:owner/repo.git
    m = re.search(r"github\.com[:/]([^/]+)/([^/.\s]+?)(?:\.git)?$", remote_url.strip())
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def _run_subprocess(args: list[str], cwd: Path, timeout: int = 30) -> str:
    """Run a subprocess with timeout; return stdout or empty string."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd),
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return ""


def load_audit_intel(
    target_path: Path,
    enumerate_github: bool = True,
) -> tuple[Path | None, list[KnownFinding], list[str]]:
    """One-shot loader: detect reports, extract findings, find post-audit changes,
    and (optionally) enumerate GitHub issues+PRs as additional dedupe signal.

    Used by the orchestrator's run_phase_audit_intel. Returns
    (audit_dir, known_findings, priority_files).
    """
    audit_dir, reports = detect_audit_reports(target_path)
    findings = extract_all_known_findings(reports)
    priority = detect_post_audit_changes(target_path, reports)

    if enumerate_github:
        gh_findings = enumerate_github_known_issues(target_path)
        # Dedupe: don't add github items whose title matches an existing audit finding
        existing_titles = {kf.title[:60].lower() for kf in findings}
        for gf in gh_findings:
            if gf.title[:60].lower() not in existing_titles:
                findings.append(gf)

    return audit_dir, findings, priority
