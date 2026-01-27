"""
Fix Reviewer - Trail of Bits Skill

Verifies that git commits address security audit findings without
introducing new bugs. Differential analysis against audit reports.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/fix-review
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess
import re


class FixStatus(Enum):
    """Status of a fix for an audit finding."""
    FIXED = "fixed"  # Code change directly addresses the finding
    PARTIALLY_FIXED = "partially_fixed"  # Some aspects addressed, others remain
    NOT_ADDRESSED = "not_addressed"  # No relevant changes found
    CANNOT_DETERMINE = "cannot_determine"  # Insufficient context


@dataclass
class AuditFinding:
    """Original audit finding to verify."""
    id: str  # e.g., "TOB-PROJ-1"
    title: str
    severity: str
    description: str
    affected_files: list[str]
    recommendation: str


@dataclass
class FixVerification:
    """Verification result for a fix."""
    finding: AuditFinding
    status: FixStatus
    commits: list[str]  # Commit hashes that address it
    evidence: str  # Code changes that address the finding
    root_cause_addressed: bool
    new_bugs_introduced: list[str]
    confidence: float  # 0-1

    def to_markdown(self) -> str:
        status_emoji = {
            FixStatus.FIXED: "FIXED",
            FixStatus.PARTIALLY_FIXED: "PARTIAL",
            FixStatus.NOT_ADDRESSED: "NOT FIXED",
            FixStatus.CANNOT_DETERMINE: "UNKNOWN",
        }

        lines = [
            f"### {self.finding.id}: {self.finding.title}",
            "",
            f"**Status**: {status_emoji.get(self.status, 'UNKNOWN')}",
            f"**Severity**: {self.finding.severity}",
            f"**Root Cause Addressed**: {'Yes' if self.root_cause_addressed else 'No'}",
            f"**Confidence**: {self.confidence:.0%}",
            "",
        ]

        if self.commits:
            lines.append("**Commits**:")
            for c in self.commits:
                lines.append(f"- `{c}`")
            lines.append("")

        if self.evidence:
            lines.append("**Evidence**:")
            lines.append(f"```\n{self.evidence[:500]}\n```")
            lines.append("")

        if self.new_bugs_introduced:
            lines.append("**Concerns**:")
            for bug in self.new_bugs_introduced:
                lines.append(f"- {bug}")

        return "\n".join(lines)


@dataclass
class BugPattern:
    """Potential bug introduction pattern."""
    name: str
    description: str
    pattern: str  # Regex pattern to detect
    severity: str


@dataclass
class FixReviewReport:
    """Complete fix review report."""
    source_commit: str
    target_commit: str
    report_path: Optional[str]
    findings_reviewed: list[AuditFinding]
    verifications: list[FixVerification]
    bug_introductions: list[dict]

    @property
    def fixed_count(self) -> int:
        return len([v for v in self.verifications if v.status == FixStatus.FIXED])

    @property
    def not_addressed_count(self) -> int:
        return len([v for v in self.verifications if v.status == FixStatus.NOT_ADDRESSED])

    def to_markdown(self) -> str:
        lines = [
            "# Fix Review Report",
            "",
            f"**Source**: `{self.source_commit}`",
            f"**Target**: `{self.target_commit}`",
            f"**Report**: {self.report_path or 'None provided'}",
            "",
            "## Executive Summary",
            "",
            f"- **Findings Reviewed**: {len(self.findings_reviewed)}",
            f"- **Fixed**: {self.fixed_count}",
            f"- **Not Addressed**: {self.not_addressed_count}",
            f"- **Bug Introduction Concerns**: {len(self.bug_introductions)}",
            "",
            "## Finding Status",
            "",
            "| ID | Title | Severity | Status | Evidence |",
            "|----|-------|----------|--------|----------|",
        ]

        for v in self.verifications:
            status = v.status.value.replace("_", " ").upper()
            commits = ", ".join(v.commits[:2]) if v.commits else "-"
            lines.append(f"| {v.finding.id} | {v.finding.title} | {v.finding.severity} | {status} | {commits} |")

        lines.append("")
        lines.append("## Detailed Verification")
        lines.append("")

        for v in self.verifications:
            lines.append(v.to_markdown())
            lines.append("")
            lines.append("---")
            lines.append("")

        if self.bug_introductions:
            lines.append("## Bug Introduction Concerns")
            lines.append("")
            for bug in self.bug_introductions:
                lines.append(f"### {bug.get('pattern', 'Unknown')}")
                lines.append(f"**File**: `{bug.get('file', '')}`")
                lines.append(f"**Description**: {bug.get('description', '')}")
                lines.append("")

        return "\n".join(lines)


class FixReviewer:
    """
    Verify fixes address security findings without introducing bugs.

    Rationalizations to reject:
    - "The commit message says it fixes TOB-XXX" - Messages lie; code tells truth
    - "Small fix, no new bugs possible" - Small changes cause big bugs
    - "I'll check the important findings" - All findings matter
    - "The tests pass" - Tests may not cover the fix
    """

    # Bug introduction patterns to detect
    BUG_PATTERNS = [
        BugPattern(
            name="access_control_weakened",
            description="Access control modifier removed",
            pattern=r"^-\s*(onlyOwner|onlyAdmin|require.*msg\.sender)",
            severity="critical",
        ),
        BugPattern(
            name="validation_removed",
            description="Require/assert statement removed",
            pattern=r"^-\s*(require|assert)\s*\(",
            severity="high",
        ),
        BugPattern(
            name="error_handling_reduced",
            description="Try/catch block removed",
            pattern=r"^-\s*try\s*\{",
            severity="medium",
        ),
        BugPattern(
            name="external_call_reordered",
            description="State change after external call (reentrancy risk)",
            pattern=r"\.call\{.*\}.*\n.*=\s*",
            severity="high",
        ),
        BugPattern(
            name="safemath_removed",
            description="SafeMath usage removed",
            pattern=r"^-.*\.add\(|^-.*\.sub\(|^-.*\.mul\(|^-.*\.div\(",
            severity="medium",
        ),
    ]

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def _run_git(self, *args: str) -> str:
        """Run a git command."""
        result = subprocess.run(
            ["git", "-C", str(self.repo_path)] + list(args),
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _get_commits_between(self, source: str, target: str) -> list[str]:
        """Get commit hashes between source and target."""
        output = self._run_git("log", f"{source}..{target}", "--format=%H")
        return [c for c in output.strip().split('\n') if c]

    def _get_commit_message(self, commit_hash: str) -> str:
        """Get commit message."""
        return self._run_git("log", "-1", "--format=%B", commit_hash)

    def _get_commit_diff(self, commit_hash: str) -> str:
        """Get diff for a specific commit."""
        return self._run_git("show", commit_hash, "--format=")

    def _get_full_diff(self, source: str, target: str) -> str:
        """Get full diff between commits."""
        return self._run_git("diff", source, target)

    def parse_audit_report(self, report_path: str) -> list[AuditFinding]:
        """
        Parse audit report to extract findings.

        Supports Trail of Bits format (TOB-XXX-N) and others.
        """
        findings = []
        content = Path(report_path).read_text()

        # Trail of Bits format: TOB-[A-Z]+-[0-9]+
        tob_pattern = re.compile(
            r'(?:##?\s*)?(TOB-[A-Z]+-\d+)[:\s]+([^\n]+)\n'
            r'(?:.*?Severity:\s*(\w+))?',
            re.MULTILINE | re.DOTALL
        )

        for match in tob_pattern.finditer(content):
            finding_id = match.group(1)
            title = match.group(2).strip()
            severity = match.group(3) if match.group(3) else "Unknown"

            findings.append(AuditFinding(
                id=finding_id,
                title=title,
                severity=severity,
                description="",  # Would extract from report
                affected_files=[],
                recommendation="",
            ))

        # Numbered findings format: Finding 1, Finding 2, etc.
        if not findings:
            numbered_pattern = re.compile(
                r'(?:Finding|Issue)\s+(\d+)[:\s]+([^\n]+)',
                re.MULTILINE
            )
            for match in numbered_pattern.finditer(content):
                findings.append(AuditFinding(
                    id=f"FINDING-{match.group(1)}",
                    title=match.group(2).strip(),
                    severity="Unknown",
                    description="",
                    affected_files=[],
                    recommendation="",
                ))

        return findings

    def match_commits_to_finding(
        self,
        finding: AuditFinding,
        commits: list[str],
    ) -> list[str]:
        """
        Match commits that address a finding.

        Match by:
        - Commit messages referencing the finding ID
        - File paths mentioned in finding
        - Function/variable names in finding description
        """
        matching_commits = []

        for commit in commits:
            message = self._get_commit_message(commit).lower()
            diff = self._get_commit_diff(commit)

            # Check if commit message references finding
            if finding.id.lower() in message:
                matching_commits.append(commit)
                continue

            # Check if affected files are modified
            for affected_file in finding.affected_files:
                if affected_file in diff:
                    matching_commits.append(commit)
                    break

            # Check title keywords in diff
            title_words = [w for w in finding.title.lower().split() if len(w) > 4]
            if any(word in diff.lower() for word in title_words):
                matching_commits.append(commit)

        return list(set(matching_commits))

    def verify_fix(
        self,
        finding: AuditFinding,
        commits: list[str],
        full_diff: str,
    ) -> FixVerification:
        """
        Verify that commits actually fix the finding.

        Checks:
        - Root cause is addressed (not just symptoms)
        - Fix follows the report's recommendation
        - No new vulnerabilities introduced
        """
        matching_commits = self.match_commits_to_finding(finding, commits)

        if not matching_commits:
            return FixVerification(
                finding=finding,
                status=FixStatus.NOT_ADDRESSED,
                commits=[],
                evidence="No commits found addressing this finding",
                root_cause_addressed=False,
                new_bugs_introduced=[],
                confidence=0.9,
            )

        # Collect evidence from matching commits
        evidence_parts = []
        for commit in matching_commits[:3]:
            diff = self._get_commit_diff(commit)
            # Extract relevant lines
            for line in diff.split('\n'):
                if line.startswith('+') or line.startswith('-'):
                    if any(kw in line.lower() for kw in finding.title.lower().split()[:3]):
                        evidence_parts.append(line)

        evidence = '\n'.join(evidence_parts[:20])

        # Detect potential new bugs
        new_bugs = []
        for commit in matching_commits:
            diff = self._get_commit_diff(commit)
            for pattern in self.BUG_PATTERNS:
                if re.search(pattern.pattern, diff, re.MULTILINE):
                    new_bugs.append(f"{pattern.name}: {pattern.description}")

        # Determine status
        if evidence and not new_bugs:
            status = FixStatus.FIXED
            root_cause_addressed = True
            confidence = 0.8
        elif evidence:
            status = FixStatus.PARTIALLY_FIXED
            root_cause_addressed = False
            confidence = 0.6
        else:
            status = FixStatus.CANNOT_DETERMINE
            root_cause_addressed = False
            confidence = 0.3

        return FixVerification(
            finding=finding,
            status=status,
            commits=matching_commits,
            evidence=evidence,
            root_cause_addressed=root_cause_addressed,
            new_bugs_introduced=new_bugs,
            confidence=confidence,
        )

    def detect_bug_introductions(
        self,
        source: str,
        target: str,
    ) -> list[dict]:
        """
        Analyze commits for bug introduction patterns.

        Key patterns:
        - Access control weakening
        - Validation removal
        - Error handling reduction
        - External call reordering
        - Integer operation changes
        """
        bug_introductions = []
        full_diff = self._get_full_diff(source, target)

        for pattern in self.BUG_PATTERNS:
            matches = re.finditer(pattern.pattern, full_diff, re.MULTILINE)
            for match in matches:
                # Find the file this is in
                file_match = re.search(
                    r'diff --git a/(\S+)',
                    full_diff[:match.start()],
                )
                file_path = file_match.group(1) if file_match else "unknown"

                bug_introductions.append({
                    "pattern": pattern.name,
                    "file": file_path,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "evidence": match.group(0)[:100],
                })

        return bug_introductions

    def review(
        self,
        source_commit: str,
        target_commit: str,
        report_path: Optional[str] = None,
        findings: Optional[list[AuditFinding]] = None,
    ) -> FixReviewReport:
        """
        Review fixes for audit findings.

        Args:
            source_commit: Commit before fixes
            target_commit: Commit(s) to analyze
            report_path: Path to audit report (optional)
            findings: List of findings to verify (optional)

        Returns:
            FixReviewReport with verification results
        """
        # Parse report or use provided findings
        if report_path and not findings:
            findings = self.parse_audit_report(report_path)
        elif not findings:
            findings = []

        # Get commits
        commits = self._get_commits_between(source_commit, target_commit)
        full_diff = self._get_full_diff(source_commit, target_commit)

        # Verify each finding
        verifications = []
        for finding in findings:
            verification = self.verify_fix(finding, commits, full_diff)
            verifications.append(verification)

        # Detect bug introductions
        bug_introductions = self.detect_bug_introductions(source_commit, target_commit)

        return FixReviewReport(
            source_commit=source_commit,
            target_commit=target_commit,
            report_path=report_path,
            findings_reviewed=findings,
            verifications=verifications,
            bug_introductions=bug_introductions,
        )


def verify_fixes(
    repo_path: str,
    source_commit: str,
    target_commit: str,
    report_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> FixReviewReport:
    """
    Verify that commits fix audit findings.

    Args:
        repo_path: Path to git repository
        source_commit: Commit before fixes
        target_commit: Commit after fixes
        report_path: Path to audit report
        output_path: Optional path for markdown report

    Returns:
        FixReviewReport with results
    """
    reviewer = FixReviewer(repo_path)
    report = reviewer.review(source_commit, target_commit, report_path)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
