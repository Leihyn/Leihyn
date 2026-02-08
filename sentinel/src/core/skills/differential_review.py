"""
Differential Review - Trail of Bits Skill

Security-focused differential review of code changes (PRs, commits, diffs).
Adapts analysis depth to codebase size, uses git history for context.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/differential-review
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess
import re


class RiskLevel(Enum):
    """Risk level for code changes."""
    HIGH = "high"  # Auth, crypto, external calls, value transfer
    MEDIUM = "medium"  # Business logic, state changes, new APIs
    LOW = "low"  # Comments, tests, UI, logging


class CodebaseSize(Enum):
    """Codebase size classification."""
    SMALL = "small"  # <20 files - DEEP analysis
    MEDIUM = "medium"  # 20-200 files - FOCUSED analysis
    LARGE = "large"  # 200+ files - SURGICAL analysis


class FindingSeverity(Enum):
    """Security finding severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeChange:
    """Represents a code change."""
    file_path: str
    old_content: Optional[str]
    new_content: Optional[str]
    diff: str
    added_lines: list[int] = field(default_factory=list)
    removed_lines: list[int] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class ReviewFinding:
    """Security finding from differential review."""
    title: str
    severity: FindingSeverity
    file_path: str
    line_numbers: list[int]
    description: str
    attack_scenario: str
    evidence: str
    recommendation: str
    commit_hash: Optional[str] = None

    def to_markdown(self) -> str:
        lines = [
            f"## [{self.severity.value.upper()}] {self.title}",
            "",
            f"**Location**: `{self.file_path}:{','.join(map(str, self.line_numbers))}`",
            f"**Commit**: {self.commit_hash or 'N/A'}",
            "",
            "### Description",
            self.description,
            "",
            "### Attack Scenario",
            self.attack_scenario,
            "",
            "### Evidence",
            f"```\n{self.evidence}\n```",
            "",
            "### Recommendation",
            self.recommendation,
        ]
        return "\n".join(lines)


@dataclass
class BlastRadius:
    """Blast radius analysis for a change."""
    changed_function: str
    direct_callers: list[str]
    transitive_callers: list[str]
    affected_state: list[str]
    risk_multiplier: float


@dataclass
class DifferentialReport:
    """Complete differential review report."""
    source_commit: str
    target_commit: str
    codebase_size: CodebaseSize
    files_changed: list[str]
    changes: list[CodeChange]
    findings: list[ReviewFinding]
    blast_radius_analyses: list[BlastRadius]
    test_coverage: dict[str, float]  # file -> coverage %

    @property
    def high_risk_count(self) -> int:
        return len([c for c in self.changes if c.risk_level == RiskLevel.HIGH])

    @property
    def critical_findings(self) -> list[ReviewFinding]:
        return [f for f in self.findings if f.severity == FindingSeverity.CRITICAL]

    def to_markdown(self) -> str:
        lines = [
            "# Differential Security Review Report",
            "",
            f"**Source**: `{self.source_commit}`",
            f"**Target**: `{self.target_commit}`",
            f"**Codebase Size**: {self.codebase_size.value}",
            f"**Files Changed**: {len(self.files_changed)}",
            "",
            "## Executive Summary",
            "",
            f"- **Total Changes**: {len(self.changes)}",
            f"- **High Risk Changes**: {self.high_risk_count}",
            f"- **Critical Findings**: {len(self.critical_findings)}",
            f"- **Total Findings**: {len(self.findings)}",
            "",
            "## Risk Classification",
            "",
            "| Risk Level | Files | Triggers |",
            "|------------|-------|----------|",
        ]

        for level in RiskLevel:
            count = len([c for c in self.changes if c.risk_level == level])
            triggers = self._get_risk_triggers(level)
            lines.append(f"| {level.value.upper()} | {count} | {triggers} |")

        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for finding in sorted(self.findings, key=lambda f: f.severity.value):
            lines.append(finding.to_markdown())
            lines.append("")
            lines.append("---")
            lines.append("")

        if self.blast_radius_analyses:
            lines.append("## Blast Radius Analysis")
            lines.append("")
            for br in self.blast_radius_analyses:
                lines.append(f"### `{br.changed_function}`")
                lines.append(f"- **Direct Callers**: {len(br.direct_callers)}")
                lines.append(f"- **Transitive Callers**: {len(br.transitive_callers)}")
                lines.append(f"- **Risk Multiplier**: {br.risk_multiplier:.1f}x")
                lines.append("")

        return "\n".join(lines)

    def _get_risk_triggers(self, level: RiskLevel) -> str:
        triggers = {
            RiskLevel.HIGH: "Auth, crypto, external calls, value transfer",
            RiskLevel.MEDIUM: "Business logic, state changes, new APIs",
            RiskLevel.LOW: "Comments, tests, UI, logging",
        }
        return triggers.get(level, "")


class DifferentialReviewer:
    """
    Security-focused differential code review.

    Core Principles:
    1. Risk-First: Focus on auth, crypto, value transfer, external calls
    2. Evidence-Based: Every finding backed by git history, line numbers
    3. Adaptive: Scale to codebase size
    4. Honest: Explicitly state coverage limits
    """

    # High-risk patterns
    HIGH_RISK_PATTERNS = [
        # Access control
        r"onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender",
        r"transferOwnership|renounceOwnership",
        # Crypto
        r"ecrecover|keccak256|sha256|abi\.encodePacked",
        r"sign|verify|signature",
        # External calls
        r"\.call\{|\.delegatecall\{|\.staticcall\{",
        r"transfer\(|send\(|transferFrom\(",
        # Value handling
        r"msg\.value|address\(this\)\.balance",
        r"withdraw|deposit|mint|burn",
        # Validation
        r"require\(|assert\(|revert\(",
    ]

    # Red flags that require immediate investigation
    RED_FLAGS = [
        "Security code removed from CVE/fix commit",
        "Access control modifiers removed (onlyOwner, internal → external)",
        "Validation removed without replacement",
        "External calls added without checks",
        "High blast radius (50+ callers) + HIGH risk change",
    ]

    # Rationalizations to reject
    RATIONALIZATIONS = {
        "Small PR, quick review": "Heartbleed was 2 lines. Classify by RISK, not size.",
        "I know this codebase": "Familiarity breeds blind spots. Build explicit context.",
        "Git history takes too long": "History reveals regressions. Never skip Phase 1.",
        "Blast radius is obvious": "You'll miss transitive callers. Calculate quantitatively.",
        "No tests = not my problem": "Missing tests = elevated risk. Flag in report.",
        "Just a refactor, no security impact": "Refactors break invariants. Analyze as HIGH.",
    }

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

    def _classify_codebase_size(self) -> CodebaseSize:
        """Classify codebase size for analysis strategy."""
        file_count = 0
        for pattern in ["**/*.sol", "**/*.vy", "**/*.rs", "**/*.move"]:
            file_count += len(list(self.repo_path.glob(pattern)))

        if file_count < 20:
            return CodebaseSize.SMALL
        elif file_count < 200:
            return CodebaseSize.MEDIUM
        else:
            return CodebaseSize.LARGE

    def _classify_risk(self, diff: str, file_path: str) -> RiskLevel:
        """Classify risk level of a change."""
        # Check for high-risk patterns
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, diff, re.IGNORECASE):
                return RiskLevel.HIGH

        # Check file type
        if any(x in file_path.lower() for x in ["test", "mock", "fixture"]):
            return RiskLevel.LOW

        # Check for state changes
        if re.search(r"storage|mapping|state", diff, re.IGNORECASE):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _get_commit_range(self, source: str, target: str) -> list[str]:
        """Get commits between source and target."""
        output = self._run_git("log", f"{source}..{target}", "--oneline")
        return [line.split()[0] for line in output.strip().split('\n') if line]

    def _get_diff(self, source: str, target: str) -> str:
        """Get diff between commits."""
        return self._run_git("diff", source, target)

    def _get_changed_files(self, source: str, target: str) -> list[str]:
        """Get list of changed files."""
        output = self._run_git("diff", "--name-only", source, target)
        return [f for f in output.strip().split('\n') if f]

    def _analyze_git_blame(self, file_path: str, lines: list[int]) -> dict:
        """Analyze git blame for specific lines."""
        blame_info = {}
        for line in lines:
            output = self._run_git("blame", "-L", f"{line},{line}", "--", file_path)
            blame_info[line] = output.strip()
        return blame_info

    def _calculate_blast_radius(self, function_name: str) -> BlastRadius:
        """Calculate blast radius for a changed function."""
        # Search for direct callers
        grep_output = self._run_git(
            "grep", "-n", f"{function_name}\\s*\\(",
        )

        callers = []
        for line in grep_output.split('\n'):
            if line and function_name in line:
                callers.append(line.split(':')[0])

        return BlastRadius(
            changed_function=function_name,
            direct_callers=callers[:10],  # Limit for display
            transitive_callers=[],  # Would need call graph
            affected_state=[],
            risk_multiplier=1.0 + (len(callers) / 10),
        )

    def _detect_security_patterns(self, change: CodeChange) -> list[ReviewFinding]:
        """Detect security-relevant patterns in a change."""
        findings = []

        # Check for removed validation
        if re.search(r"^-\s*require\(|^-\s*assert\(", change.diff, re.MULTILINE):
            findings.append(ReviewFinding(
                title="Validation Removed",
                severity=FindingSeverity.HIGH,
                file_path=change.file_path,
                line_numbers=change.removed_lines[:5],
                description="Require/assert statement was removed",
                attack_scenario="If validation was protecting against invalid input, removal may enable exploitation",
                evidence=self._extract_removed_lines(change.diff, r"require|assert"),
                recommendation="Verify the validation is no longer needed or moved elsewhere",
            ))

        # Check for external call additions
        if re.search(r"^\+.*\.call\{|^\+.*\.delegatecall", change.diff, re.MULTILINE):
            findings.append(ReviewFinding(
                title="External Call Added",
                severity=FindingSeverity.MEDIUM,
                file_path=change.file_path,
                line_numbers=change.added_lines[:5],
                description="External call was added",
                attack_scenario="External calls can introduce reentrancy or unexpected behavior",
                evidence=self._extract_added_lines(change.diff, r"\.call|\.delegatecall"),
                recommendation="Ensure proper checks-effects-interactions pattern and reentrancy guards",
            ))

        # Check for access control changes
        if re.search(r"^-\s*onlyOwner|^-\s*onlyAdmin", change.diff, re.MULTILINE):
            findings.append(ReviewFinding(
                title="Access Control Weakened",
                severity=FindingSeverity.CRITICAL,
                file_path=change.file_path,
                line_numbers=change.removed_lines[:5],
                description="Access control modifier was removed",
                attack_scenario="Function may now be callable by unauthorized users",
                evidence=self._extract_removed_lines(change.diff, r"only"),
                recommendation="Verify this is intentional and document the new access model",
            ))

        return findings

    def _extract_removed_lines(self, diff: str, pattern: str) -> str:
        """Extract removed lines matching pattern."""
        lines = []
        for line in diff.split('\n'):
            if line.startswith('-') and re.search(pattern, line, re.IGNORECASE):
                lines.append(line)
        return '\n'.join(lines[:10])

    def _extract_added_lines(self, diff: str, pattern: str) -> str:
        """Extract added lines matching pattern."""
        lines = []
        for line in diff.split('\n'):
            if line.startswith('+') and re.search(pattern, line, re.IGNORECASE):
                lines.append(line)
        return '\n'.join(lines[:10])

    def review(
        self,
        source_commit: str,
        target_commit: str,
    ) -> DifferentialReport:
        """
        Perform security-focused differential review.

        Workflow:
        1. Pre-Analysis: Build baseline context
        2. Phase 0: Triage - Classify changes by risk
        3. Phase 1: Code Analysis - Examine HIGH risk changes
        4. Phase 2: Test Coverage - Check for missing tests
        5. Phase 3: Blast Radius - Calculate impact
        6. Phase 4: Deep Context - Use git history
        7. Phase 5: Adversarial - Model attack scenarios
        8. Phase 6: Report - Generate findings
        """
        codebase_size = self._classify_codebase_size()
        changed_files = self._get_changed_files(source_commit, target_commit)

        # Parse changes
        changes: list[CodeChange] = []
        findings: list[ReviewFinding] = []
        blast_analyses: list[BlastRadius] = []

        full_diff = self._get_diff(source_commit, target_commit)

        for file_path in changed_files:
            # Get file-specific diff
            file_diff = self._run_git("diff", source_commit, target_commit, "--", file_path)

            # Parse added/removed lines
            added = []
            removed = []
            current_line = 0
            for line in file_diff.split('\n'):
                if line.startswith('@@'):
                    # Parse hunk header
                    match = re.search(r'\+(\d+)', line)
                    if match:
                        current_line = int(match.group(1))
                elif line.startswith('+') and not line.startswith('+++'):
                    added.append(current_line)
                    current_line += 1
                elif line.startswith('-') and not line.startswith('---'):
                    removed.append(current_line)
                else:
                    current_line += 1

            change = CodeChange(
                file_path=file_path,
                old_content=None,  # Would fetch from git
                new_content=None,
                diff=file_diff,
                added_lines=added,
                removed_lines=removed,
                risk_level=self._classify_risk(file_diff, file_path),
            )
            changes.append(change)

            # Detect security patterns
            findings.extend(self._detect_security_patterns(change))

        # Calculate blast radius for high-risk changes
        for change in changes:
            if change.risk_level == RiskLevel.HIGH:
                # Extract function names from diff (simplified)
                func_matches = re.findall(r'function\s+(\w+)', change.diff)
                for func in func_matches[:3]:  # Limit
                    blast_analyses.append(self._calculate_blast_radius(func))

        return DifferentialReport(
            source_commit=source_commit,
            target_commit=target_commit,
            codebase_size=codebase_size,
            files_changed=changed_files,
            changes=changes,
            findings=findings,
            blast_radius_analyses=blast_analyses,
            test_coverage={},
        )


def review_changes(
    repo_path: str,
    source_commit: str,
    target_commit: str,
    output_path: Optional[str] = None,
) -> DifferentialReport:
    """
    Review code changes between commits.

    Args:
        repo_path: Path to git repository
        source_commit: Source commit (before changes)
        target_commit: Target commit (after changes)
        output_path: Optional path for markdown report

    Returns:
        DifferentialReport with findings
    """
    reviewer = DifferentialReviewer(repo_path)
    report = reviewer.review(source_commit, target_commit)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
