"""
Bug Bounty Rules & Compliance - Based on Immunefi Platform Rules

Enforces proper whitehat behavior when using Sentinel for bug bounty research.
Ensures all findings, PoCs, and reports comply with Immunefi platform rules
before submission.

Key rules:
- NO mainnet/testnet testing (immediate permanent ban)
- NO AI-generated/automated scanner submissions (must be researcher's own work)
- All PoCs must use local forks only
- Reports must be in English with complete PoC
- No public disclosure before fix + payment
- No placeholder/spam submissions

Source: https://immunefi.com/rules/
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Violation(Enum):
    """Violation categories that result in ban/forfeiture."""
    MAINNET_TESTING = "mainnet_testing"
    MISREPRESENTED_SCOPE = "misrepresented_scope"
    MISREPRESENTED_SEVERITY = "misrepresented_severity"
    MISREPRESENTED_IMPACT = "misrepresented_impact"
    AI_GENERATED_REPORT = "ai_generated_report"
    PLACEHOLDER_SUBMISSION = "placeholder_submission"
    PUBLIC_DISCLOSURE = "public_disclosure"
    DUPLICATE_SUBMISSION = "duplicate_submission"
    NO_POC = "no_poc"
    WRONG_LANGUAGE = "wrong_language"
    DIRECT_CONTACT = "direct_contact"
    EXPLOIT_THREAT = "exploit_threat"
    SPAM = "spam"


class ReportQuality(Enum):
    """Report quality assessment levels."""
    SUBMISSION_READY = "submission_ready"
    NEEDS_WORK = "needs_work"
    INCOMPLETE = "incomplete"
    VIOLATION = "violation"


@dataclass
class ComplianceCheck:
    """Result of a compliance check against Immunefi rules."""
    passed: bool
    rule: str
    details: str
    violation: Optional[Violation] = None
    severity: str = "info"  # info, warning, ban


@dataclass
class SubmissionReview:
    """Pre-submission review of a bug report."""
    checks: list[ComplianceCheck] = field(default_factory=list)
    quality: ReportQuality = ReportQuality.INCOMPLETE
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    @property
    def is_submittable(self) -> bool:
        return self.quality == ReportQuality.SUBMISSION_READY and len(self.blockers) == 0

    def to_markdown(self) -> str:
        status = "READY" if self.is_submittable else "NOT READY"
        lines = [
            f"# Pre-Submission Review [{status}]",
            "",
            f"**Quality**: {self.quality.value}",
            f"**Checks Passed**: {sum(1 for c in self.checks if c.passed)}/{len(self.checks)}",
            "",
        ]
        if self.blockers:
            lines.append("## Blockers (must fix before submission)")
            for b in self.blockers:
                lines.append(f"- {b}")
            lines.append("")
        if self.warnings:
            lines.append("## Warnings")
            for w in self.warnings:
                lines.append(f"- {w}")
            lines.append("")
        lines.append("## Compliance Checks")
        for c in self.checks:
            icon = "PASS" if c.passed else "FAIL"
            lines.append(f"- [{icon}] {c.rule}: {c.details}")
        return "\n".join(lines)


# Immunefi PoC requirements
POC_REQUIREMENTS = {
    "local_fork_only": "All PoCs must run on local forks (forge --fork-url), NEVER mainnet/testnet",
    "reproducible": "PoC must include complete reproducible steps",
    "english_only": "Report and PoC must be written in English",
    "original_work": "Must be substantially your own research, not AI-generated scanner output",
    "complete": "No placeholder submissions - must include title, description, impact, and PoC",
    "correct_scope": "Bug must affect an asset listed as in-scope on the program page",
    "correct_severity": "Severity must match actual impact (no inflation)",
    "correct_impact": "Selected impacts must actually apply to the finding",
    "single_submission": "Do not submit duplicates of the same finding to claim additional rewards",
    "no_public_disclosure": "Do not disclose (or even confirm existence of) a report before fix + payment",
}

# Report quality checklist
REPORT_CHECKLIST = [
    {"item": "Clear, specific title (not vague)", "required": True},
    {"item": "Detailed vulnerability description", "required": True},
    {"item": "Affected asset is in program scope", "required": True},
    {"item": "Correct severity classification", "required": True},
    {"item": "Impact description matches selected impacts", "required": True},
    {"item": "Complete PoC with reproducible steps", "required": True},
    {"item": "PoC runs on local fork only", "required": True},
    {"item": "Written in English", "required": True},
    {"item": "Original research (not automated scanner output)", "required": True},
    {"item": "Attack scenario described step-by-step", "required": False},
    {"item": "Estimated financial impact quantified", "required": False},
    {"item": "Remediation suggestion included", "required": False},
    {"item": "No screenshots from Immunefi dashboard", "required": True},
]

# Severity classification guidance (Immunefi standard)
SEVERITY_GUIDE = {
    "critical": {
        "description": "Direct theft of funds, permanent freezing of funds, or protocol insolvency",
        "examples": [
            "Drain user funds via arbitrary call",
            "Permanent DoS of core protocol functions",
            "Governance takeover allowing treasury drain",
            "Oracle manipulation leading to bad debt exceeding reserves",
        ],
        "payout_range": "$50K - $10M+",
    },
    "high": {
        "description": "Theft of yield, temporary freezing, or significant value extraction",
        "examples": [
            "Theft of unclaimed yield/rewards",
            "Temporary freezing of funds (recoverable)",
            "MEV extraction beyond normal arbitrage",
            "Griefing attack with material financial impact",
        ],
        "payout_range": "$10K - $50K",
    },
    "medium": {
        "description": "Protocol misbehavior, griefing, or limited impact issues",
        "examples": [
            "Smart contract unable to operate due to external conditions",
            "Griefing without direct financial loss",
            "Block stuffing or gas price manipulation",
            "Incorrect fee calculations with limited impact",
        ],
        "payout_range": "$1K - $10K",
    },
    "low": {
        "description": "Minor issues, informational findings",
        "examples": [
            "Contract returns incorrect data without financial impact",
            "Event emission errors",
            "Minor documentation discrepancies in implementation",
        ],
        "payout_range": "$100 - $1K",
    },
}


class BugBountyCompliance:
    """
    Immunefi bug bounty compliance checker for Sentinel.

    Validates that all research, PoCs, and reports comply with
    Immunefi platform rules before submission. Prevents:
    - Mainnet/testnet testing (permanent ban)
    - AI-generated report submissions
    - Incomplete/placeholder reports
    - Severity misrepresentation
    - Public disclosure violations

    Usage:
        compliance = BugBountyCompliance()
        review = compliance.pre_submission_review(
            title="Arbitrary call in swap function",
            description="The swap() function passes user-controlled...",
            severity="critical",
            has_poc=True,
            poc_uses_fork=True,
            asset_in_scope=True,
        )
        if review.is_submittable:
            print("Ready to submit!")
    """

    def __init__(self):
        self.poc_requirements = POC_REQUIREMENTS
        self.checklist = REPORT_CHECKLIST
        self.severity_guide = SEVERITY_GUIDE

    def check_poc_safety(self, poc_code: str) -> list[ComplianceCheck]:
        """Check PoC code for rule violations (mainnet interaction, etc.)."""
        import re
        checks = []

        # Check for mainnet RPC URLs (CRITICAL - permanent ban)
        mainnet_patterns = [
            r"https?://eth-mainnet",
            r"https?://mainnet\.infura",
            r"https?://rpc\.ankr\.com/eth(?!/goerli|/sepolia)",
            r"--rpc-url.*mainnet",
            r"--network\s+mainnet",
        ]
        for pattern in mainnet_patterns:
            if re.search(pattern, poc_code, re.IGNORECASE):
                checks.append(ComplianceCheck(
                    passed=False,
                    rule="No mainnet testing",
                    details="PoC contains mainnet RPC URL. Use --fork-url for local fork instead.",
                    violation=Violation.MAINNET_TESTING,
                    severity="ban",
                ))
                break
        else:
            checks.append(ComplianceCheck(
                passed=True,
                rule="No mainnet testing",
                details="No mainnet RPC URLs detected",
            ))

        # Check for fork usage (required)
        if re.search(r"(--fork-url|--fork-block|vm\.createFork|vm\.selectFork)", poc_code):
            checks.append(ComplianceCheck(
                passed=True,
                rule="Local fork usage",
                details="PoC uses local fork (correct approach)",
            ))
        else:
            checks.append(ComplianceCheck(
                passed=False,
                rule="Local fork usage",
                details="PoC should use --fork-url or vm.createFork for local fork testing",
                severity="warning",
            ))

        # Check for actual exploit attempt on live contracts
        if re.search(r"(broadcast|--broadcast|vm\.startBroadcast)", poc_code):
            checks.append(ComplianceCheck(
                passed=False,
                rule="No live execution",
                details="PoC contains broadcast/live execution commands. Remove these.",
                violation=Violation.MAINNET_TESTING,
                severity="ban",
            ))

        return checks

    def pre_submission_review(
        self,
        title: str = "",
        description: str = "",
        severity: str = "",
        has_poc: bool = False,
        poc_uses_fork: bool = False,
        poc_code: str = "",
        asset_in_scope: bool = True,
        is_original_research: bool = True,
        impacts_match: bool = True,
    ) -> SubmissionReview:
        """Run full pre-submission compliance review."""
        review = SubmissionReview()

        # Title check
        if not title or len(title) < 10:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Clear title",
                details="Title is missing or too vague (placeholder submission risk)",
                violation=Violation.PLACEHOLDER_SUBMISSION,
                severity="warning",
            ))
            review.blockers.append("Add a clear, specific title")
        else:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Clear title", details="Title provided"))

        # Description check
        if not description or len(description) < 50:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Detailed description",
                details="Description is missing or too short",
                violation=Violation.PLACEHOLDER_SUBMISSION,
                severity="warning",
            ))
            review.blockers.append("Add detailed vulnerability description")
        else:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Detailed description", details="Description provided"))

        # Severity check
        if severity and severity.lower() in self.severity_guide:
            review.checks.append(ComplianceCheck(
                passed=True,
                rule="Valid severity",
                details=f"Severity '{severity}' is valid. Verify it matches actual impact.",
            ))
            guide = self.severity_guide[severity.lower()]
            review.warnings.append(
                f"Severity '{severity}': {guide['description']}. "
                f"Payout range: {guide['payout_range']}"
            )
        elif severity:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Valid severity",
                details=f"Unknown severity '{severity}'. Use: critical, high, medium, low",
                severity="warning",
            ))
            review.blockers.append("Set a valid severity level")

        # PoC check
        if not has_poc:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Complete PoC",
                details="PoC is required. Submissions without PoC may be rejected.",
                violation=Violation.NO_POC,
                severity="warning",
            ))
            review.blockers.append("Add complete PoC with reproducible steps")
        else:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Complete PoC", details="PoC provided"))

        # Fork-only check
        if has_poc and not poc_uses_fork:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Fork-only testing",
                details="PoC must use local fork. Mainnet/testnet testing = permanent ban.",
                violation=Violation.MAINNET_TESTING,
                severity="ban",
            ))
            review.blockers.append("CRITICAL: PoC must use local fork, not mainnet/testnet")
        elif has_poc:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Fork-only testing", details="Uses local fork"))

        # Scope check
        if not asset_in_scope:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Asset in scope",
                details="Bug must affect an asset listed in the program's scope",
                violation=Violation.MISREPRESENTED_SCOPE,
                severity="warning",
            ))
            review.blockers.append("Verify the affected asset is in the program's scope")
        else:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Asset in scope", details="Asset confirmed in scope"))

        # Original research check
        if not is_original_research:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Original research",
                details="AI-generated/automated scanner reports are prohibited",
                violation=Violation.AI_GENERATED_REPORT,
                severity="ban",
            ))
            review.blockers.append("Report must be substantially your own research")
        else:
            review.checks.append(ComplianceCheck(
                passed=True, rule="Original research", details="Original research confirmed"))

        # Impact match check
        if not impacts_match:
            review.checks.append(ComplianceCheck(
                passed=False,
                rule="Impacts match",
                details="Selected impacts must actually apply to the finding",
                violation=Violation.MISREPRESENTED_IMPACT,
                severity="warning",
            ))
            review.warnings.append("Verify selected impacts match actual vulnerability behavior")

        # PoC code safety check
        if poc_code:
            poc_checks = self.check_poc_safety(poc_code)
            review.checks.extend(poc_checks)
            for check in poc_checks:
                if not check.passed and check.severity == "ban":
                    review.blockers.append(f"CRITICAL: {check.details}")

        # Determine overall quality
        ban_violations = [c for c in review.checks if not c.passed and c.severity == "ban"]
        failures = [c for c in review.checks if not c.passed]

        if ban_violations:
            review.quality = ReportQuality.VIOLATION
        elif len(failures) > 2:
            review.quality = ReportQuality.INCOMPLETE
        elif failures:
            review.quality = ReportQuality.NEEDS_WORK
        else:
            review.quality = ReportQuality.SUBMISSION_READY

        return review

    def get_severity_guide(self, severity: str) -> Optional[dict]:
        """Get severity classification guidance."""
        return self.severity_guide.get(severity.lower())

    def get_report_checklist(self) -> list[dict]:
        """Get full report quality checklist."""
        return self.checklist

    def generate_submission_template(
        self,
        title: str,
        severity: str,
        asset: str,
        description: str,
        impact: str,
        poc_steps: list[str],
        remediation: str = "",
    ) -> str:
        """Generate a properly formatted bug report for Immunefi submission."""
        lines = [
            f"# {title}",
            "",
            f"**Severity**: {severity.capitalize()}",
            f"**Asset**: {asset}",
            "",
            "## Description",
            "",
            description,
            "",
            "## Impact",
            "",
            impact,
            "",
            "## Proof of Concept",
            "",
            "**Environment**: Local fork via Foundry (`forge test --fork-url`)",
            "",
            "### Steps to Reproduce",
            "",
        ]
        for i, step in enumerate(poc_steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append("### PoC Code")
        lines.append("")
        lines.append("```solidity")
        lines.append("// See attached test file")
        lines.append("```")

        if remediation:
            lines.extend([
                "",
                "## Recommended Fix",
                "",
                remediation,
            ])

        return "\n".join(lines)


def create_compliance_checker() -> BugBountyCompliance:
    """Create a new bug bounty compliance checker."""
    return BugBountyCompliance()
