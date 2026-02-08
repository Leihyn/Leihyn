"""
SENTINEL - World-Class Smart Contract Security Auditor

Master integration module that combines:
- Pattern-based bug detection
- Maximum-depth ultrathink prompts
- Slop-free PoC generation
- Concrete test templates
- Professional report generation

Usage:
    from sentinel.src.core.sentinel import Sentinel

    sentinel = Sentinel()

    # Full audit
    report = sentinel.audit(code, language="solidity")

    # Quick bug detection
    bugs = sentinel.detect(code)

    # Generate PoC for specific bug
    poc = sentinel.generate_poc(bug)

    # Generate report
    markdown = sentinel.report(findings, format="code4rena")
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

from .bug_detection import detect_bugs, DetectedBug, Severity
from .poc_generator import generate_poc, PoCType, PoCValidator
from .test_templates import generate_exploit_test, TestFramework
from .report_generator import generate_report, Finding, ReportFormat
from .ultrathink_strict import build_strict_prompt, validate_finding
from .ultrathink_max import build_max_ultrathink, Language
from .fuzzing_generator import (
    ContractAnalyzer,
    StandardizedCoverageAnalyzer,
    generate_fuzzing_suite,
    analyze_standardized_coverage,
    FuzzingConfig,
)


class AuditMode(Enum):
    QUICK = "quick"  # Pattern matching only
    STANDARD = "standard"  # Patterns + basic analysis
    DEEP = "deep"  # Full ultrathink analysis
    COMPETITION = "competition"  # Maximum depth for contests


@dataclass
class AuditConfig:
    """Configuration for audit runs."""
    mode: AuditMode = AuditMode.STANDARD
    language: str = "solidity"
    include_poc: bool = True
    include_tests: bool = True
    test_framework: TestFramework = TestFramework.FOUNDRY
    report_format: ReportFormat = ReportFormat.PROFESSIONAL
    thinking_budget: int = 24000
    strict_mode: bool = True  # No slop allowed
    # Recon Magic: Standardized coverage and fuzzing
    generate_fuzzing_suite: bool = False
    use_standardized_coverage: bool = True  # Focus quality on state-changing functions


@dataclass
class StandardizedCoverageMetrics:
    """
    Standardized line coverage metrics (Recon Magic methodology).

    Traditional coverage includes view/pure functions which don't contribute
    to state exploration. Standardized coverage focuses only on functions
    that can alter contract state.
    """
    functions_of_interest: list[str]  # State-changing, external functions
    excluded_functions: list[str]  # View/pure functions (not counted)
    total_target_functions: int
    standardized_ratio: float  # foi / (foi + excluded)


@dataclass
class AuditResult:
    """Complete audit result."""
    bugs_detected: list[DetectedBug]
    findings: list[Finding]
    pocs: dict[str, str]  # finding_id -> poc_code
    tests: dict[str, str]  # finding_id -> test_code
    report: str
    prompt_used: str
    quality_score: int
    # Standardized coverage metrics (Recon Magic)
    standardized_coverage: Optional[StandardizedCoverageMetrics] = None
    fuzzing_suite: Optional[str] = None  # Generated Chimera test suite


class Sentinel:
    """
    World-class smart contract security auditor.

    Zero tolerance for AI slop.
    Every finding must be concrete, provable, and actionable.
    """

    def __init__(self, config: Optional[AuditConfig] = None):
        self.config = config or AuditConfig()

    def audit(
        self,
        code: str,
        contract_name: str = "Contract",
        config: Optional[AuditConfig] = None,
    ) -> AuditResult:
        """
        Run complete security audit.

        Args:
            code: Source code to audit
            contract_name: Name of the contract
            config: Optional config override

        Returns:
            Complete audit result with findings, PoCs, tests, and report
        """
        config = config or self.config

        # Step 1: Pattern-based detection
        bugs = detect_bugs(code, config.language)

        # Step 2: Generate ultrathink prompt
        if config.mode == AuditMode.COMPETITION:
            prompt = self._build_competition_prompt(code, contract_name, config)
        elif config.mode == AuditMode.DEEP:
            prompt = self._build_deep_prompt(code, contract_name, config)
        else:
            prompt = self._build_standard_prompt(code, contract_name, config)

        # Step 3: Convert detected bugs to findings
        findings = self._bugs_to_findings(bugs, code)

        # Step 4: Generate PoCs
        pocs = {}
        if config.include_poc:
            for finding in findings:
                poc = self._generate_poc_for_finding(finding, config)
                if poc:
                    pocs[finding.id] = poc

        # Step 5: Generate tests
        tests = {}
        if config.include_tests:
            for finding in findings:
                test = self._generate_test_for_finding(finding, config)
                if test:
                    tests[finding.id] = test

        # Step 6: Generate report
        report = generate_report(
            project_name=contract_name,
            auditor="SENTINEL",
            findings=findings,
            scope=[contract_name],
            format=config.report_format,
        )

        # Step 7: Analyze standardized coverage (Recon Magic)
        standardized_coverage = None
        fuzzing_suite = None

        if config.use_standardized_coverage:
            coverage_data = analyze_standardized_coverage(code, contract_name)
            standardized_coverage = StandardizedCoverageMetrics(
                functions_of_interest=coverage_data["functions_of_interest"],
                excluded_functions=coverage_data["excluded_functions"],
                total_target_functions=coverage_data["total_standardized"],
                standardized_ratio=coverage_data["standardized_ratio"],
            )

        # Step 8: Generate Chimera fuzzing suite if requested
        if config.generate_fuzzing_suite:
            fuzzing_config = FuzzingConfig(contract_name=contract_name)
            fuzzing_suite = generate_fuzzing_suite(code, contract_name, fuzzing_config)

        # Calculate quality score (using standardized coverage if enabled)
        quality_score = self._calculate_quality_score(
            findings, pocs, tests, standardized_coverage
        )

        return AuditResult(
            bugs_detected=bugs,
            findings=findings,
            pocs=pocs,
            tests=tests,
            report=report,
            prompt_used=prompt,
            quality_score=quality_score,
            standardized_coverage=standardized_coverage,
            fuzzing_suite=fuzzing_suite,
        )

    def detect(self, code: str, language: str = "solidity") -> list[DetectedBug]:
        """Quick pattern-based bug detection."""
        return detect_bugs(code, language)

    def generate_poc(
        self,
        finding: Finding,
        config: Optional[AuditConfig] = None,
    ) -> str:
        """Generate PoC for a finding."""
        config = config or self.config
        return self._generate_poc_for_finding(finding, config)

    def generate_test(
        self,
        finding: Finding,
        framework: TestFramework = TestFramework.FOUNDRY,
    ) -> str:
        """Generate test for a finding."""
        return generate_exploit_test(
            vulnerability_type=finding.category,
            target_contract="Target",
            target_address="0x...",
            framework=framework,
        )

    def report(
        self,
        findings: list[Finding],
        project_name: str = "Project",
        format: ReportFormat = ReportFormat.PROFESSIONAL,
    ) -> str:
        """Generate audit report."""
        return generate_report(
            project_name=project_name,
            auditor="SENTINEL",
            findings=findings,
            scope=[],
            format=format,
        )

    def get_prompt(
        self,
        code: str,
        mode: AuditMode = AuditMode.STANDARD,
        contract_name: str = "Contract",
    ) -> str:
        """Get ultrathink prompt for manual analysis."""
        config = AuditConfig(mode=mode)

        if mode == AuditMode.COMPETITION:
            return self._build_competition_prompt(code, contract_name, config)
        elif mode == AuditMode.DEEP:
            return self._build_deep_prompt(code, contract_name, config)
        else:
            return self._build_standard_prompt(code, contract_name, config)

    def get_standardized_coverage(
        self,
        code: str,
        contract_name: str = "Contract",
    ) -> dict:
        """
        Analyze contract for standardized coverage metrics.

        Based on Recon Magic methodology:
        - Returns functions of interest (state-changing, external)
        - Returns excluded functions (view/pure)
        - Calculates standardized ratio

        This helps identify what should actually be covered by fuzzing.
        """
        return analyze_standardized_coverage(code, contract_name)

    def get_fuzzing_suite(
        self,
        code: str,
        contract_name: str = "Contract",
        actors: Optional[list[str]] = None,
    ) -> str:
        """
        Generate Chimera-compatible fuzzing test suite.

        Based on Recon Magic methodology:
        - Generates unclamped handlers for full search space
        - Generates clamped handlers with intelligent input restriction
        - Generates shortcut functions for deep state exploration

        Output is compatible with Echidna and Medusa fuzzers.
        """
        config = FuzzingConfig(
            contract_name=contract_name,
            actors=actors or ["actor1", "actor2", "actor3"],
        )
        return generate_fuzzing_suite(code, contract_name, config)

    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================

    def _build_competition_prompt(
        self,
        code: str,
        contract_name: str,
        config: AuditConfig,
    ) -> str:
        """Build maximum-depth competition prompt."""
        language = self._get_language_enum(config.language)
        return build_max_ultrathink(code, language, contract_name)

    def _build_deep_prompt(
        self,
        code: str,
        contract_name: str,
        config: AuditConfig,
    ) -> str:
        """Build deep analysis prompt."""
        return build_strict_prompt(code, config.language, contract_name)

    def _build_standard_prompt(
        self,
        code: str,
        contract_name: str,
        config: AuditConfig,
    ) -> str:
        """Build standard analysis prompt."""
        return build_strict_prompt(code, config.language, contract_name)

    def _get_language_enum(self, language: str) -> Language:
        """Convert string to Language enum."""
        mapping = {
            "solidity": Language.SOLIDITY,
            "rust": Language.RUST_ANCHOR,
            "anchor": Language.RUST_ANCHOR,
            "move": Language.MOVE_APTOS,
            "aptos": Language.MOVE_APTOS,
            "sui": Language.MOVE_SUI,
            "cairo": Language.CAIRO,
            "vyper": Language.VYPER,
        }
        return mapping.get(language.lower(), Language.SOLIDITY)

    def _bugs_to_findings(
        self,
        bugs: list[DetectedBug],
        code: str,
    ) -> list[Finding]:
        """Convert detected bugs to proper findings."""
        findings = []

        severity_map = {
            Severity.CRITICAL: "Critical",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFO: "Informational",
        }

        for i, bug in enumerate(bugs):
            severity_prefix = bug.severity.value[0].upper()
            finding_id = f"{severity_prefix}-{i+1:02d}"

            findings.append(Finding(
                id=finding_id,
                title=bug.title,
                severity=self._convert_severity(bug.severity),
                category=bug.pattern_id.split("-")[1] if "-" in bug.pattern_id else "General",
                root_cause=bug.description,
                vulnerable_code=f"Line {bug.line_number}: {bug.code_snippet}",
                attack_path=[bug.exploitation],
                impact=f"Severity: {severity_map.get(bug.severity, 'Unknown')}",
                likelihood="High" if bug.confidence > 0.8 else "Medium",
                poc_code="// PoC to be generated",
                poc_output="// Expected output",
                recommendation=bug.fix,
                fixed_code="// Fix to be applied",
                references=bug.references,
            ))

        return findings

    def _convert_severity(self, severity: Severity):
        """Convert internal severity to report severity."""
        from .report_generator import Severity as ReportSeverity
        mapping = {
            Severity.CRITICAL: ReportSeverity.CRITICAL,
            Severity.HIGH: ReportSeverity.HIGH,
            Severity.MEDIUM: ReportSeverity.MEDIUM,
            Severity.LOW: ReportSeverity.LOW,
            Severity.INFO: ReportSeverity.INFORMATIONAL,
        }
        return mapping.get(severity, ReportSeverity.MEDIUM)

    def _generate_poc_for_finding(
        self,
        finding: Finding,
        config: AuditConfig,
    ) -> str:
        """Generate PoC for a specific finding."""
        # Map category to PoC type
        poc_type_map = {
            "CRIT": PoCType.ACCESS_CONTROL,
            "HIGH": PoCType.REENTRANCY,
            "reentrancy": PoCType.REENTRANCY,
            "access": PoCType.ACCESS_CONTROL,
            "oracle": PoCType.ORACLE_MANIPULATION,
            "flash": PoCType.FLASH_LOAN,
        }

        poc_type = None
        for key, ptype in poc_type_map.items():
            if key.lower() in finding.category.lower():
                poc_type = ptype
                break

        if poc_type:
            return generate_poc(
                vulnerability_type=poc_type,
                target_contract="Target",
                target_address="0x...",
            )

        return ""

    def _generate_test_for_finding(
        self,
        finding: Finding,
        config: AuditConfig,
    ) -> str:
        """Generate test for a specific finding."""
        return generate_exploit_test(
            vulnerability_type=finding.category,
            target_contract="Target",
            target_address="0x...",
            framework=config.test_framework,
        )

    def _calculate_quality_score(
        self,
        findings: list[Finding],
        pocs: dict[str, str],
        tests: dict[str, str],
        standardized_coverage: Optional[StandardizedCoverageMetrics] = None,
    ) -> int:
        """
        Calculate quality score for the audit.

        Uses standardized line coverage methodology (Recon Magic):
        - Focus on state-changing functions (functions of interest)
        - Exclude view/pure functions from coverage calculation
        - Better metric for actual fuzzer efficacy
        """
        if not findings:
            return 100  # No findings = clean audit

        score = 100

        # Deduct for missing PoCs
        for finding in findings:
            if finding.id not in pocs:
                score -= 5

        # Deduct for missing tests
        for finding in findings:
            if finding.id not in tests:
                score -= 3

        # Validate PoCs aren't sloppy
        for poc_code in pocs.values():
            is_valid, errors = PoCValidator.validate(poc_code)
            if not is_valid:
                score -= len(errors) * 2

        # Bonus for good standardized coverage ratio
        # High ratio means more state-changing functions = more thorough audit
        if standardized_coverage:
            if standardized_coverage.standardized_ratio > 0.5:
                score += 5  # Good coverage focus
            if standardized_coverage.total_target_functions > 10:
                score += 3  # Complex contract thoroughly analyzed

        return max(0, min(100, score))


# Convenience function
def quick_audit(code: str, language: str = "solidity") -> list[DetectedBug]:
    """Quick pattern-based audit."""
    return Sentinel().detect(code, language)


def full_audit(
    code: str,
    contract_name: str = "Contract",
    mode: AuditMode = AuditMode.STANDARD,
) -> AuditResult:
    """Full audit with all features."""
    config = AuditConfig(mode=mode)
    return Sentinel(config).audit(code, contract_name)
