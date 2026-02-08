"""
Differential Auditor

Compare contract versions to catch security regressions:
1. Post-audit modifications - Did changes introduce bugs?
2. Upgrade analysis - Is V2 still secure?
3. Fork comparison - What did the fork change?
4. Patch verification - Did the fix actually work?

Use cases:
- Before deploying an upgrade
- After developers "just changed one thing"
- Reviewing PRs for security impact
- Verifying vulnerability fixes
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re
import difflib


class ChangeType(Enum):
    """Types of changes between versions."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    MOVED = "moved"


class RiskLevel(Enum):
    """Risk level of a change."""
    CRITICAL = "critical"     # High-risk change to security function
    HIGH = "high"             # Change to sensitive code path
    MEDIUM = "medium"         # Change to business logic
    LOW = "low"               # Cosmetic or documentation
    INFORMATIONAL = "informational"


@dataclass
class CodeChange:
    """A detected change between versions."""
    change_type: ChangeType
    risk_level: RiskLevel
    file_path: str
    function_name: Optional[str]
    old_code: str
    new_code: str
    line_number_old: int
    line_number_new: int
    description: str
    security_impact: str


@dataclass
class RegressionRisk:
    """A potential security regression."""
    risk_level: RiskLevel
    change: CodeChange
    title: str
    description: str
    vulnerable_pattern: Optional[str]  # If matches known vulnerability
    recommendation: str


@dataclass
class DiffConfig:
    """Configuration for differential analysis."""
    ignore_whitespace: bool = True
    ignore_comments: bool = True
    check_access_control: bool = True
    check_state_variables: bool = True
    check_external_calls: bool = True
    check_math_operations: bool = True


# =============================================================================
# SECURITY-SENSITIVE PATTERNS
# =============================================================================

SECURITY_SENSITIVE_PATTERNS = {
    "access_control": {
        "patterns": [
            r"onlyOwner",
            r"onlyRole",
            r"onlyAdmin",
            r"require\s*\([^)]*msg\.sender",
            r"require\s*\([^)]*owner",
            r"modifier\s+\w+",
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "Access control modification",
    },
    "external_calls": {
        "patterns": [
            r"\.call\{",
            r"\.delegatecall\(",
            r"\.staticcall\(",
            r"\.transfer\(",
            r"\.send\(",
            r"IERC20\([^)]+\)\.\w+",
        ],
        "risk": RiskLevel.HIGH,
        "description": "External call modification",
    },
    "state_changes": {
        "patterns": [
            r"\w+\s*=\s*[^=]",
            r"\w+\s*\+=",
            r"\w+\s*-=",
            r"delete\s+\w+",
            r"\.push\(",
            r"\.pop\(",
        ],
        "risk": RiskLevel.MEDIUM,
        "description": "State variable modification",
    },
    "math_operations": {
        "patterns": [
            r"\+(?!\+)",
            r"-(?!-|>)",
            r"\*",
            r"/",
            r"%",
            r"\*\*",
        ],
        "risk": RiskLevel.MEDIUM,
        "description": "Arithmetic modification",
    },
    "reentrancy_guards": {
        "patterns": [
            r"nonReentrant",
            r"ReentrancyGuard",
            r"_status\s*=",
            r"locked\s*=",
        ],
        "risk": RiskLevel.CRITICAL,
        "description": "Reentrancy protection modification",
    },
    "oracle_usage": {
        "patterns": [
            r"latestRoundData",
            r"getPrice",
            r"oracle\.",
            r"priceFeed\.",
        ],
        "risk": RiskLevel.HIGH,
        "description": "Oracle usage modification",
    },
}


class DifferentialAuditor:
    """
    Compare contract versions for security regressions.

    Features:
    - Semantic diff (ignoring formatting)
    - Security-focused change analysis
    - Regression detection
    - Fix verification
    """

    def __init__(self, config: Optional[DiffConfig] = None):
        self.config = config or DiffConfig()
        self.changes: list[CodeChange] = []
        self.regressions: list[RegressionRisk] = []

    def diff(
        self,
        old_source: str,
        new_source: str,
        old_name: str = "v1",
        new_name: str = "v2",
    ) -> tuple[list[CodeChange], list[RegressionRisk]]:
        """
        Perform differential security analysis.

        Returns:
            Tuple of (changes, potential_regressions)
        """
        self.changes = []
        self.regressions = []

        # Normalize sources
        old_normalized = self._normalize(old_source)
        new_normalized = self._normalize(new_source)

        # Extract and compare functions
        old_functions = self._extract_functions(old_source)
        new_functions = self._extract_functions(new_source)

        # Find changes
        self._analyze_function_changes(old_functions, new_functions)

        # Analyze state variable changes
        if self.config.check_state_variables:
            self._analyze_state_changes(old_source, new_source)

        # Check for security regressions
        self._detect_regressions()

        return self.changes, self.regressions

    def verify_fix(
        self,
        vulnerable_code: str,
        patched_code: str,
        vulnerability_pattern: str,
    ) -> dict:
        """
        Verify that a vulnerability fix is effective.

        Returns:
            Dict with verification results
        """
        result = {
            "vulnerability_present_before": False,
            "vulnerability_present_after": False,
            "fix_effective": False,
            "potential_bypass": None,
            "recommendation": None,
        }

        # Check if vulnerability exists in original
        if re.search(vulnerability_pattern, vulnerable_code, re.DOTALL):
            result["vulnerability_present_before"] = True

        # Check if vulnerability exists in patch
        if re.search(vulnerability_pattern, patched_code, re.DOTALL):
            result["vulnerability_present_after"] = True
            result["fix_effective"] = False
            result["recommendation"] = "Vulnerability pattern still present in patched code"
        else:
            result["fix_effective"] = result["vulnerability_present_before"]

        # Check for common bypass patterns
        bypass = self._check_fix_bypass(vulnerable_code, patched_code, vulnerability_pattern)
        if bypass:
            result["potential_bypass"] = bypass
            result["fix_effective"] = False

        return result

    def _normalize(self, source: str) -> str:
        """Normalize source code for comparison."""
        normalized = source

        if self.config.ignore_whitespace:
            # Normalize whitespace
            normalized = re.sub(r'\s+', ' ', normalized)

        if self.config.ignore_comments:
            # Remove single-line comments
            normalized = re.sub(r'//[^\n]*', '', normalized)
            # Remove multi-line comments
            normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)

        return normalized.strip()

    def _extract_functions(self, source: str) -> dict[str, dict]:
        """Extract all functions with their code and metadata."""
        functions = {}

        func_pattern = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*'
            r'((?:external|public|internal|private|view|pure|payable|\s)*)'
            r'(?:returns\s*\([^)]*\))?\s*'
            r'\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            re.MULTILINE | re.DOTALL
        )

        for match in func_pattern.finditer(source):
            name = match.group(1)
            params = match.group(2)
            modifiers = match.group(3)
            body = match.group(4)

            functions[name] = {
                "params": params,
                "modifiers": modifiers,
                "body": body,
                "full": match.group(0),
                "line": source[:match.start()].count('\n') + 1,
            }

        return functions

    def _analyze_function_changes(
        self,
        old_funcs: dict[str, dict],
        new_funcs: dict[str, dict],
    ) -> None:
        """Analyze changes in functions."""
        all_funcs = set(old_funcs.keys()) | set(new_funcs.keys())

        for func_name in all_funcs:
            old = old_funcs.get(func_name)
            new = new_funcs.get(func_name)

            if old and not new:
                # Function removed
                self.changes.append(CodeChange(
                    change_type=ChangeType.REMOVED,
                    risk_level=self._assess_risk(old["full"], "removed"),
                    file_path="",
                    function_name=func_name,
                    old_code=old["full"],
                    new_code="",
                    line_number_old=old["line"],
                    line_number_new=0,
                    description=f"Function '{func_name}' was removed",
                    security_impact=self._assess_security_impact(old["full"], "removed"),
                ))

            elif new and not old:
                # Function added
                self.changes.append(CodeChange(
                    change_type=ChangeType.ADDED,
                    risk_level=self._assess_risk(new["full"], "added"),
                    file_path="",
                    function_name=func_name,
                    old_code="",
                    new_code=new["full"],
                    line_number_old=0,
                    line_number_new=new["line"],
                    description=f"Function '{func_name}' was added",
                    security_impact=self._assess_security_impact(new["full"], "added"),
                ))

            elif old and new:
                # Check if modified
                if self._normalize(old["full"]) != self._normalize(new["full"]):
                    # Analyze what changed
                    changes_desc = self._describe_changes(old, new)

                    self.changes.append(CodeChange(
                        change_type=ChangeType.MODIFIED,
                        risk_level=self._assess_risk(new["full"], "modified", old["full"]),
                        file_path="",
                        function_name=func_name,
                        old_code=old["full"],
                        new_code=new["full"],
                        line_number_old=old["line"],
                        line_number_new=new["line"],
                        description=f"Function '{func_name}' was modified: {changes_desc}",
                        security_impact=self._assess_security_impact(
                            new["full"], "modified", old["full"]
                        ),
                    ))

    def _analyze_state_changes(self, old_source: str, new_source: str) -> None:
        """Analyze changes in state variables."""
        old_vars = self._extract_state_variables(old_source)
        new_vars = self._extract_state_variables(new_source)

        all_vars = set(old_vars.keys()) | set(new_vars.keys())

        for var_name in all_vars:
            old = old_vars.get(var_name)
            new = new_vars.get(var_name)

            if old and not new:
                self.changes.append(CodeChange(
                    change_type=ChangeType.REMOVED,
                    risk_level=RiskLevel.HIGH,
                    file_path="",
                    function_name=None,
                    old_code=old["declaration"],
                    new_code="",
                    line_number_old=old["line"],
                    line_number_new=0,
                    description=f"State variable '{var_name}' was removed",
                    security_impact="Storage layout changed - potential upgrade incompatibility",
                ))

            elif new and not old:
                self.changes.append(CodeChange(
                    change_type=ChangeType.ADDED,
                    risk_level=RiskLevel.MEDIUM,
                    file_path="",
                    function_name=None,
                    old_code="",
                    new_code=new["declaration"],
                    line_number_old=0,
                    line_number_new=new["line"],
                    description=f"State variable '{var_name}' was added",
                    security_impact="New state variable - verify initialization",
                ))

            elif old["type"] != new["type"]:
                self.changes.append(CodeChange(
                    change_type=ChangeType.MODIFIED,
                    risk_level=RiskLevel.CRITICAL,
                    file_path="",
                    function_name=None,
                    old_code=old["declaration"],
                    new_code=new["declaration"],
                    line_number_old=old["line"],
                    line_number_new=new["line"],
                    description=f"State variable '{var_name}' type changed: {old['type']} -> {new['type']}",
                    security_impact="Type change - potential storage corruption on upgrade",
                ))

    def _extract_state_variables(self, source: str) -> dict[str, dict]:
        """Extract state variables from source."""
        variables = {}

        var_pattern = re.compile(
            r'^\s*(mapping\s*\([^)]+\)|uint\d*|int\d*|address|bool|bytes\d*|string|\w+(?:\[\d*\])?)\s+'
            r'(public|private|internal|immutable|constant)?\s*'
            r'(\w+)\s*(?:=\s*[^;]+)?;',
            re.MULTILINE
        )

        for match in var_pattern.finditer(source):
            var_type = match.group(1)
            visibility = match.group(2) or "internal"
            var_name = match.group(3)

            # Skip constants and immutables
            if visibility in ("constant", "immutable"):
                continue

            variables[var_name] = {
                "type": var_type,
                "visibility": visibility,
                "declaration": match.group(0).strip(),
                "line": source[:match.start()].count('\n') + 1,
            }

        return variables

    def _describe_changes(self, old: dict, new: dict) -> str:
        """Describe what changed in a function."""
        changes = []

        if old["params"] != new["params"]:
            changes.append("parameters changed")

        if old["modifiers"] != new["modifiers"]:
            changes.append("modifiers changed")

        if self._normalize(old["body"]) != self._normalize(new["body"]):
            changes.append("body changed")

        return ", ".join(changes) if changes else "unknown changes"

    def _assess_risk(
        self,
        code: str,
        change_type: str,
        old_code: str = "",
    ) -> RiskLevel:
        """Assess security risk of a change."""
        max_risk = RiskLevel.LOW

        for category, info in SECURITY_SENSITIVE_PATTERNS.items():
            for pattern in info["patterns"]:
                # Check if pattern is affected by change
                in_new = bool(re.search(pattern, code))
                in_old = bool(re.search(pattern, old_code)) if old_code else False

                # Change affects security-sensitive pattern
                if in_new != in_old or (in_new and change_type == "modified"):
                    if info["risk"].value < max_risk.value or max_risk == RiskLevel.LOW:
                        max_risk = info["risk"]

        return max_risk

    def _assess_security_impact(
        self,
        code: str,
        change_type: str,
        old_code: str = "",
    ) -> str:
        """Generate security impact description."""
        impacts = []

        for category, info in SECURITY_SENSITIVE_PATTERNS.items():
            for pattern in info["patterns"]:
                in_new = bool(re.search(pattern, code))
                in_old = bool(re.search(pattern, old_code)) if old_code else False

                if change_type == "removed" and in_old:
                    impacts.append(f"REMOVED: {info['description']}")
                elif change_type == "added" and in_new:
                    impacts.append(f"ADDED: {info['description']}")
                elif change_type == "modified" and (in_new or in_old):
                    impacts.append(f"MODIFIED: {info['description']}")

        return "; ".join(impacts) if impacts else "No obvious security impact"

    def _detect_regressions(self) -> None:
        """Detect potential security regressions from changes."""
        for change in self.changes:
            # High-risk removals
            if change.change_type == ChangeType.REMOVED:
                if "nonReentrant" in change.old_code or "ReentrancyGuard" in change.old_code:
                    self.regressions.append(RegressionRisk(
                        risk_level=RiskLevel.CRITICAL,
                        change=change,
                        title="Reentrancy Protection Removed",
                        description="nonReentrant modifier or ReentrancyGuard was removed",
                        vulnerable_pattern=r"\.call\{[^}]*\}\s*\(",
                        recommendation="Verify reentrancy is prevented by other means",
                    ))

                if "onlyOwner" in change.old_code or "onlyRole" in change.old_code:
                    self.regressions.append(RegressionRisk(
                        risk_level=RiskLevel.CRITICAL,
                        change=change,
                        title="Access Control Removed",
                        description="Access control modifier was removed from function",
                        vulnerable_pattern=r"function\s+\w+\s*\([^)]*\)\s*external",
                        recommendation="Verify function should be publicly accessible",
                    ))

            # Modifications to critical functions
            if change.change_type == ChangeType.MODIFIED:
                if change.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                    self.regressions.append(RegressionRisk(
                        risk_level=change.risk_level,
                        change=change,
                        title=f"Security-Sensitive Function Modified: {change.function_name}",
                        description=change.security_impact,
                        vulnerable_pattern=None,
                        recommendation="Thorough review required for this change",
                    ))

    def _check_fix_bypass(
        self,
        vulnerable: str,
        patched: str,
        pattern: str,
    ) -> Optional[str]:
        """Check if a fix can be bypassed."""
        # Common bypass patterns
        bypasses = []

        # Check if fix just moved the vulnerability
        if re.search(pattern, patched, re.DOTALL | re.IGNORECASE):
            bypasses.append("Vulnerability pattern still present (possibly moved)")

        # Check if new external calls were introduced
        old_calls = len(re.findall(r'\.call\{', vulnerable))
        new_calls = len(re.findall(r'\.call\{', patched))
        if new_calls > old_calls:
            bypasses.append("New external calls introduced - verify no new vectors")

        return "; ".join(bypasses) if bypasses else None

    def generate_report(self) -> str:
        """Generate markdown report of differential analysis."""
        report = ["# Differential Security Audit Report\n"]

        # Summary
        report.append("## Summary\n")
        report.append(f"- Total changes: {len(self.changes)}\n")
        report.append(f"- Potential regressions: {len(self.regressions)}\n\n")

        # Risk distribution
        risk_counts = {}
        for change in self.changes:
            risk_counts[change.risk_level.value] = risk_counts.get(change.risk_level.value, 0) + 1

        report.append("### Risk Distribution\n")
        for risk, count in sorted(risk_counts.items()):
            report.append(f"- {risk.upper()}: {count}\n")
        report.append("\n")

        # Regressions
        if self.regressions:
            report.append("## Potential Security Regressions\n")
            for reg in self.regressions:
                report.append(f"### {reg.title}\n")
                report.append(f"**Risk Level:** {reg.risk_level.value.upper()}\n\n")
                report.append(f"{reg.description}\n\n")
                report.append(f"**Recommendation:** {reg.recommendation}\n\n")

        # All changes
        report.append("## All Changes\n")
        for change in sorted(self.changes, key=lambda x: x.risk_level.value):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                change.risk_level.value, "⚪"
            )
            report.append(f"### {icon} {change.function_name or 'State Variable'}\n")
            report.append(f"**Type:** {change.change_type.value}\n")
            report.append(f"**Risk:** {change.risk_level.value}\n\n")
            report.append(f"{change.description}\n\n")
            report.append(f"**Security Impact:** {change.security_impact}\n\n")

        return "".join(report)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def diff_contracts(v1_source: str, v2_source: str) -> tuple[list[CodeChange], list[RegressionRisk]]:
    """Quick diff between two contract versions."""
    auditor = DifferentialAuditor()
    return auditor.diff(v1_source, v2_source)


def verify_vulnerability_fix(
    vulnerable_code: str,
    patched_code: str,
    vulnerability_pattern: str,
) -> dict:
    """Verify that a vulnerability fix is effective."""
    auditor = DifferentialAuditor()
    return auditor.verify_fix(vulnerable_code, patched_code, vulnerability_pattern)
