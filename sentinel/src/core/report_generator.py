"""
Professional Audit Report Generator

Outputs:
1. Contest-ready reports (Code4rena, Sherlock, Immunefi format)
2. Professional audit reports (Trail of Bits, OpenZeppelin style)
3. Executive summaries for non-technical stakeholders

NO FLUFF. Evidence-based. Judge-proof.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    GAS = "Gas Optimization"


class ReportFormat(Enum):
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    IMMUNEFI = "immunefi"
    PROFESSIONAL = "professional"
    EXECUTIVE = "executive"


@dataclass
class Finding:
    """Single vulnerability finding with all required evidence."""

    # Required fields
    id: str  # e.g., "H-01", "M-02"
    title: str  # Concise, descriptive
    severity: Severity
    category: str  # e.g., "Reentrancy", "Access Control"

    # Evidence (ALL required for valid finding)
    root_cause: str  # Technical explanation of the bug
    vulnerable_code: str  # Exact code snippet with file:line
    attack_path: list[str]  # Step-by-step exploitation
    impact: str  # Quantified impact ($ or %)
    likelihood: str  # How likely is exploitation

    # Proof
    poc_code: str  # Working PoC
    poc_output: str  # Expected output showing success

    # Fix
    recommendation: str  # Specific fix
    fixed_code: str  # Corrected code snippet

    # Optional
    references: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AuditReport:
    """Complete audit report."""
    project_name: str
    auditor: str
    audit_date: str
    commit_hash: str
    scope: list[str]
    findings: list[Finding]
    executive_summary: str = ""


class ReportGenerator:
    """Generate professional audit reports."""

    def generate(
        self,
        report: AuditReport,
        format: ReportFormat = ReportFormat.PROFESSIONAL
    ) -> str:
        """Generate report in specified format."""

        if format == ReportFormat.CODE4RENA:
            return self._generate_code4rena(report)
        elif format == ReportFormat.SHERLOCK:
            return self._generate_sherlock(report)
        elif format == ReportFormat.IMMUNEFI:
            return self._generate_immunefi(report)
        elif format == ReportFormat.PROFESSIONAL:
            return self._generate_professional(report)
        elif format == ReportFormat.EXECUTIVE:
            return self._generate_executive(report)

        return self._generate_professional(report)

    def _generate_code4rena(self, report: AuditReport) -> str:
        """Generate Code4rena contest submission format."""
        output = []

        # Group by severity
        for severity in [Severity.HIGH, Severity.MEDIUM]:
            findings = [f for f in report.findings if f.severity == severity]
            if not findings:
                continue

            for finding in findings:
                output.append(self._format_c4_finding(finding))

        # QA Report (Low + Info)
        qa_findings = [f for f in report.findings
                      if f.severity in [Severity.LOW, Severity.INFORMATIONAL]]
        if qa_findings:
            output.append("\n---\n# QA Report\n")
            for finding in qa_findings:
                output.append(self._format_c4_qa(finding))

        return "\n".join(output)

    def _format_c4_finding(self, f: Finding) -> str:
        """Format single Code4rena finding."""
        return f'''# [{f.id}] {f.title}

## Summary
{f.root_cause}

## Vulnerability Detail
{f.root_cause}

### Vulnerable Code
```solidity
{f.vulnerable_code}
```

### Attack Path
{self._format_numbered_list(f.attack_path)}

## Impact
{f.impact}

**Likelihood:** {f.likelihood}

## Proof of Concept
```solidity
{f.poc_code}
```

**Expected Output:**
```
{f.poc_output}
```

## Recommended Mitigation
{f.recommendation}

```solidity
{f.fixed_code}
```

---
'''

    def _format_c4_qa(self, f: Finding) -> str:
        """Format QA finding for Code4rena."""
        return f'''## [{f.id}] {f.title}

{f.root_cause}

**Code:**
```solidity
{f.vulnerable_code}
```

**Recommendation:** {f.recommendation}

---
'''

    def _generate_sherlock(self, report: AuditReport) -> str:
        """Generate Sherlock contest format."""
        output = []

        for finding in report.findings:
            if finding.severity not in [Severity.HIGH, Severity.MEDIUM]:
                continue

            output.append(f'''## {finding.title}

### Summary
{finding.root_cause}

### Root Cause
In `{finding.vulnerable_code.split(":")[0] if ":" in finding.vulnerable_code else "contract"}`:
```solidity
{finding.vulnerable_code}
```

### Internal pre-conditions
1. Contract must be deployed with vulnerable code
2. Attacker has access to public/external functions

### External pre-conditions
None required.

### Attack Path
{self._format_numbered_list(finding.attack_path)}

### Impact
{finding.impact}

### PoC
```solidity
{finding.poc_code}
```

### Mitigation
{finding.recommendation}

```solidity
{finding.fixed_code}
```

---
''')

        return "\n".join(output)

    def _generate_immunefi(self, report: AuditReport) -> str:
        """Generate Immunefi bug bounty report format."""
        output = []

        for finding in report.findings:
            # Immunefi focuses on critical/high for bounties
            if finding.severity not in [Severity.CRITICAL, Severity.HIGH]:
                continue

            output.append(f'''# Bug Report: {finding.title}

## Brief/Intro
{finding.root_cause}

## Vulnerability Details
### Affected Component
```
{finding.vulnerable_code}
```

### Technical Description
{finding.root_cause}

### Attack Scenario
{self._format_numbered_list(finding.attack_path)}

## Impact Details
{finding.impact}

### Severity Justification
- **Likelihood:** {finding.likelihood}
- **Impact:** {finding.impact}
- **Overall:** {finding.severity.value}

## References
{self._format_bullet_list(finding.references) if finding.references else "N/A"}

## Proof of Concept
```solidity
{finding.poc_code}
```

### Steps to Reproduce
1. Copy PoC to `test/Exploit.t.sol`
2. Run: `forge test --match-contract ExploitTest -vvvv`
3. Observe output showing successful exploitation

### Expected Output
```
{finding.poc_output}
```

## Recommendation
{finding.recommendation}

### Suggested Fix
```solidity
{finding.fixed_code}
```

---
''')

        return "\n".join(output)

    def _generate_professional(self, report: AuditReport) -> str:
        """Generate professional audit report (ToB/OZ style)."""

        # Count by severity
        counts = {s: len([f for f in report.findings if f.severity == s])
                 for s in Severity}

        return f'''# Security Audit Report

## {report.project_name}

**Auditor:** {report.auditor}
**Date:** {report.audit_date}
**Commit:** `{report.commit_hash}`

---

## Executive Summary

{report.executive_summary or self._generate_exec_summary(report)}

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {counts.get(Severity.CRITICAL, 0)} |
| High | {counts.get(Severity.HIGH, 0)} |
| Medium | {counts.get(Severity.MEDIUM, 0)} |
| Low | {counts.get(Severity.LOW, 0)} |
| Informational | {counts.get(Severity.INFORMATIONAL, 0)} |

---

## Scope

The following contracts were in scope:

{self._format_bullet_list(report.scope)}

---

## Findings

{self._format_professional_findings(report.findings)}

---

## Appendix

### Methodology
- Manual code review
- Automated analysis (Slither, Mythril)
- Custom exploit development
- Invariant testing

### Severity Definitions

| Severity | Description |
|----------|-------------|
| Critical | Direct loss of funds, no preconditions |
| High | Loss of funds with preconditions, significant impact |
| Medium | Limited impact, unlikely scenarios |
| Low | Best practices, minor issues |
| Informational | Suggestions, no security impact |

---

*Report generated by SENTINEL*
'''

    def _format_professional_findings(self, findings: list[Finding]) -> str:
        """Format findings for professional report."""
        output = []

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                        Severity.LOW, Severity.INFORMATIONAL]:
            severity_findings = [f for f in findings if f.severity == severity]
            if not severity_findings:
                continue

            output.append(f"### {severity.value} Severity\n")

            for finding in severity_findings:
                output.append(f'''#### {finding.id}: {finding.title}

**Category:** {finding.category}

**Description:**
{finding.root_cause}

**Affected Code:**
```solidity
{finding.vulnerable_code}
```

**Exploitation:**
{self._format_numbered_list(finding.attack_path)}

**Impact:**
{finding.impact}

**Proof of Concept:**
```solidity
{finding.poc_code}
```

**Recommendation:**
{finding.recommendation}

**Suggested Fix:**
```solidity
{finding.fixed_code}
```

---
''')

        return "\n".join(output)

    def _generate_executive(self, report: AuditReport) -> str:
        """Generate executive summary for non-technical stakeholders."""

        critical_high = [f for f in report.findings
                        if f.severity in [Severity.CRITICAL, Severity.HIGH]]

        risk_level = "HIGH" if critical_high else "MEDIUM" if report.findings else "LOW"

        return f'''# Security Assessment Summary

## {report.project_name}

**Assessment Date:** {report.audit_date}
**Overall Risk Level:** {risk_level}

---

## Key Findings

{len(critical_high)} critical/high severity issues were identified that require immediate attention.

### Issues Requiring Immediate Action

{self._format_executive_findings(critical_high) if critical_high else "No critical issues found."}

---

## Recommendations

1. Address all critical and high severity findings before deployment
2. Implement suggested fixes and verify with follow-up review
3. Consider additional security measures (monitoring, circuit breakers)

---

## Risk Summary

| Risk Category | Status |
|--------------|--------|
| Loss of Funds | {"HIGH RISK" if any(f.severity == Severity.CRITICAL for f in report.findings) else "Mitigated"} |
| Access Control | {"NEEDS REVIEW" if any("access" in f.category.lower() for f in report.findings) else "Adequate"} |
| Economic Attacks | {"NEEDS REVIEW" if any("economic" in f.category.lower() or "oracle" in f.category.lower() for f in report.findings) else "Adequate"} |

---

*This is an executive summary. See full technical report for details.*
'''

    def _format_executive_findings(self, findings: list[Finding]) -> str:
        """Format findings for executive summary."""
        output = []
        for f in findings:
            output.append(f'''### {f.title}
**Severity:** {f.severity.value}
**Impact:** {f.impact}
**Status:** Requires Fix
''')
        return "\n".join(output)

    def _generate_exec_summary(self, report: AuditReport) -> str:
        """Auto-generate executive summary."""
        total = len(report.findings)
        critical = len([f for f in report.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in report.findings if f.severity == Severity.HIGH])

        if critical > 0:
            risk = "critical risk"
            action = "immediate remediation required before deployment"
        elif high > 0:
            risk = "high risk"
            action = "significant fixes required before deployment"
        elif total > 0:
            risk = "moderate risk"
            action = "recommended fixes before deployment"
        else:
            risk = "low risk"
            action = "no critical issues identified"

        return f'''This security audit identified {total} findings, including {critical} critical and {high} high severity issues. The overall security posture represents {risk}, with {action}.'''

    def _format_numbered_list(self, items: list[str]) -> str:
        """Format as numbered list."""
        return "\n".join(f"{i+1}. {item}" for i, item in enumerate(items))

    def _format_bullet_list(self, items: list[str]) -> str:
        """Format as bullet list."""
        return "\n".join(f"- {item}" for item in items)


# Convenience function
def generate_report(
    project_name: str,
    auditor: str,
    findings: list[Finding],
    scope: list[str],
    commit_hash: str = "",
    format: ReportFormat = ReportFormat.PROFESSIONAL,
) -> str:
    """Generate audit report."""
    report = AuditReport(
        project_name=project_name,
        auditor=auditor,
        audit_date=datetime.now().strftime("%Y-%m-%d"),
        commit_hash=commit_hash,
        scope=scope,
        findings=findings,
    )
    return ReportGenerator().generate(report, format)
