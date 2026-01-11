"""
Competitive Intelligence - Learn from winning audit reports.

Top auditors learn from:
- Code4rena winning reports
- Sherlock lead judge decisions
- Immunefi high-value bounties
- Trail of Bits/Spearbit public reports

This system:
1. Analyzes winning report patterns
2. Calibrates severity assessment
3. Learns effective writing styles
4. Tracks judge preferences
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

from rich.console import Console
from rich.table import Table

console = Console()


class ContestPlatform(Enum):
    """Audit contest platforms."""
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    CANTINA = "cantina"
    IMMUNEFI = "immunefi"
    HATS = "hats"


class ReportQuality(Enum):
    """Quality rating of a report."""
    SELECTED = "selected"       # Won/selected for rewards
    VALID = "valid"             # Accepted but not top
    DUPLICATE = "duplicate"     # Valid but duplicate
    INVALID = "invalid"         # Rejected


@dataclass
class WinningReport:
    """A winning audit report."""
    id: str
    platform: ContestPlatform
    contest: str
    title: str
    severity: str
    vulnerability_type: str
    payout: float
    quality: ReportQuality
    description: str
    impact: str
    poc: str
    recommendation: str
    judge_comments: str = ""
    auditor: str = ""
    date: str = ""


@dataclass
class SeverityCalibration:
    """Calibration data for severity assessment."""
    vulnerability_type: str
    reported_severity: str  # What auditor reported
    judged_severity: str    # What judge decided
    platform: ContestPlatform
    reasoning: str


@dataclass
class WritingPattern:
    """Effective writing pattern from winning reports."""
    pattern_type: str  # title, impact, poc, recommendation
    example: str
    effectiveness_score: float  # 0-1
    source_report: str


class CompetitiveIntelligence:
    """
    Learn from winning audit reports to improve findings quality.

    Features:
    - Severity calibration based on historical judging
    - Winning writing patterns
    - Judge preference learning
    - Effective PoC styles
    """

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or Path(__file__).parent.parent.parent / "knowledge_base" / "reports"
        self.winning_reports: list[WinningReport] = []
        self.calibrations: list[SeverityCalibration] = []
        self.patterns: list[WritingPattern] = []
        self._loaded = False

    def load_data(self) -> None:
        """Load competitive intelligence data."""
        if self._loaded:
            return

        # Load from YAML files if available
        import yaml

        reports_file = self.data_path / "winning_reports.yaml"
        if reports_file.exists():
            with open(reports_file) as f:
                data = yaml.safe_load(f)
                for r in data.get("reports", []):
                    self.winning_reports.append(WinningReport(**r))

        calibrations_file = self.data_path / "severity_calibrations.yaml"
        if calibrations_file.exists():
            with open(calibrations_file) as f:
                data = yaml.safe_load(f)
                for c in data.get("calibrations", []):
                    self.calibrations.append(SeverityCalibration(**c))

        self._loaded = True
        console.print(f"[green]Loaded {len(self.winning_reports)} winning reports[/green]")

    def get_severity_calibration(
        self,
        vulnerability_type: str,
        platform: Optional[ContestPlatform] = None,
    ) -> dict:
        """Get severity calibration for a vulnerability type."""
        self.load_data()

        relevant = [c for c in self.calibrations if vulnerability_type.lower() in c.vulnerability_type.lower()]

        if platform:
            relevant = [c for c in relevant if c.platform == platform]

        if not relevant:
            return {"adjustment": None, "confidence": 0}

        # Count severity adjustments
        adjustments = {}
        for c in relevant:
            key = (c.reported_severity, c.judged_severity)
            adjustments[key] = adjustments.get(key, 0) + 1

        # Find most common pattern
        if adjustments:
            most_common = max(adjustments.items(), key=lambda x: x[1])
            (reported, judged), count = most_common

            return {
                "reported": reported,
                "judged": judged,
                "samples": len(relevant),
                "confidence": count / len(relevant),
                "adjustment": "downgrade" if self._severity_rank(judged) > self._severity_rank(reported) else "upgrade" if self._severity_rank(judged) < self._severity_rank(reported) else "none",
            }

        return {"adjustment": None, "confidence": 0}

    def _severity_rank(self, severity: str) -> int:
        """Get numeric rank for severity."""
        ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        return ranks.get(severity.lower(), 5)

    def get_similar_winning_reports(
        self,
        vulnerability_type: str,
        n: int = 5,
    ) -> list[WinningReport]:
        """Find similar winning reports for reference."""
        self.load_data()

        # Simple keyword matching
        vuln_lower = vulnerability_type.lower()

        scored = []
        for report in self.winning_reports:
            if report.quality != ReportQuality.SELECTED:
                continue

            score = 0
            if vuln_lower in report.vulnerability_type.lower():
                score += 3
            if vuln_lower in report.description.lower():
                score += 1
            if vuln_lower in report.title.lower():
                score += 2

            if score > 0:
                scored.append((report, score))

        scored.sort(key=lambda x: (-x[1], -x[0].payout))
        return [r for r, _ in scored[:n]]

    def get_effective_patterns(
        self,
        pattern_type: str,  # title, impact, poc, recommendation
        n: int = 5,
    ) -> list[WritingPattern]:
        """Get effective writing patterns."""
        self.load_data()

        matching = [p for p in self.patterns if p.pattern_type == pattern_type]
        matching.sort(key=lambda x: x.effectiveness_score, reverse=True)
        return matching[:n]

    def calibrate_severity(
        self,
        current_severity: str,
        vulnerability_type: str,
        platform: ContestPlatform = ContestPlatform.CODE4RENA,
    ) -> str:
        """Calibrate severity based on historical data."""
        calibration = self.get_severity_calibration(vulnerability_type, platform)

        if calibration.get("confidence", 0) < 0.5:
            return current_severity  # Not enough data

        if calibration.get("adjustment") == "downgrade":
            # Suggest downgrade
            return calibration.get("judged", current_severity)

        return current_severity

    def generate_report_improvement_suggestions(
        self,
        finding_title: str,
        finding_impact: str,
        vulnerability_type: str,
    ) -> list[str]:
        """Generate suggestions to improve finding quality."""
        self.load_data()

        suggestions = []

        # Check title patterns
        similar = self.get_similar_winning_reports(vulnerability_type, 3)
        if similar:
            suggestions.append(f"Reference winning titles: {[r.title[:50] for r in similar]}")

        # Check impact patterns
        impact_patterns = self.get_effective_patterns("impact", 3)
        if impact_patterns:
            suggestions.append("Effective impact patterns found - use quantified damages")

        # General suggestions based on winning patterns
        suggestions.extend([
            "Include specific dollar amounts at risk if possible",
            "Provide step-by-step attack scenario",
            "Include working PoC code",
            "Reference similar historical exploits",
            "Use clear, direct language",
        ])

        return suggestions


class SeverityCalibrator:
    """
    Calibrate severity based on historical contest judging.

    Learns the boundary between:
    - High vs Medium
    - Medium vs Low
    - Valid vs Invalid
    """

    # Hardcoded calibration data from real contests
    CALIBRATION_DATA = {
        # Vulnerability type -> (typical reported, typical judged, notes)
        "reentrancy": ("high", "high", "Usually accepted as high if funds at risk"),
        "reentrancy_read_only": ("high", "medium", "Often downgraded unless direct fund loss"),
        "oracle_manipulation": ("high", "high", "High if price impact > 5%"),
        "access_control": ("high", "high", "High if unauthorized access to funds/admin"),
        "front_running": ("medium", "medium", "Usually medium unless guaranteed profit"),
        "dos": ("medium", "low", "Often downgraded, temporary issues"),
        "gas_optimization": ("low", "gas", "Usually separated into gas category"),
        "centralization": ("medium", "low", "Often downgraded as 'admin trust'"),
        "first_depositor": ("high", "medium", "Medium if mitigated by seed deposit"),
        "flash_loan_governance": ("critical", "high", "Critical only if unconditional"),
    }

    def __init__(self, platform: ContestPlatform = ContestPlatform.CODE4RENA):
        self.platform = platform

    def calibrate(self, vulnerability_type: str, current_severity: str) -> tuple[str, str]:
        """
        Calibrate severity and return (adjusted_severity, reasoning).
        """
        vuln_lower = vulnerability_type.lower().replace("_", " ").replace("-", " ")

        # Find matching calibration
        for key, (reported, judged, notes) in self.CALIBRATION_DATA.items():
            if key.replace("_", " ") in vuln_lower or vuln_lower in key.replace("_", " "):
                if current_severity.lower() != judged:
                    return (
                        judged,
                        f"Historical data suggests {key} is typically judged as {judged}. {notes}"
                    )
                return (current_severity, "Severity aligns with historical judging")

        return (current_severity, "No historical calibration data available")

    def get_severity_boundaries(self) -> dict:
        """Get severity boundary definitions."""
        return {
            "critical_high_boundary": [
                "CRITICAL: Direct, unconditional loss of funds for any user/protocol",
                "HIGH: Conditional loss of funds, requires specific preconditions",
            ],
            "high_medium_boundary": [
                "HIGH: Financial loss with realistic attack path",
                "MEDIUM: Limited loss, griefing, temporary issues",
            ],
            "medium_low_boundary": [
                "MEDIUM: Clear impact but limited scope",
                "LOW: Edge cases, unlikely scenarios, best practices",
            ],
            "valid_invalid_boundary": [
                "VALID: Clear vulnerability with demonstrable impact",
                "INVALID: Theoretical, requires admin trust, no real impact",
            ],
        }


class JudgePreferenceTracker:
    """
    Track judge preferences for better submissions.

    Different judges have different standards:
    - Some are strict on severity
    - Some prioritize PoC quality
    - Some focus on impact quantification
    """

    KNOWN_PREFERENCES = {
        "code4rena": {
            "severity_strictness": "high",
            "poc_required": True,
            "impact_quantification": "preferred",
            "duplicate_handling": "first_valid_wins",
            "notes": "Strict severity standards, PoC strongly encouraged",
        },
        "sherlock": {
            "severity_strictness": "medium",
            "poc_required": False,
            "impact_quantification": "required",
            "duplicate_handling": "proportional_split",
            "notes": "Clear impact statement required, PoC optional but helpful",
        },
        "immunefi": {
            "severity_strictness": "low",
            "poc_required": True,
            "impact_quantification": "required",
            "duplicate_handling": "first_report_wins",
            "notes": "Working PoC required, dollar impact important for payout",
        },
    }

    def get_platform_guidance(self, platform: str) -> dict:
        """Get platform-specific submission guidance."""
        return self.KNOWN_PREFERENCES.get(platform.lower(), {
            "notes": "No specific guidance available for this platform",
        })


# Convenience functions
def calibrate_severity(
    vulnerability_type: str,
    current_severity: str,
    platform: str = "code4rena",
) -> tuple[str, str]:
    """Quick severity calibration."""
    calibrator = SeverityCalibrator(ContestPlatform(platform))
    return calibrator.calibrate(vulnerability_type, current_severity)


def get_platform_guidance(platform: str) -> dict:
    """Get submission guidance for a platform."""
    tracker = JudgePreferenceTracker()
    return tracker.get_platform_guidance(platform)
