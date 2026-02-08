"""
Self-Improving Feedback Loop - Learn From Every Audit

The best auditors learn from experience.
This module makes SENTINEL learn from:
1. Which findings were valid vs invalid
2. Which PoCs worked vs failed
3. Which patterns were most effective
4. Which contests were won vs lost

Over time, SENTINEL gets BETTER, not just bigger.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path
from enum import Enum


class FindingOutcome(Enum):
    VALID_CRITICAL = "valid_critical"
    VALID_HIGH = "valid_high"
    VALID_MEDIUM = "valid_medium"
    VALID_LOW = "valid_low"
    INVALID = "invalid"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    WONT_FIX = "wont_fix"


class ContestResult(Enum):
    WON = "won"           # Top 3
    PLACED = "placed"     # Top 10
    PARTICIPATED = "participated"
    BOMBED = "bombed"     # No valid findings


@dataclass
class AuditRecord:
    """Record of a single audit."""
    id: str
    date: datetime
    protocol: str
    chain: str
    nsloc: int
    findings_submitted: int
    findings_valid: int
    findings_invalid: int
    payout_usd: float
    patterns_used: list[str]
    time_spent_hours: float
    contest_result: Optional[ContestResult] = None
    notes: str = ""


@dataclass
class FindingRecord:
    """Record of a single finding."""
    id: str
    audit_id: str
    title: str
    severity: str
    outcome: FindingOutcome
    pattern_ids: list[str]
    poc_worked: bool
    detection_method: str  # pattern, semantic, symbolic, llm, manual
    time_to_find_minutes: int
    confidence_score: float
    actual_confidence: float  # After judging
    notes: str = ""


@dataclass
class PatternPerformance:
    """Performance metrics for a detection pattern."""
    pattern_id: str
    times_triggered: int
    true_positives: int
    false_positives: int
    precision: float  # TP / (TP + FP)
    avg_severity: float  # Average severity of valid findings
    avg_payout: float  # Average payout when pattern leads to valid finding
    last_updated: datetime = field(default_factory=datetime.now)


class AuditFeedbackLoop:
    """
    Track audit results and improve over time.

    Maintains:
    - Historical audit records
    - Finding validity rates
    - Pattern performance metrics
    - Win/loss analysis
    """

    def __init__(self, storage_path: str = ".sentinel/history"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.audits: list[AuditRecord] = []
        self.findings: list[FindingRecord] = []
        self.pattern_stats: dict[str, PatternPerformance] = {}

        self._load_history()

    def _load_history(self):
        """Load historical data from disk."""
        audits_file = self.storage_path / "audits.json"
        if audits_file.exists():
            with open(audits_file) as f:
                data = json.load(f)
                # Parse into dataclasses
                pass

        findings_file = self.storage_path / "findings.json"
        if findings_file.exists():
            with open(findings_file) as f:
                data = json.load(f)
                pass

        patterns_file = self.storage_path / "patterns.json"
        if patterns_file.exists():
            with open(patterns_file) as f:
                data = json.load(f)
                pass

    def _save_history(self):
        """Save historical data to disk."""
        with open(self.storage_path / "audits.json", 'w') as f:
            json.dump([vars(a) for a in self.audits], f, default=str, indent=2)

        with open(self.storage_path / "findings.json", 'w') as f:
            json.dump([vars(f) for f in self.findings], f, default=str, indent=2)

        with open(self.storage_path / "patterns.json", 'w') as f:
            json.dump({k: vars(v) for k, v in self.pattern_stats.items()}, f, default=str, indent=2)

    def record_audit(self, audit: AuditRecord):
        """Record a completed audit."""
        self.audits.append(audit)
        self._save_history()

    def record_finding(self, finding: FindingRecord):
        """Record a finding and its outcome."""
        self.findings.append(finding)

        # Update pattern stats
        for pattern_id in finding.pattern_ids:
            if pattern_id not in self.pattern_stats:
                self.pattern_stats[pattern_id] = PatternPerformance(
                    pattern_id=pattern_id,
                    times_triggered=0,
                    true_positives=0,
                    false_positives=0,
                    precision=0,
                    avg_severity=0,
                    avg_payout=0,
                )

            stats = self.pattern_stats[pattern_id]
            stats.times_triggered += 1

            if finding.outcome in [
                FindingOutcome.VALID_CRITICAL,
                FindingOutcome.VALID_HIGH,
                FindingOutcome.VALID_MEDIUM,
                FindingOutcome.VALID_LOW,
            ]:
                stats.true_positives += 1
            else:
                stats.false_positives += 1

            # Update precision
            total = stats.true_positives + stats.false_positives
            stats.precision = stats.true_positives / total if total > 0 else 0

        self._save_history()

    def get_pattern_recommendations(self) -> list[dict]:
        """
        Get recommendations for pattern usage based on historical performance.

        Returns patterns sorted by effectiveness.
        """
        recommendations = []

        for pattern_id, stats in self.pattern_stats.items():
            if stats.times_triggered >= 5:  # Need enough data
                recommendations.append({
                    "pattern_id": pattern_id,
                    "precision": stats.precision,
                    "times_used": stats.times_triggered,
                    "recommendation": self._get_pattern_recommendation(stats),
                })

        return sorted(recommendations, key=lambda x: x["precision"], reverse=True)

    def _get_pattern_recommendation(self, stats: PatternPerformance) -> str:
        """Get recommendation for a pattern."""
        if stats.precision >= 0.8:
            return "HIGH VALUE - Use confidently"
        elif stats.precision >= 0.5:
            return "MODERATE VALUE - Verify findings manually"
        elif stats.precision >= 0.2:
            return "LOW VALUE - High false positive rate"
        else:
            return "POOR VALUE - Consider disabling"

    def get_overall_stats(self) -> dict:
        """Get overall performance statistics."""
        if not self.audits:
            return {"message": "No audit history yet"}

        total_findings = len(self.findings)
        valid_findings = sum(
            1 for f in self.findings
            if f.outcome in [
                FindingOutcome.VALID_CRITICAL,
                FindingOutcome.VALID_HIGH,
                FindingOutcome.VALID_MEDIUM,
                FindingOutcome.VALID_LOW,
            ]
        )

        total_payout = sum(a.payout_usd for a in self.audits)
        avg_payout = total_payout / len(self.audits) if self.audits else 0

        wins = sum(1 for a in self.audits if a.contest_result == ContestResult.WON)
        placements = sum(1 for a in self.audits if a.contest_result == ContestResult.PLACED)

        return {
            "total_audits": len(self.audits),
            "total_findings": total_findings,
            "valid_findings": valid_findings,
            "precision": valid_findings / total_findings if total_findings > 0 else 0,
            "total_payout_usd": total_payout,
            "avg_payout_per_audit": avg_payout,
            "contest_wins": wins,
            "contest_placements": placements,
            "top_patterns": self._get_top_patterns(5),
            "worst_patterns": self._get_worst_patterns(3),
        }

    def _get_top_patterns(self, n: int) -> list[dict]:
        """Get top N performing patterns."""
        sorted_patterns = sorted(
            self.pattern_stats.values(),
            key=lambda x: (x.precision, x.true_positives),
            reverse=True,
        )
        return [
            {"id": p.pattern_id, "precision": p.precision, "hits": p.true_positives}
            for p in sorted_patterns[:n]
        ]

    def _get_worst_patterns(self, n: int) -> list[dict]:
        """Get worst N performing patterns (candidates for removal)."""
        sorted_patterns = sorted(
            [p for p in self.pattern_stats.values() if p.times_triggered >= 3],
            key=lambda x: x.precision,
        )
        return [
            {"id": p.pattern_id, "precision": p.precision, "false_positives": p.false_positives}
            for p in sorted_patterns[:n]
        ]

    def suggest_improvements(self) -> list[dict]:
        """
        Analyze history and suggest improvements.

        Returns actionable suggestions.
        """
        suggestions = []

        # Check for patterns with high false positive rates
        for pattern_id, stats in self.pattern_stats.items():
            if stats.precision < 0.3 and stats.times_triggered >= 5:
                suggestions.append({
                    "type": "REMOVE_PATTERN",
                    "pattern_id": pattern_id,
                    "reason": f"Only {stats.precision:.0%} precision over {stats.times_triggered} uses",
                    "action": "Consider removing or tightening this pattern",
                })

        # Check for underperforming detection methods
        method_stats = {}
        for finding in self.findings:
            if finding.detection_method not in method_stats:
                method_stats[finding.detection_method] = {"valid": 0, "total": 0}
            method_stats[finding.detection_method]["total"] += 1
            if finding.outcome.value.startswith("valid"):
                method_stats[finding.detection_method]["valid"] += 1

        for method, stats in method_stats.items():
            precision = stats["valid"] / stats["total"] if stats["total"] > 0 else 0
            if precision < 0.4 and stats["total"] >= 10:
                suggestions.append({
                    "type": "IMPROVE_METHOD",
                    "method": method,
                    "reason": f"Only {precision:.0%} precision for {method} detection",
                    "action": "Review and improve this detection method",
                })

        # Check for missed opportunities
        high_value_misses = [
            f for f in self.findings
            if f.outcome == FindingOutcome.DUPLICATE
            and f.severity in ["CRITICAL", "HIGH"]
        ]
        if len(high_value_misses) >= 3:
            suggestions.append({
                "type": "SPEED_UP",
                "reason": f"{len(high_value_misses)} high-value findings were duplicates",
                "action": "Focus on finding these patterns faster",
            })

        return suggestions


def learn_from_result(
    audit_id: str,
    findings: list[dict],
    outcomes: list[str],
    payout: float,
) -> dict:
    """
    Learn from audit results.

    Call this after receiving contest/audit results.
    """
    feedback = AuditFeedbackLoop()

    # Record each finding
    for finding, outcome in zip(findings, outcomes):
        finding_record = FindingRecord(
            id=f"{audit_id}-{finding.get('id', 'unknown')}",
            audit_id=audit_id,
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            outcome=FindingOutcome(outcome),
            pattern_ids=finding.get("patterns", []),
            poc_worked=finding.get("poc_worked", False),
            detection_method=finding.get("method", "unknown"),
            time_to_find_minutes=finding.get("time", 0),
            confidence_score=finding.get("confidence", 0),
            actual_confidence=1.0 if outcome.startswith("valid") else 0.0,
        )
        feedback.record_finding(finding_record)

    return {
        "recorded": True,
        "stats": feedback.get_overall_stats(),
        "suggestions": feedback.suggest_improvements(),
    }


def get_historical_accuracy() -> dict:
    """Get historical accuracy statistics."""
    feedback = AuditFeedbackLoop()
    return feedback.get_overall_stats()


class CompetitionIntelligence:
    """
    Intelligence about security competitions.

    Tracks:
    - Which platforms pay best
    - What bug types win most often
    - Optimal contest selection
    """

    PLATFORM_STATS = {
        "code4rena": {
            "avg_pool": 50000,
            "top_payout_rate": 0.15,  # Top hunters get ~15% of pool
            "competition_level": "HIGH",
            "best_bug_types": ["reentrancy", "access_control", "logic"],
        },
        "sherlock": {
            "avg_pool": 40000,
            "top_payout_rate": 0.20,
            "competition_level": "HIGH",
            "best_bug_types": ["economic", "oracle", "integration"],
        },
        "immunefi": {
            "avg_bounty": 10000,
            "max_bounty": 10000000,
            "competition_level": "MEDIUM",  # Less competitive, more scope
            "best_bug_types": ["critical", "bridge", "consensus"],
        },
        "cantina": {
            "avg_pool": 100000,
            "top_payout_rate": 0.25,
            "competition_level": "VERY_HIGH",
            "best_bug_types": ["novel", "complex", "economic"],
        },
    }

    @classmethod
    def recommend_contests(cls, skills: list[str], time_hours: int) -> list[dict]:
        """
        Recommend contests based on skills and available time.

        Args:
            skills: List of vulnerability types you're good at
            time_hours: Available time for the contest

        Returns:
            Ranked contest recommendations
        """
        recommendations = []

        for platform, stats in cls.PLATFORM_STATS.items():
            skill_match = len(set(skills) & set(stats["best_bug_types"]))
            expected_value = stats.get("avg_pool", stats.get("avg_bounty", 0)) * stats.get("top_payout_rate", 0.1)

            recommendations.append({
                "platform": platform,
                "skill_match": skill_match,
                "expected_value": expected_value,
                "competition": stats["competition_level"],
                "recommendation": "STRONG" if skill_match >= 2 else "MODERATE" if skill_match >= 1 else "WEAK",
            })

        return sorted(recommendations, key=lambda x: x["expected_value"], reverse=True)
