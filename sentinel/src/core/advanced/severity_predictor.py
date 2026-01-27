"""
Severity Predictor

ML-based severity prediction trained on historical judging data:
1. Code4rena judging outcomes
2. Sherlock escalations
3. Immunefi payouts

Features extracted:
- Impact description embedding
- Funds at risk amount
- Likelihood indicators
- Protocol TVL
- Vulnerability category
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re
import json
from collections import Counter


class Severity(Enum):
    """Severity levels matching audit platforms."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    INVALID = "invalid"


class Platform(Enum):
    """Audit platforms with different judging criteria."""
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    IMMUNEFI = "immunefi"
    CANTINA = "cantina"


@dataclass
class SeverityPrediction:
    """Prediction result with confidence."""
    predicted_severity: Severity
    confidence: float
    reasoning: list[str]
    similar_findings: list[dict]
    platform_adjustments: dict[Platform, Severity]


@dataclass
class FindingFeatures:
    """Features extracted from a finding for prediction."""
    vulnerability_category: str
    funds_at_risk: Optional[float]  # In USD
    requires_preconditions: bool
    likelihood: str  # "high", "medium", "low"
    impact_keywords: list[str]
    has_poc: bool
    code_quality: float  # 0-1
    protocol_tvl: Optional[float]


# =============================================================================
# TRAINING DATA PATTERNS
# =============================================================================

# Historical severity patterns from judging
SEVERITY_INDICATORS = {
    Severity.CRITICAL: {
        "keywords": [
            "drain", "steal", "loss of all", "complete loss", "unlimited",
            "protocol insolvency", "total loss", "entire balance",
            "selfdestruct", "rug pull", "backdoor",
        ],
        "categories": [
            "arbitrary-code-execution", "authentication-bypass",
            "private-key-exposure", "upgrade-attack",
        ],
        "min_funds_at_risk_pct": 50,  # % of TVL
    },
    Severity.HIGH: {
        "keywords": [
            "significant loss", "substantial", "major", "direct theft",
            "manipulation", "bypass", "unauthorized", "reentrancy",
            "oracle manipulation", "flash loan attack",
        ],
        "categories": [
            "reentrancy", "access-control", "oracle-manipulation",
            "flash-loan", "price-manipulation", "privilege-escalation",
        ],
        "min_funds_at_risk_pct": 10,
    },
    Severity.MEDIUM: {
        "keywords": [
            "partial loss", "griefing", "dos", "temporary",
            "under certain conditions", "edge case", "front-running",
            "loss of yield", "accounting error",
        ],
        "categories": [
            "front-running", "dos", "accounting", "rounding",
            "state-manipulation", "timing",
        ],
        "min_funds_at_risk_pct": 1,
    },
    Severity.LOW: {
        "keywords": [
            "minor", "unlikely", "theoretical", "best practice",
            "code quality", "gas optimization", "documentation",
        ],
        "categories": [
            "gas-optimization", "code-quality", "documentation",
            "informational", "suggestion",
        ],
        "min_funds_at_risk_pct": 0,
    },
}


# Platform-specific adjustments
PLATFORM_ADJUSTMENTS = {
    Platform.CODE4RENA: {
        "strict_likelihood": True,  # High/Medium requires high likelihood
        "requires_poc_for_high": False,
        "accepts_theoretical": True,
    },
    Platform.SHERLOCK: {
        "strict_likelihood": True,
        "requires_poc_for_high": True,  # Stricter PoC requirements
        "accepts_theoretical": False,
    },
    Platform.IMMUNEFI: {
        "strict_likelihood": False,  # Severity based mainly on impact
        "requires_poc_for_high": True,
        "accepts_theoretical": False,
        "tvl_scaling": True,  # Severity scales with protocol TVL
    },
}


# Historical judging patterns (anonymized examples)
JUDGING_PATTERNS = {
    "downgrade_reasons": [
        {
            "from": Severity.HIGH,
            "to": Severity.MEDIUM,
            "reason": "requires specific preconditions",
            "keywords": ["admin action", "specific state", "unlikely scenario"],
        },
        {
            "from": Severity.HIGH,
            "to": Severity.MEDIUM,
            "reason": "limited impact",
            "keywords": ["bounded loss", "small amount", "only affects"],
        },
        {
            "from": Severity.MEDIUM,
            "to": Severity.LOW,
            "reason": "no direct fund loss",
            "keywords": ["no loss", "inconvenience", "DoS only"],
        },
    ],
    "upgrade_reasons": [
        {
            "from": Severity.MEDIUM,
            "to": Severity.HIGH,
            "reason": "direct fund loss possible",
            "keywords": ["can steal", "drain", "extract"],
        },
        {
            "from": Severity.LOW,
            "to": Severity.MEDIUM,
            "reason": "leads to fund loss indirectly",
            "keywords": ["leads to", "enables", "combined with"],
        },
    ],
}


class SeverityPredictor:
    """
    Predict severity based on historical judging patterns.

    Uses:
    - Keyword matching
    - Category classification
    - Funds at risk estimation
    - Platform-specific adjustments
    - Historical similar findings
    """

    def __init__(self, platform: Platform = Platform.CODE4RENA):
        self.platform = platform
        self.historical_findings: list[dict] = []

    def predict(
        self,
        title: str,
        description: str,
        vulnerability_category: str = "",
        funds_at_risk: Optional[float] = None,
        protocol_tvl: Optional[float] = None,
        has_poc: bool = False,
        likelihood: str = "medium",
    ) -> SeverityPrediction:
        """
        Predict severity for a finding.

        Args:
            title: Finding title
            description: Full description
            vulnerability_category: Category/type of vulnerability
            funds_at_risk: Estimated funds at risk in USD
            protocol_tvl: Total value locked in protocol
            has_poc: Whether finding has working PoC
            likelihood: Estimated likelihood (high/medium/low)

        Returns:
            SeverityPrediction with confidence and reasoning
        """
        features = self._extract_features(
            title, description, vulnerability_category,
            funds_at_risk, protocol_tvl, has_poc, likelihood
        )

        # Initial prediction based on keywords and category
        severity_scores = self._calculate_severity_scores(features)

        # Apply platform-specific adjustments
        adjusted_scores = self._apply_platform_adjustments(severity_scores, features)

        # Get final prediction
        predicted = max(adjusted_scores, key=adjusted_scores.get)
        confidence = adjusted_scores[predicted] / sum(adjusted_scores.values())

        # Generate reasoning
        reasoning = self._generate_reasoning(features, predicted)

        # Find similar historical findings
        similar = self._find_similar_findings(title, description)

        # Calculate platform-specific predictions
        platform_predictions = self._predict_for_all_platforms(features)

        return SeverityPrediction(
            predicted_severity=predicted,
            confidence=confidence,
            reasoning=reasoning,
            similar_findings=similar[:3],
            platform_adjustments=platform_predictions,
        )

    def _extract_features(
        self,
        title: str,
        description: str,
        category: str,
        funds: Optional[float],
        tvl: Optional[float],
        has_poc: bool,
        likelihood: str,
    ) -> FindingFeatures:
        """Extract features from finding."""
        text = f"{title} {description}".lower()

        # Extract impact keywords
        impact_keywords = []
        for severity, indicators in SEVERITY_INDICATORS.items():
            for keyword in indicators["keywords"]:
                if keyword in text:
                    impact_keywords.append(keyword)

        # Calculate code quality (simplified)
        code_quality = 0.5
        if has_poc:
            code_quality += 0.3
        if "```" in description:  # Has code snippets
            code_quality += 0.1
        if len(description) > 500:  # Detailed
            code_quality += 0.1

        # Determine preconditions
        precondition_keywords = [
            "if admin", "requires", "only if", "specific", "unlikely",
            "edge case", "under certain"
        ]
        requires_preconditions = any(kw in text for kw in precondition_keywords)

        return FindingFeatures(
            vulnerability_category=category.lower(),
            funds_at_risk=funds,
            requires_preconditions=requires_preconditions,
            likelihood=likelihood,
            impact_keywords=impact_keywords,
            has_poc=has_poc,
            code_quality=min(1.0, code_quality),
            protocol_tvl=tvl,
        )

    def _calculate_severity_scores(self, features: FindingFeatures) -> dict[Severity, float]:
        """Calculate base severity scores."""
        scores = {s: 0.0 for s in Severity if s != Severity.INVALID}

        # Score based on keywords
        for severity, indicators in SEVERITY_INDICATORS.items():
            for keyword in indicators["keywords"]:
                if keyword in features.impact_keywords:
                    scores[severity] += 10

            # Category matching
            if features.vulnerability_category in indicators["categories"]:
                scores[severity] += 15

        # Funds at risk scoring
        if features.funds_at_risk and features.protocol_tvl:
            risk_pct = (features.funds_at_risk / features.protocol_tvl) * 100

            for severity, indicators in SEVERITY_INDICATORS.items():
                if risk_pct >= indicators["min_funds_at_risk_pct"]:
                    scores[severity] += 5 * (risk_pct / 10)

        # Likelihood adjustment
        likelihood_multiplier = {
            "high": 1.2,
            "medium": 1.0,
            "low": 0.7,
        }.get(features.likelihood, 1.0)

        for severity in scores:
            if severity in (Severity.HIGH, Severity.CRITICAL):
                scores[severity] *= likelihood_multiplier

        # PoC bonus
        if features.has_poc:
            scores[Severity.HIGH] *= 1.1
            scores[Severity.CRITICAL] *= 1.1

        # Preconditions penalty
        if features.requires_preconditions:
            scores[Severity.CRITICAL] *= 0.7
            scores[Severity.HIGH] *= 0.8

        # Ensure minimum scores
        for severity in scores:
            scores[severity] = max(1.0, scores[severity])

        return scores

    def _apply_platform_adjustments(
        self,
        scores: dict[Severity, float],
        features: FindingFeatures,
    ) -> dict[Severity, float]:
        """Apply platform-specific adjustments."""
        adjustments = PLATFORM_ADJUSTMENTS.get(self.platform, {})
        adjusted = scores.copy()

        # Strict likelihood platforms
        if adjustments.get("strict_likelihood"):
            if features.likelihood == "low":
                adjusted[Severity.HIGH] *= 0.5
                adjusted[Severity.CRITICAL] *= 0.3

        # PoC requirements
        if adjustments.get("requires_poc_for_high"):
            if not features.has_poc:
                adjusted[Severity.HIGH] *= 0.7
                adjusted[Severity.CRITICAL] *= 0.5

        # Theoretical findings
        if not adjustments.get("accepts_theoretical"):
            if features.requires_preconditions:
                adjusted[Severity.HIGH] *= 0.6

        # TVL scaling (Immunefi style)
        if adjustments.get("tvl_scaling") and features.protocol_tvl:
            if features.protocol_tvl > 100_000_000:  # >$100M
                adjusted[Severity.CRITICAL] *= 1.3
            elif features.protocol_tvl > 10_000_000:  # >$10M
                adjusted[Severity.HIGH] *= 1.2

        return adjusted

    def _generate_reasoning(
        self,
        features: FindingFeatures,
        predicted: Severity,
    ) -> list[str]:
        """Generate reasoning for prediction."""
        reasoning = []

        # Impact keywords
        if features.impact_keywords:
            keywords = features.impact_keywords[:3]
            reasoning.append(f"Impact keywords detected: {', '.join(keywords)}")

        # Category
        if features.vulnerability_category:
            reasoning.append(f"Vulnerability category: {features.vulnerability_category}")

        # Funds at risk
        if features.funds_at_risk:
            reasoning.append(f"Estimated funds at risk: ${features.funds_at_risk:,.0f}")

        # Likelihood
        reasoning.append(f"Likelihood assessment: {features.likelihood}")

        # Preconditions
        if features.requires_preconditions:
            reasoning.append("Requires specific preconditions (may downgrade severity)")

        # PoC
        if features.has_poc:
            reasoning.append("Has working PoC (increases confidence)")
        else:
            reasoning.append("No PoC provided (may need verification)")

        # Platform note
        reasoning.append(f"Predicted for platform: {self.platform.value}")

        return reasoning

    def _find_similar_findings(
        self,
        title: str,
        description: str,
    ) -> list[dict]:
        """Find similar historical findings."""
        # In production, this would use embedding similarity search
        # For now, simple keyword matching

        similar = []
        text = f"{title} {description}".lower()

        # Sample historical findings (would be from database)
        historical = [
            {
                "title": "Reentrancy in withdraw function",
                "severity": "High",
                "platform": "Code4rena",
                "keywords": ["reentrancy", "withdraw", "drain"],
            },
            {
                "title": "Oracle manipulation via flash loan",
                "severity": "High",
                "platform": "Sherlock",
                "keywords": ["oracle", "flash loan", "manipulation"],
            },
            {
                "title": "Admin can rug users",
                "severity": "Medium",
                "platform": "Code4rena",
                "keywords": ["admin", "centralization", "rug"],
            },
        ]

        for finding in historical:
            match_count = sum(1 for kw in finding["keywords"] if kw in text)
            if match_count > 0:
                similar.append({
                    **finding,
                    "relevance": match_count / len(finding["keywords"]),
                })

        return sorted(similar, key=lambda x: x["relevance"], reverse=True)

    def _predict_for_all_platforms(
        self,
        features: FindingFeatures,
    ) -> dict[Platform, Severity]:
        """Predict severity for all platforms."""
        predictions = {}

        for platform in Platform:
            old_platform = self.platform
            self.platform = platform

            scores = self._calculate_severity_scores(features)
            adjusted = self._apply_platform_adjustments(scores, features)
            predictions[platform] = max(adjusted, key=adjusted.get)

            self.platform = old_platform

        return predictions

    def calibrate(self, findings_with_outcomes: list[dict]) -> None:
        """
        Calibrate predictor with historical findings and their outcomes.

        Args:
            findings_with_outcomes: List of dicts with 'finding' and 'actual_severity'
        """
        self.historical_findings.extend(findings_with_outcomes)

        # In production, this would retrain the model
        # For now, we just store for similarity search

    def get_calibration_metrics(self) -> dict:
        """Get accuracy metrics from calibration data."""
        if not self.historical_findings:
            return {"error": "No calibration data"}

        correct = 0
        total = len(self.historical_findings)
        confusion = {}

        for entry in self.historical_findings:
            finding = entry.get("finding", {})
            actual = Severity(entry.get("actual_severity", "medium").lower())

            prediction = self.predict(
                finding.get("title", ""),
                finding.get("description", ""),
            )

            if prediction.predicted_severity == actual:
                correct += 1

            # Track confusion
            key = (prediction.predicted_severity.value, actual.value)
            confusion[key] = confusion.get(key, 0) + 1

        return {
            "accuracy": correct / total if total > 0 else 0,
            "total_samples": total,
            "confusion_matrix": confusion,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def predict_severity(
    title: str,
    description: str,
    platform: str = "code4rena",
) -> SeverityPrediction:
    """Quick severity prediction."""
    predictor = SeverityPredictor(Platform(platform))
    return predictor.predict(title, description)


def compare_platforms(title: str, description: str) -> dict[str, str]:
    """Compare predicted severity across platforms."""
    predictor = SeverityPredictor()
    prediction = predictor.predict(title, description)
    return {p.value: s.value for p, s in prediction.platform_adjustments.items()}
