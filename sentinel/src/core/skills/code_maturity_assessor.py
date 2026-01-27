"""
Code Maturity Assessor - Trail of Bits Skill

Systematic code maturity assessment using Trail of Bits' 9-category framework.
Produces professional scorecard with evidence-based ratings.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re


class MaturityCategory(Enum):
    """The 9 maturity assessment categories."""
    ARITHMETIC = "arithmetic"
    AUDITING = "auditing"
    ACCESS_CONTROL = "access_control"
    COMPLEXITY = "complexity"
    DECENTRALIZATION = "decentralization"
    DOCUMENTATION = "documentation"
    MEV_RISKS = "mev_risks"
    LOW_LEVEL = "low_level"
    TESTING = "testing"


class MaturityRating(Enum):
    """Rating levels."""
    MISSING = 0  # Not present/not implemented
    WEAK = 1  # Several significant improvements needed
    MODERATE = 2  # Adequate, can be improved
    SATISFACTORY = 3  # Above average, minor improvements
    STRONG = 4  # Exceptional, only small improvements possible


@dataclass
class CategoryAssessment:
    """Assessment for a single category."""
    category: MaturityCategory
    rating: MaturityRating
    score: int  # 0-4
    evidence: list[str]  # File:line references
    strengths: list[str]
    gaps: list[str]
    recommendations: list[str]

    def to_markdown(self) -> str:
        rating_display = {
            MaturityRating.MISSING: "Missing (0)",
            MaturityRating.WEAK: "Weak (1)",
            MaturityRating.MODERATE: "Moderate (2)",
            MaturityRating.SATISFACTORY: "Satisfactory (3)",
            MaturityRating.STRONG: "Strong (4)",
        }

        lines = [
            f"### {self.category.value.replace('_', ' ').title()}",
            "",
            f"**Rating**: {rating_display[self.rating]}",
            "",
        ]

        if self.strengths:
            lines.append("**Strengths:**")
            for s in self.strengths:
                lines.append(f"- {s}")
            lines.append("")

        if self.gaps:
            lines.append("**Gaps:**")
            for g in self.gaps:
                lines.append(f"- {g}")
            lines.append("")

        if self.evidence:
            lines.append("**Evidence:**")
            for e in self.evidence[:5]:  # Limit to 5
                lines.append(f"- `{e}`")
            lines.append("")

        if self.recommendations:
            lines.append("**Recommendations:**")
            for r in self.recommendations:
                lines.append(f"- {r}")

        return "\n".join(lines)


@dataclass
class MaturityReport:
    """Complete maturity assessment report."""
    project_name: str
    assessments: dict[MaturityCategory, CategoryAssessment]
    overall_score: float
    top_strengths: list[str]
    critical_gaps: list[str]
    improvement_roadmap: list[dict]

    def to_markdown(self) -> str:
        lines = [
            f"# Code Maturity Assessment: {self.project_name}",
            "",
            "## Executive Summary",
            "",
            f"**Overall Maturity Score**: {self.overall_score:.1f}/4.0",
            "",
            "### Top Strengths",
            "",
        ]

        for s in self.top_strengths[:3]:
            lines.append(f"- {s}")
        lines.append("")

        lines.append("### Critical Gaps")
        lines.append("")
        for g in self.critical_gaps[:3]:
            lines.append(f"- {g}")
        lines.append("")

        # Scorecard table
        lines.append("## Maturity Scorecard")
        lines.append("")
        lines.append("| Category | Rating | Score | Key Finding |")
        lines.append("|----------|--------|-------|-------------|")

        for cat in MaturityCategory:
            assessment = self.assessments.get(cat)
            if assessment:
                rating = assessment.rating.name
                score = assessment.score
                finding = assessment.gaps[0] if assessment.gaps else "N/A"
                lines.append(f"| {cat.value.replace('_', ' ').title()} | {rating} | {score}/4 | {finding[:50]}... |")

        lines.append("")
        lines.append("## Detailed Analysis")
        lines.append("")

        for cat in MaturityCategory:
            assessment = self.assessments.get(cat)
            if assessment:
                lines.append(assessment.to_markdown())
                lines.append("")
                lines.append("---")
                lines.append("")

        # Improvement roadmap
        lines.append("## Improvement Roadmap")
        lines.append("")

        for item in self.improvement_roadmap:
            priority = item.get("priority", "MEDIUM")
            action = item.get("action", "")
            effort = item.get("effort", "")
            lines.append(f"### [{priority}] {action}")
            lines.append(f"**Effort**: {effort}")
            lines.append("")

        return "\n".join(lines)


class CodeMaturityAssessor:
    """
    Assess code maturity using Trail of Bits' 9-category framework.

    Rating System:
    - Missing (0): Not present/not implemented
    - Weak (1): Several significant improvements needed
    - Moderate (2): Adequate, can be improved
    - Satisfactory (3): Above average, minor improvements
    - Strong (4): Exceptional

    Rating Logic:
    - ANY "Weak" criteria → Weak
    - NO "Weak" + SOME "Moderate" unmet → Moderate
    - ALL "Moderate" + SOME "Satisfactory" met → Satisfactory
    - ALL "Satisfactory" + exceptional practices → Strong
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def assess(self) -> MaturityReport:
        """Run full maturity assessment."""
        assessments: dict[MaturityCategory, CategoryAssessment] = {}

        # Collect all code for analysis
        all_code = self._collect_code()

        # Assess each category
        assessments[MaturityCategory.ARITHMETIC] = self._assess_arithmetic(all_code)
        assessments[MaturityCategory.AUDITING] = self._assess_auditing(all_code)
        assessments[MaturityCategory.ACCESS_CONTROL] = self._assess_access_control(all_code)
        assessments[MaturityCategory.COMPLEXITY] = self._assess_complexity(all_code)
        assessments[MaturityCategory.DECENTRALIZATION] = self._assess_decentralization(all_code)
        assessments[MaturityCategory.DOCUMENTATION] = self._assess_documentation(all_code)
        assessments[MaturityCategory.MEV_RISKS] = self._assess_mev_risks(all_code)
        assessments[MaturityCategory.LOW_LEVEL] = self._assess_low_level(all_code)
        assessments[MaturityCategory.TESTING] = self._assess_testing()

        # Calculate overall score
        scores = [a.score for a in assessments.values()]
        overall_score = sum(scores) / len(scores) if scores else 0

        # Identify top strengths and gaps
        top_strengths = []
        critical_gaps = []

        for cat, assessment in assessments.items():
            if assessment.rating in [MaturityRating.SATISFACTORY, MaturityRating.STRONG]:
                top_strengths.extend(assessment.strengths[:1])
            if assessment.rating in [MaturityRating.MISSING, MaturityRating.WEAK]:
                critical_gaps.extend(assessment.gaps[:1])

        # Build improvement roadmap
        roadmap = self._build_roadmap(assessments)

        return MaturityReport(
            project_name=self.project_path.name,
            assessments=assessments,
            overall_score=overall_score,
            top_strengths=top_strengths[:3],
            critical_gaps=critical_gaps[:3],
            improvement_roadmap=roadmap,
        )

    def _collect_code(self) -> dict[str, str]:
        """Collect all code files."""
        code: dict[str, str] = {}
        for pattern in ["**/*.sol", "**/*.vy", "**/*.rs", "**/*.move"]:
            for file_path in self.project_path.glob(pattern):
                rel_path = str(file_path.relative_to(self.project_path))
                try:
                    code[rel_path] = file_path.read_text()
                except Exception:
                    pass
        return code

    def _assess_arithmetic(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess arithmetic safety."""
        evidence = []
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for SafeMath or Solidity 0.8+
        if re.search(r"pragma solidity \^?0\.[89]|SafeMath|using.*Math", all_content):
            strengths.append("Overflow protection in place (Solidity 0.8+ or SafeMath)")
        else:
            gaps.append("No overflow protection detected")

        # Check for unchecked blocks
        unchecked_count = len(re.findall(r"unchecked\s*\{", all_content))
        if unchecked_count > 0:
            gaps.append(f"Found {unchecked_count} unchecked blocks - verify intentional")

        # Check for division
        division_count = len(re.findall(r"/\s*[^/]", all_content))
        if division_count > 10 and not re.search(r"// precision|// rounding", all_content, re.IGNORECASE):
            gaps.append("Multiple divisions without documented precision handling")

        # Determine rating
        if not strengths and gaps:
            rating = MaturityRating.WEAK
        elif strengths and not gaps:
            rating = MaturityRating.SATISFACTORY
        elif strengths:
            rating = MaturityRating.MODERATE
        else:
            rating = MaturityRating.MISSING

        return CategoryAssessment(
            category=MaturityCategory.ARITHMETIC,
            rating=rating,
            score=rating.value,
            evidence=evidence,
            strengths=strengths,
            gaps=gaps,
            recommendations=["Document precision handling for all divisions", "Add fuzz tests for arithmetic edge cases"],
        )

    def _assess_auditing(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess auditing/event logging."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Count events
        event_count = len(re.findall(r"event\s+\w+", all_content))
        emit_count = len(re.findall(r"emit\s+\w+", all_content))

        if event_count > 5:
            strengths.append(f"Good event coverage ({event_count} events defined)")
        else:
            gaps.append(f"Limited event coverage ({event_count} events)")

        # Check for indexed parameters
        indexed_count = len(re.findall(r"indexed", all_content))
        if indexed_count > event_count / 2:
            strengths.append("Events use indexed parameters for efficient querying")

        # Determine rating
        if event_count == 0:
            rating = MaturityRating.MISSING
        elif event_count < 3:
            rating = MaturityRating.WEAK
        elif event_count < 10:
            rating = MaturityRating.MODERATE
        else:
            rating = MaturityRating.SATISFACTORY

        return CategoryAssessment(
            category=MaturityCategory.AUDITING,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Add events for all state changes", "Include indexed parameters for key fields"],
        )

    def _assess_access_control(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess access control patterns."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for access control patterns
        has_ownable = bool(re.search(r"Ownable|onlyOwner", all_content))
        has_roles = bool(re.search(r"AccessControl|hasRole|onlyRole", all_content))
        has_requires = bool(re.search(r"require\s*\(\s*msg\.sender", all_content))

        if has_roles:
            strengths.append("Role-based access control implemented")
        elif has_ownable:
            strengths.append("Owner-based access control implemented")
        elif has_requires:
            strengths.append("Basic access control with require statements")
        else:
            gaps.append("No access control patterns detected")

        # Check for multi-sig or timelock
        has_multisig = bool(re.search(r"multisig|gnosis|safe", all_content, re.IGNORECASE))
        has_timelock = bool(re.search(r"timelock|TimelockController", all_content))

        if has_timelock:
            strengths.append("Timelock protection for privileged operations")
        if has_multisig:
            strengths.append("Multi-signature requirement for critical functions")

        # Determine rating
        if not has_ownable and not has_roles and not has_requires:
            rating = MaturityRating.MISSING
        elif has_roles and (has_timelock or has_multisig):
            rating = MaturityRating.STRONG
        elif has_roles:
            rating = MaturityRating.SATISFACTORY
        elif has_ownable:
            rating = MaturityRating.MODERATE
        else:
            rating = MaturityRating.WEAK

        return CategoryAssessment(
            category=MaturityCategory.ACCESS_CONTROL,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Implement role-based access control", "Add timelock for admin functions"],
        )

    def _assess_complexity(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess code complexity."""
        strengths = []
        gaps = []

        # Count functions and contracts
        all_content = "\n".join(code.values())
        function_count = len(re.findall(r"function\s+\w+", all_content))
        contract_count = len(re.findall(r"contract\s+\w+", all_content))

        if function_count < 50:
            strengths.append(f"Manageable function count ({function_count})")
        else:
            gaps.append(f"High function count ({function_count}) - consider splitting")

        # Check for deep nesting
        deep_nesting = len(re.findall(r"\{\s*\{s*\{s*\{", all_content))
        if deep_nesting > 5:
            gaps.append(f"Deep nesting detected ({deep_nesting} instances)")

        # Determine rating
        if function_count > 100:
            rating = MaturityRating.WEAK
        elif function_count > 50:
            rating = MaturityRating.MODERATE
        else:
            rating = MaturityRating.SATISFACTORY

        return CategoryAssessment(
            category=MaturityCategory.COMPLEXITY,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Split large contracts into modules", "Reduce function complexity"],
        )

    def _assess_decentralization(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess decentralization and centralization risks."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for upgradability
        has_proxy = bool(re.search(r"proxy|upgradeable|implementation", all_content, re.IGNORECASE))
        if has_proxy:
            gaps.append("Upgradeable contracts - admin can change logic")

        # Check for pausing
        has_pause = bool(re.search(r"pause|Pausable", all_content))
        if has_pause:
            gaps.append("Pausable contract - admin can halt operations")

        # Check for minting
        has_mint = bool(re.search(r"mint\s*\(|_mint\s*\(", all_content))
        if has_mint:
            gaps.append("Minting capability - check for supply caps")

        # Determine rating
        centralization_risks = len(gaps)
        if centralization_risks >= 3:
            rating = MaturityRating.WEAK
        elif centralization_risks == 2:
            rating = MaturityRating.MODERATE
        elif centralization_risks == 1:
            rating = MaturityRating.SATISFACTORY
        else:
            strengths.append("Minimal centralization risks")
            rating = MaturityRating.STRONG

        return CategoryAssessment(
            category=MaturityCategory.DECENTRALIZATION,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Add timelock to admin functions", "Document all admin capabilities"],
        )

    def _assess_documentation(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess documentation quality."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for NatSpec
        natspec_count = len(re.findall(r"@notice|@dev|@param|@return", all_content))
        function_count = len(re.findall(r"function\s+\w+", all_content))

        doc_ratio = natspec_count / max(function_count, 1)

        if doc_ratio > 2:
            strengths.append("Comprehensive NatSpec documentation")
        elif doc_ratio > 0.5:
            strengths.append("Partial NatSpec documentation")
        else:
            gaps.append("Limited or no NatSpec documentation")

        # Check for README
        readme_exists = (self.project_path / "README.md").exists()
        if readme_exists:
            strengths.append("README documentation present")
        else:
            gaps.append("No README found")

        # Determine rating
        if doc_ratio > 2 and readme_exists:
            rating = MaturityRating.STRONG
        elif doc_ratio > 0.5:
            rating = MaturityRating.SATISFACTORY
        elif doc_ratio > 0:
            rating = MaturityRating.MODERATE
        else:
            rating = MaturityRating.WEAK

        return CategoryAssessment(
            category=MaturityCategory.DOCUMENTATION,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Add NatSpec to all public functions", "Create architecture documentation"],
        )

    def _assess_mev_risks(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess MEV/transaction ordering risks."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for DEX patterns
        has_swap = bool(re.search(r"swap|exchange", all_content, re.IGNORECASE))
        has_slippage = bool(re.search(r"slippage|minAmount|deadline", all_content, re.IGNORECASE))

        if has_swap and not has_slippage:
            gaps.append("Swap functionality without slippage protection")
        elif has_swap and has_slippage:
            strengths.append("Slippage protection implemented")

        # Check for oracle usage
        has_oracle = bool(re.search(r"oracle|price|chainlink", all_content, re.IGNORECASE))
        if has_oracle:
            has_twap = bool(re.search(r"twap|average|observe", all_content, re.IGNORECASE))
            if has_twap:
                strengths.append("TWAP/price averaging for oracle security")
            else:
                gaps.append("Oracle usage without apparent TWAP protection")

        # Determine rating
        if gaps:
            rating = MaturityRating.WEAK if len(gaps) > 1 else MaturityRating.MODERATE
        elif strengths:
            rating = MaturityRating.SATISFACTORY
        else:
            rating = MaturityRating.MODERATE  # N/A essentially

        return CategoryAssessment(
            category=MaturityCategory.MEV_RISKS,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Add slippage protection", "Use TWAP for price oracles", "Add deadline parameters"],
        )

    def _assess_low_level(self, code: dict[str, str]) -> CategoryAssessment:
        """Assess low-level code usage."""
        strengths = []
        gaps = []

        all_content = "\n".join(code.values())

        # Check for assembly
        assembly_count = len(re.findall(r"assembly\s*\{", all_content))
        if assembly_count > 0:
            gaps.append(f"Inline assembly used ({assembly_count} blocks)")

        # Check for low-level calls
        low_level_calls = len(re.findall(r"\.call\{|\.delegatecall\{|\.staticcall\{", all_content))
        if low_level_calls > 0:
            gaps.append(f"Low-level calls used ({low_level_calls})")

        # Check for proper handling
        has_return_check = bool(re.search(r"\(bool\s+\w+,", all_content))
        if low_level_calls > 0 and has_return_check:
            strengths.append("Low-level call return values checked")

        # Determine rating
        if assembly_count > 5 or low_level_calls > 10:
            rating = MaturityRating.WEAK
        elif assembly_count > 0 or low_level_calls > 0:
            rating = MaturityRating.MODERATE
        else:
            strengths.append("No low-level code detected")
            rating = MaturityRating.STRONG

        return CategoryAssessment(
            category=MaturityCategory.LOW_LEVEL,
            rating=rating,
            score=rating.value,
            evidence=[],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Document all assembly blocks", "Justify low-level call usage"],
        )

    def _assess_testing(self) -> CategoryAssessment:
        """Assess testing coverage."""
        strengths = []
        gaps = []

        # Check for test files
        test_files = list(self.project_path.glob("**/test*/**/*.sol"))
        test_files.extend(self.project_path.glob("**/test*/**/*.t.sol"))
        test_files.extend(self.project_path.glob("**/test*/**/*.ts"))

        if len(test_files) > 10:
            strengths.append(f"Good test coverage ({len(test_files)} test files)")
        elif len(test_files) > 0:
            strengths.append(f"Some tests present ({len(test_files)} test files)")
        else:
            gaps.append("No test files found")

        # Check for fuzzing
        fuzz_tests = list(self.project_path.glob("**/*fuzz*"))
        fuzz_tests.extend(self.project_path.glob("**/echidna*"))
        if fuzz_tests:
            strengths.append("Fuzz testing configured")

        # Check for formal verification
        formal = list(self.project_path.glob("**/*certora*"))
        formal.extend(self.project_path.glob("**/*halmos*"))
        if formal:
            strengths.append("Formal verification configured")

        # Determine rating
        if not test_files:
            rating = MaturityRating.MISSING
        elif len(test_files) < 5:
            rating = MaturityRating.WEAK
        elif fuzz_tests or formal:
            rating = MaturityRating.STRONG
        elif len(test_files) > 10:
            rating = MaturityRating.SATISFACTORY
        else:
            rating = MaturityRating.MODERATE

        return CategoryAssessment(
            category=MaturityCategory.TESTING,
            rating=rating,
            score=rating.value,
            evidence=[str(f) for f in test_files[:5]],
            strengths=strengths,
            gaps=gaps,
            recommendations=["Add fuzz tests with Echidna/Foundry", "Aim for >90% code coverage"],
        )

    def _build_roadmap(self, assessments: dict[MaturityCategory, CategoryAssessment]) -> list[dict]:
        """Build improvement roadmap prioritized by impact."""
        roadmap = []

        # Critical items (Missing/Weak ratings)
        for cat, assessment in assessments.items():
            if assessment.rating in [MaturityRating.MISSING, MaturityRating.WEAK]:
                for rec in assessment.recommendations[:1]:
                    roadmap.append({
                        "priority": "CRITICAL",
                        "action": f"[{cat.value}] {rec}",
                        "effort": "High",
                    })

        # High items (Moderate ratings)
        for cat, assessment in assessments.items():
            if assessment.rating == MaturityRating.MODERATE:
                for rec in assessment.recommendations[:1]:
                    roadmap.append({
                        "priority": "HIGH",
                        "action": f"[{cat.value}] {rec}",
                        "effort": "Medium",
                    })

        return roadmap[:10]


def assess_maturity(
    project_path: str,
    output_path: Optional[str] = None,
) -> MaturityReport:
    """
    Assess code maturity using 9-category framework.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        MaturityReport with scores and recommendations
    """
    assessor = CodeMaturityAssessor(project_path)
    report = assessor.assess()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
