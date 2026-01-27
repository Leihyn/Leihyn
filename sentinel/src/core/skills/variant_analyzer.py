"""
Variant Analyzer - Trail of Bits Skill

Find similar vulnerabilities across codebases using pattern-based analysis.
After finding an initial bug, systematically search for variants.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/variant-analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess
import re


class ConfidenceLevel(Enum):
    """Confidence in variant match."""
    HIGH = "high"  # Strong match, likely vulnerable
    MEDIUM = "medium"  # Possible match, needs review
    LOW = "low"  # Weak match, likely false positive


class SearchTool(Enum):
    """Tool used for variant search."""
    RIPGREP = "ripgrep"  # Fast, zero setup
    SEMGREP = "semgrep"  # Pattern matching, no build
    CODEQL = "codeql"  # Best interprocedural analysis


@dataclass
class VulnerabilityPattern:
    """Original vulnerability pattern to search for."""
    id: str
    description: str
    root_cause: str
    conditions: list[str]  # Required conditions
    exploitability: str
    original_location: str
    original_code: str
    # Abstraction points
    can_abstract_function_name: bool = True
    can_abstract_variable_names: bool = True
    can_abstract_literal_values: bool = True


@dataclass
class Variant:
    """A potential variant of the original vulnerability."""
    file_path: str
    line_number: int
    code_snippet: str
    confidence: ConfidenceLevel
    pattern_match: str  # What pattern matched
    exploitability: str
    priority: int  # 1-5, higher = more critical

    def to_dict(self) -> dict:
        return {
            "file": f"{self.file_path}:{self.line_number}",
            "snippet": self.code_snippet[:200],
            "confidence": self.confidence.value,
            "pattern": self.pattern_match,
            "priority": self.priority,
        }


@dataclass
class VariantReport:
    """Complete variant analysis report."""
    original_vulnerability: VulnerabilityPattern
    variants_found: list[Variant]
    patterns_searched: list[str]
    search_tool: SearchTool
    false_positive_rate: float
    files_searched: int

    @property
    def high_confidence_count(self) -> int:
        return len([v for v in self.variants_found if v.confidence == ConfidenceLevel.HIGH])

    def to_markdown(self) -> str:
        lines = [
            "# Variant Analysis Report",
            "",
            "## Original Vulnerability",
            "",
            f"**ID**: {self.original_vulnerability.id}",
            f"**Description**: {self.original_vulnerability.description}",
            f"**Root Cause**: {self.original_vulnerability.root_cause}",
            f"**Location**: `{self.original_vulnerability.original_location}`",
            "",
            "### Original Code",
            f"```\n{self.original_vulnerability.original_code}\n```",
            "",
            "## Search Results",
            "",
            f"**Tool**: {self.search_tool.value}",
            f"**Files Searched**: {self.files_searched}",
            f"**Patterns Searched**: {len(self.patterns_searched)}",
            f"**Variants Found**: {len(self.variants_found)}",
            f"**High Confidence**: {self.high_confidence_count}",
            f"**Estimated FP Rate**: {self.false_positive_rate:.0%}",
            "",
            "## Variants",
            "",
        ]

        # Group by confidence
        for confidence in ConfidenceLevel:
            variants = [v for v in self.variants_found if v.confidence == confidence]
            if variants:
                lines.append(f"### {confidence.value.title()} Confidence ({len(variants)})")
                lines.append("")
                lines.append("| Location | Pattern | Priority |")
                lines.append("|----------|---------|----------|")
                for v in sorted(variants, key=lambda x: -x.priority):
                    lines.append(f"| `{v.file_path}:{v.line_number}` | {v.pattern_match} | {v.priority} |")
                lines.append("")

        return "\n".join(lines)


class VariantAnalyzer:
    """
    Find similar vulnerabilities across a codebase.

    The Five-Step Process:
    1. Understand the Original Issue - root cause, conditions, exploitability
    2. Create an Exact Match - pattern matches ONLY the known instance
    3. Identify Abstraction Points - what can be generalized
    4. Iteratively Generalize - one change at a time, verify after each
    5. Analyze and Triage Results - classify each match

    Stop when false positive rate exceeds ~50%.
    """

    # Critical pitfalls to avoid
    PITFALLS = {
        "narrow_scope": "Searching only the module where bug was found misses variants elsewhere",
        "too_specific": "Using exact attribute/function names misses related constructs",
        "single_class": "Focusing on one manifestation misses other forms of same root cause",
        "missing_edge_cases": "Testing only normal scenarios misses edge case triggers",
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._check_tools()

    def _check_tools(self) -> dict[SearchTool, bool]:
        """Check available search tools."""
        available = {}
        for tool in SearchTool:
            try:
                if tool == SearchTool.RIPGREP:
                    result = subprocess.run(["rg", "--version"], capture_output=True)
                elif tool == SearchTool.SEMGREP:
                    result = subprocess.run(["semgrep", "--version"], capture_output=True)
                elif tool == SearchTool.CODEQL:
                    result = subprocess.run(["codeql", "version"], capture_output=True)
                available[tool] = result.returncode == 0
            except FileNotFoundError:
                available[tool] = False
        return available

    def _run_ripgrep(self, pattern: str, path: Optional[str] = None) -> list[dict]:
        """Run ripgrep search."""
        search_path = path or str(self.project_path)
        try:
            result = subprocess.run(
                ["rg", "-n", "--json", pattern, search_path],
                capture_output=True,
                text=True,
            )
            matches = []
            for line in result.stdout.split('\n'):
                if line and '"type":"match"' in line:
                    import json
                    data = json.loads(line)
                    if data.get("type") == "match":
                        match_data = data.get("data", {})
                        matches.append({
                            "file": match_data.get("path", {}).get("text", ""),
                            "line": match_data.get("line_number", 0),
                            "text": match_data.get("lines", {}).get("text", ""),
                        })
            return matches
        except Exception:
            return []

    def _run_semgrep(self, rule_yaml: str) -> list[dict]:
        """Run Semgrep with a custom rule."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(rule_yaml)
            rule_path = f.name

        try:
            result = subprocess.run(
                ["semgrep", "--config", rule_path, "--json", str(self.project_path)],
                capture_output=True,
                text=True,
            )
            import json
            data = json.loads(result.stdout) if result.stdout else {}
            matches = []
            for finding in data.get("results", []):
                matches.append({
                    "file": finding.get("path", ""),
                    "line": finding.get("start", {}).get("line", 0),
                    "text": finding.get("extra", {}).get("lines", ""),
                })
            return matches
        except Exception:
            return []
        finally:
            Path(rule_path).unlink(missing_ok=True)

    def create_exact_match_pattern(self, code: str) -> str:
        """
        Step 2: Create pattern that matches ONLY the known instance.

        Start specific, verify matches exactly one location.
        """
        # Escape regex special characters
        pattern = re.escape(code.strip())
        # Allow flexible whitespace
        pattern = re.sub(r'\\ +', r'\\s+', pattern)
        return pattern

    def identify_abstraction_points(
        self,
        code: str,
        vulnerability: VulnerabilityPattern,
    ) -> dict[str, bool]:
        """
        Step 3: Identify what can be abstracted.

        Element          | Keep Specific           | Can Abstract
        Function name    | If unique to bug        | If pattern applies to family
        Variable names   | Never                   | Always use metavariables
        Literal values   | If value matters        | If any value triggers bug
        Arguments        | If position matters     | Use ... wildcards
        """
        return {
            "function_name": vulnerability.can_abstract_function_name,
            "variable_names": vulnerability.can_abstract_variable_names,
            "literal_values": vulnerability.can_abstract_literal_values,
            "argument_count": True,  # Usually can abstract
        }

    def generalize_pattern(
        self,
        pattern: str,
        abstraction: str,
    ) -> str:
        """
        Step 4: Generalize one element at a time.

        Change ONE element, run pattern, review ALL matches,
        classify true/false positives, repeat.
        """
        if abstraction == "variable_names":
            # Replace variable names with wildcard
            pattern = re.sub(r'\b[a-z_][a-zA-Z0-9_]*\b', r'\\w+', pattern)
        elif abstraction == "literal_values":
            # Replace numeric literals
            pattern = re.sub(r'\b\d+\b', r'\\d+', pattern)
            # Replace string literals
            pattern = re.sub(r'"[^"]*"', r'"[^"]*"', pattern)
        elif abstraction == "function_name":
            # Keep function pattern flexible
            pattern = re.sub(r'\b(function|def|fn)\s+\w+', r'\\b\\1\\s+\\w+', pattern)

        return pattern

    def classify_match(
        self,
        match: dict,
        vulnerability: VulnerabilityPattern,
    ) -> tuple[ConfidenceLevel, int]:
        """
        Step 5: Classify and triage each match.

        Returns (confidence, priority).
        """
        code = match.get("text", "")

        # Check if conditions are met
        conditions_met = 0
        for condition in vulnerability.conditions:
            if re.search(condition, code, re.IGNORECASE):
                conditions_met += 1

        condition_ratio = conditions_met / len(vulnerability.conditions) if vulnerability.conditions else 0

        # Determine confidence
        if condition_ratio >= 0.8:
            confidence = ConfidenceLevel.HIGH
        elif condition_ratio >= 0.5:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        # Determine priority based on exploitability indicators
        priority = 1
        if "external" in code.lower() or "public" in code.lower():
            priority += 2
        if "msg.sender" in code or "tx.origin" in code:
            priority += 1
        if "transfer" in code.lower() or "call" in code.lower():
            priority += 1

        return confidence, min(priority, 5)

    def find_variants(
        self,
        vulnerability: VulnerabilityPattern,
        tool: SearchTool = SearchTool.RIPGREP,
        max_fp_rate: float = 0.5,
    ) -> VariantReport:
        """
        Find variants of a vulnerability.

        Iteratively generalizes the pattern, stopping when
        false positive rate exceeds max_fp_rate.
        """
        variants: list[Variant] = []
        patterns_searched: list[str] = []

        # Step 2: Start with exact match
        exact_pattern = self.create_exact_match_pattern(vulnerability.original_code)
        patterns_searched.append(exact_pattern)

        # Step 3: Get abstraction points
        abstractions = self.identify_abstraction_points(
            vulnerability.original_code, vulnerability
        )

        # Step 4: Iteratively generalize
        current_pattern = exact_pattern
        for abstraction, can_abstract in abstractions.items():
            if not can_abstract:
                continue

            new_pattern = self.generalize_pattern(current_pattern, abstraction)
            patterns_searched.append(new_pattern)

            # Search with new pattern
            if tool == SearchTool.RIPGREP:
                matches = self._run_ripgrep(new_pattern)
            else:
                matches = []  # Simplified

            # Classify matches
            true_positives = 0
            for match in matches:
                confidence, priority = self.classify_match(match, vulnerability)

                variant = Variant(
                    file_path=match.get("file", ""),
                    line_number=match.get("line", 0),
                    code_snippet=match.get("text", ""),
                    confidence=confidence,
                    pattern_match=new_pattern[:50] + "...",
                    exploitability=vulnerability.exploitability,
                    priority=priority,
                )
                variants.append(variant)

                if confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM]:
                    true_positives += 1

            # Check FP rate
            fp_rate = 1 - (true_positives / len(matches)) if matches else 0
            if fp_rate > max_fp_rate:
                break  # Stop generalizing

            current_pattern = new_pattern

        # Count files searched
        files_searched = len(list(self.project_path.glob("**/*.sol")))
        files_searched += len(list(self.project_path.glob("**/*.rs")))

        return VariantReport(
            original_vulnerability=vulnerability,
            variants_found=variants,
            patterns_searched=patterns_searched,
            search_tool=tool,
            false_positive_rate=0.0,  # Would calculate properly
            files_searched=files_searched,
        )

    def expand_vulnerability_classes(
        self,
        root_cause: str,
    ) -> list[str]:
        """
        Expand a root cause into related vulnerability classes.

        One root cause often has multiple manifestations.
        """
        expansions = {
            "missing_validation": [
                "Missing require/assert",
                "Unchecked return value",
                "Missing bounds check",
                "Missing null check",
            ],
            "access_control": [
                "Missing onlyOwner",
                "Incorrect role check",
                "tx.origin instead of msg.sender",
                "Missing address validation",
            ],
            "reentrancy": [
                "State after external call",
                "Cross-function reentrancy",
                "Cross-contract reentrancy",
                "Read-only reentrancy",
            ],
            "arithmetic": [
                "Overflow without SafeMath",
                "Precision loss in division",
                "Rounding errors",
                "Unchecked subtraction",
            ],
        }
        return expansions.get(root_cause, [root_cause])


def find_variants(
    project_path: str,
    vulnerability_id: str,
    description: str,
    root_cause: str,
    original_location: str,
    original_code: str,
    conditions: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> VariantReport:
    """
    Find variants of a known vulnerability.

    Args:
        project_path: Path to project
        vulnerability_id: Unique ID for the vulnerability
        description: Description of the vulnerability
        root_cause: Root cause (e.g., "missing_validation")
        original_location: File:line of original finding
        original_code: Code snippet of original vulnerability
        conditions: Conditions required for exploitation
        output_path: Optional path for markdown report

    Returns:
        VariantReport with all variants found
    """
    analyzer = VariantAnalyzer(project_path)

    vulnerability = VulnerabilityPattern(
        id=vulnerability_id,
        description=description,
        root_cause=root_cause,
        conditions=conditions or [],
        exploitability="Requires manual verification",
        original_location=original_location,
        original_code=original_code,
    )

    report = analyzer.find_variants(vulnerability)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
