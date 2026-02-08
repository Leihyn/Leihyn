"""
Sharp Edges Analyzer - Trail of Bits Skill

Identifies error-prone APIs, dangerous configurations, and footgun designs
that enable security mistakes. Evaluates "pit of success" principle.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/sharp-edges
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re


class FootgunCategory(Enum):
    """Categories of sharp edges."""
    ALGORITHM_SELECTION = "algorithm_selection"  # JWT alg:none pattern
    DANGEROUS_DEFAULTS = "dangerous_defaults"  # timeout=0 means infinite?
    PRIMITIVE_VS_SEMANTIC = "primitive_vs_semantic"  # bytes vs typed keys
    CONFIGURATION_CLIFFS = "configuration_cliffs"  # One wrong setting = disaster
    SILENT_FAILURES = "silent_failures"  # Errors that don't surface
    STRINGLY_TYPED = "stringly_typed"  # Security values as plain strings


class EdgeSeverity(Enum):
    """Severity of sharp edge."""
    CRITICAL = "critical"  # Default usage is insecure
    HIGH = "high"  # Easy misconfiguration breaks security
    MEDIUM = "medium"  # Unusual but possible misconfiguration
    LOW = "low"  # Requires deliberate misuse


@dataclass
class SharpEdge:
    """A detected sharp edge / footgun."""
    category: FootgunCategory
    severity: EdgeSeverity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    attack_scenario: str
    recommendation: str
    documented: bool = False  # Is the danger documented?

    def to_markdown(self) -> str:
        return f"""### [{self.severity.value.upper()}] {self.category.value.replace('_', ' ').title()}

**Location**: `{self.file_path}:{self.line_number}`

**Description**: {self.description}

**Code**:
```
{self.code_snippet}
```

**Attack Scenario**: {self.attack_scenario}

**Recommendation**: {self.recommendation}

**Documented**: {'Yes' if self.documented else 'No (increases severity)'}
"""


@dataclass
class SharpEdgesReport:
    """Complete sharp edges analysis report."""
    project_name: str
    files_analyzed: list[str]
    sharp_edges: list[SharpEdge]

    @property
    def critical_count(self) -> int:
        return len([e for e in self.sharp_edges if e.severity == EdgeSeverity.CRITICAL])

    @property
    def by_category(self) -> dict[FootgunCategory, list[SharpEdge]]:
        result: dict[FootgunCategory, list[SharpEdge]] = {}
        for edge in self.sharp_edges:
            if edge.category not in result:
                result[edge.category] = []
            result[edge.category].append(edge)
        return result

    def to_markdown(self) -> str:
        lines = [
            f"# Sharp Edges Analysis: {self.project_name}",
            "",
            "## Core Principle",
            "",
            "> **The pit of success**: Secure usage should be the path of least resistance.",
            "> If developers must understand cryptography, read documentation carefully,",
            "> or remember special rules to avoid vulnerabilities, the API has failed.",
            "",
            "## Summary",
            "",
            f"- **Files Analyzed**: {len(self.files_analyzed)}",
            f"- **Sharp Edges Found**: {len(self.sharp_edges)}",
            f"- **Critical**: {self.critical_count}",
            "",
            "## Findings by Category",
            "",
        ]

        for category, edges in self.by_category.items():
            lines.append(f"### {category.value.replace('_', ' ').title()} ({len(edges)})")
            lines.append("")
            for edge in edges:
                lines.append(edge.to_markdown())
                lines.append("---")
                lines.append("")

        return "\n".join(lines)


class SharpEdgesAnalyzer:
    """
    Evaluates whether APIs and configurations are resistant to developer misuse.

    Rationalizations to reject:
    - "It's documented" - Developers don't read docs under deadline pressure
    - "Advanced users need flexibility" - Flexibility creates footguns
    - "It's the developer's responsibility" - You designed the footgun
    - "Nobody would actually do that" - Developers do everything under pressure
    - "It's just a configuration option" - Wrong configs ship to production
    - "We need backwards compatibility" - Insecure defaults can't be grandfathered
    """

    # Algorithm selection footgun patterns
    ALGORITHM_PATTERNS = [
        # Function parameters that select crypto primitives
        (r'algorithm\s*[=:]\s*["\']?(\w+)', "Algorithm parameter allows insecure selection"),
        (r'cipher\s*[=:]\s*["\']?(\w+)', "Cipher parameter allows insecure selection"),
        (r'hash_type\s*[=:]\s*["\']?(\w+)', "Hash type parameter allows weak algorithms"),
        (r'mode\s*[=:]\s*["\']?(\w+)', "Mode parameter allows insecure modes"),
    ]

    # Dangerous default patterns
    DANGEROUS_DEFAULT_PATTERNS = [
        # Timeout/lifetime = 0
        (r'timeout\s*[=:]\s*0\b', "timeout=0 may mean infinite or immediate"),
        (r'lifetime\s*[=:]\s*0\b', "lifetime=0 semantics unclear"),
        (r'max_attempts\s*[=:]\s*0\b', "max_attempts=0 may disable limiting"),
        # Empty string bypasses
        (r'password\s*[=:]\s*["\']["\']', "Empty password allowed"),
        (r'secret\s*[=:]\s*["\']["\']', "Empty secret allowed"),
        (r'key\s*[=:]\s*["\']["\']', "Empty key allowed"),
        # Boolean security toggles
        (r'verify_ssl\s*[=:]\s*False', "SSL verification disabled"),
        (r'check_signature\s*[=:]\s*False', "Signature verification disabled"),
        (r'validate\s*[=:]\s*False', "Validation disabled"),
    ]

    # Silent failure patterns
    SILENT_FAILURE_PATTERNS = [
        # Return False instead of raising
        (r'except.*:\s*\n\s*return\s+False', "Exception swallowed, returns False"),
        (r'except.*:\s*\n\s*pass', "Exception silently swallowed"),
        (r'if\s+not\s+\w+:\s*\n\s*return\s+True', "Missing value returns success"),
        # Verification that returns bool
        (r'def\s+verify.*\):\s*\n.*return\s+(True|False)', "Verify returns bool (easy to ignore)"),
    ]

    # Stringly-typed security patterns
    STRINGLY_TYPED_PATTERNS = [
        # String concatenation in security contexts
        (r'execute\(["\'].*\+', "SQL built from string concatenation"),
        (r'system\(["\'].*\+', "Command built from string concatenation"),
        (r'permissions\s*\+=', "Permissions modified by string concatenation"),
        (r'roles\s*=\s*["\'].*,.*["\']', "Roles as comma-separated string"),
    ]

    # Primitive vs semantic API patterns (Solidity-specific)
    PRIMITIVE_API_PATTERNS = [
        # Raw bytes for different security concepts
        (r'bytes32\s+\w*key', "Raw bytes32 for key (no type safety)"),
        (r'bytes32\s+\w*signature', "Raw bytes32 for signature (no type safety)"),
        (r'bytes\s+memory\s+\w*hash', "Raw bytes for hash (no type safety)"),
        # Direct comparison instead of constant-time
        (r'==\s*\w*(signature|hash|mac)', "Direct comparison (timing attack risk)"),
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def analyze(self) -> SharpEdgesReport:
        """Analyze project for sharp edges."""
        sharp_edges: list[SharpEdge] = []
        files_analyzed: list[str] = []

        # Find all relevant files
        patterns = ["**/*.sol", "**/*.py", "**/*.js", "**/*.ts", "**/*.go", "**/*.rs"]
        for pattern in patterns:
            for file_path in self.project_path.glob(pattern):
                # Skip test files for now
                if "test" in str(file_path).lower():
                    continue

                rel_path = str(file_path.relative_to(self.project_path))
                files_analyzed.append(rel_path)

                content = file_path.read_text()

                # Check each category
                sharp_edges.extend(self._check_algorithm_selection(content, rel_path))
                sharp_edges.extend(self._check_dangerous_defaults(content, rel_path))
                sharp_edges.extend(self._check_silent_failures(content, rel_path))
                sharp_edges.extend(self._check_stringly_typed(content, rel_path))
                sharp_edges.extend(self._check_primitive_apis(content, rel_path))
                sharp_edges.extend(self._check_configuration_cliffs(content, rel_path))

        return SharpEdgesReport(
            project_name=self.project_path.name,
            files_analyzed=files_analyzed,
            sharp_edges=sharp_edges,
        )

    def _check_algorithm_selection(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for algorithm selection footguns."""
        edges = []
        for pattern, description in self.ALGORITHM_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.ALGORITHM_SELECTION,
                    severity=EdgeSeverity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                    attack_scenario="Attacker could select weak/none algorithm to bypass security",
                    recommendation="Remove algorithm selection or restrict to safe options only",
                ))
        return edges

    def _check_dangerous_defaults(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for dangerous default values."""
        edges = []
        for pattern, description in self.DANGEROUS_DEFAULT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.DANGEROUS_DEFAULTS,
                    severity=EdgeSeverity.CRITICAL if "password" in pattern or "secret" in pattern else EdgeSeverity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                    attack_scenario="Default or zero value may disable security entirely",
                    recommendation="Use safe defaults, validate all security-critical values",
                ))
        return edges

    def _check_silent_failures(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for silent failure patterns."""
        edges = []
        for pattern, description in self.SILENT_FAILURE_PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.SILENT_FAILURES,
                    severity=EdgeSeverity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                    attack_scenario="Security failures silently ignored, attacker succeeds",
                    recommendation="Raise exceptions on security failures, don't return booleans",
                ))
        return edges

    def _check_stringly_typed(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for stringly-typed security values."""
        edges = []
        for pattern, description in self.STRINGLY_TYPED_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.STRINGLY_TYPED,
                    severity=EdgeSeverity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                    attack_scenario="String manipulation enables injection or escalation",
                    recommendation="Use typed enums/structs for security-critical values",
                ))
        return edges

    def _check_primitive_apis(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for primitive vs semantic API issues."""
        edges = []
        for pattern, description in self.PRIMITIVE_API_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.PRIMITIVE_VS_SEMANTIC,
                    severity=EdgeSeverity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                    attack_scenario="Raw bytes can be swapped or confused between types",
                    recommendation="Use typed wrappers that enforce correct usage",
                ))
        return edges

    def _check_configuration_cliffs(self, content: str, file_path: str) -> list[SharpEdge]:
        """Check for configuration cliff patterns."""
        edges = []

        # Check for constructor parameters that should be validated
        constructor_pattern = re.compile(
            r'constructor\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )

        for match in constructor_pattern.finditer(content):
            # Check if constructor validates parameters
            constructor_body = content[match.end():match.end()+500]
            if "require" not in constructor_body and "assert" not in constructor_body:
                line_num = content[:match.start()].count('\n') + 1
                edges.append(SharpEdge(
                    category=FootgunCategory.CONFIGURATION_CLIFFS,
                    severity=EdgeSeverity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_context(content, match.start()),
                    description="Constructor parameters not validated",
                    attack_scenario="Invalid configuration deployed, security bypassed",
                    recommendation="Validate all constructor parameters with require statements",
                ))

        return edges

    def _get_context(self, content: str, pos: int, lines: int = 3) -> str:
        """Get code context around a position."""
        start = content.rfind('\n', 0, pos)
        for _ in range(lines - 1):
            new_start = content.rfind('\n', 0, start)
            if new_start == -1:
                break
            start = new_start

        end = content.find('\n', pos)
        for _ in range(lines - 1):
            new_end = content.find('\n', end + 1)
            if new_end == -1:
                break
            end = new_end

        return content[start:end].strip()


def find_sharp_edges(
    project_path: str,
    output_path: Optional[str] = None,
) -> SharpEdgesReport:
    """
    Find sharp edges and footguns in a project.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        SharpEdgesReport with findings
    """
    analyzer = SharpEdgesAnalyzer(project_path)
    report = analyzer.analyze()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
