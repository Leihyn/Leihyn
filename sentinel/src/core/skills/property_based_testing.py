"""
Property-Based Testing Guide - Trail of Bits Skill

Guidance for property-based testing across languages and smart contracts.
Automatically suggests properties for common patterns.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/property-based-testing
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re


class PropertyType(Enum):
    """Types of properties for testing."""
    ROUNDTRIP = "roundtrip"  # decode(encode(x)) == x
    IDEMPOTENCE = "idempotence"  # f(f(x)) == f(x)
    INVARIANT = "invariant"  # Property holds before/after
    COMMUTATIVITY = "commutativity"  # f(a, b) == f(b, a)
    ASSOCIATIVITY = "associativity"  # f(f(a,b), c) == f(a, f(b,c))
    IDENTITY = "identity"  # f(x, identity) == x
    INVERSE = "inverse"  # f(g(x)) == x
    ORACLE = "oracle"  # new_impl(x) == reference(x)
    EASY_TO_VERIFY = "easy_to_verify"  # is_sorted(sort(x))
    NO_EXCEPTION = "no_exception"  # No crash on valid input


class TestStrategy(Enum):
    """Testing strategy based on code pattern."""
    HIGH = "high"  # Strongly recommended
    MEDIUM = "medium"  # Recommended
    LOW = "low"  # Optional


@dataclass
class PropertySuggestion:
    """A suggested property for testing."""
    property_type: PropertyType
    description: str
    pattern_detected: str
    file_path: str
    line_number: int
    strategy: TestStrategy
    example_test: str
    rationale: str

    def to_markdown(self) -> str:
        return f"""### {self.property_type.value.title()} Property

**Pattern**: {self.pattern_detected}
**Location**: `{self.file_path}:{self.line_number}`
**Priority**: {self.strategy.value.upper()}

**Description**: {self.description}

**Rationale**: {self.rationale}

**Example Test**:
```solidity
{self.example_test}
```
"""


@dataclass
class PBTReport:
    """Property-based testing recommendations report."""
    project_path: str
    files_analyzed: list[str]
    suggestions: list[PropertySuggestion]
    library_detected: Optional[str] = None

    def to_markdown(self) -> str:
        lines = [
            "# Property-Based Testing Recommendations",
            "",
            f"**Project**: {self.project_path}",
            f"**Files Analyzed**: {len(self.files_analyzed)}",
            f"**Properties Suggested**: {len(self.suggestions)}",
        ]

        if self.library_detected:
            lines.append(f"**PBT Library Detected**: {self.library_detected}")

        lines.extend([
            "",
            "## Property Catalog",
            "",
            "| Property | Formula | When to Use |",
            "|----------|---------|-------------|",
            "| Roundtrip | `decode(encode(x)) == x` | Serialization pairs |",
            "| Idempotence | `f(f(x)) == f(x)` | Normalization, formatting |",
            "| Invariant | Property holds before/after | Any transformation |",
            "| Commutativity | `f(a, b) == f(b, a)` | Binary/set operations |",
            "| Identity | `f(x, identity) == x` | Operations with neutral element |",
            "| Inverse | `f(g(x)) == x` | encrypt/decrypt pairs |",
            "| Oracle | `new_impl(x) == reference(x)` | Refactoring verification |",
            "",
            "**Strength hierarchy** (weakest to strongest):",
            "No Exception → Type Preservation → Invariant → Idempotence → Roundtrip",
            "",
            "## Suggested Properties",
            "",
        ])

        # Group by priority
        for strategy in TestStrategy:
            strategy_suggestions = [s for s in self.suggestions if s.strategy == strategy]
            if strategy_suggestions:
                lines.append(f"### {strategy.value.upper()} Priority ({len(strategy_suggestions)})")
                lines.append("")
                for s in strategy_suggestions:
                    lines.append(s.to_markdown())
                    lines.append("---")
                    lines.append("")

        return "\n".join(lines)


class PropertyBasedTestingGuide:
    """
    Guide for property-based testing.

    Automatically detects patterns where PBT provides stronger
    coverage than example-based tests:
    - Serialization pairs (encode/decode)
    - Parsers
    - Normalization functions
    - Validators
    - Data structures
    - Mathematical/algorithmic functions
    - Smart contract invariants
    """

    # Patterns that suggest roundtrip properties
    ROUNDTRIP_PATTERNS = [
        (r'(encode|serialize|pack|toBytes|toJSON)\w*\s*\(', r'(decode|deserialize|unpack|fromBytes|fromJSON)\w*\s*\('),
        (r'compress\w*\s*\(', r'decompress\w*\s*\('),
        (r'encrypt\w*\s*\(', r'decrypt\w*\s*\('),
    ]

    # Patterns that suggest idempotence properties
    IDEMPOTENCE_PATTERNS = [
        r'normalize\w*\s*\(',
        r'sanitize\w*\s*\(',
        r'clean\w*\s*\(',
        r'format\w*\s*\(',
        r'sort\w*\s*\(',
    ]

    # Patterns that suggest invariant properties
    INVARIANT_PATTERNS = [
        (r'deposit\s*\(', "totalSupply should not decrease"),
        (r'withdraw\s*\(', "totalSupply should not increase"),
        (r'transfer\s*\(', "sum of balances should remain constant"),
        (r'mint\s*\(', "totalSupply should increase by minted amount"),
        (r'burn\s*\(', "totalSupply should decrease by burned amount"),
        (r'swap\s*\(', "product of reserves should not decrease (for AMM)"),
    ]

    # PBT libraries to detect
    PBT_LIBRARIES = {
        "echidna": r'echidna|invariant|property',
        "foundry_fuzz": r'function\s+test\w*\s*\(\s*\w+\s+\w+',  # Foundry fuzz test
        "hypothesis": r'@given|hypothesis',
        "fast_check": r'fast-check|fc\.',
        "proptest": r'proptest|prop_compose',
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def analyze(self) -> PBTReport:
        """Analyze project and suggest properties."""
        suggestions: list[PropertySuggestion] = []
        files_analyzed: list[str] = []
        library_detected = None

        # Find all contract files
        for pattern in ["**/*.sol", "**/*.rs", "**/*.py", "**/*.ts"]:
            for file_path in self.project_path.glob(pattern):
                if "test" in str(file_path).lower():
                    # Check for existing PBT library
                    content = file_path.read_text()
                    for lib, lib_pattern in self.PBT_LIBRARIES.items():
                        if re.search(lib_pattern, content, re.IGNORECASE):
                            library_detected = lib
                    continue

                rel_path = str(file_path.relative_to(self.project_path))
                files_analyzed.append(rel_path)

                content = file_path.read_text()
                suggestions.extend(self._analyze_file(content, rel_path))

        return PBTReport(
            project_path=str(self.project_path),
            files_analyzed=files_analyzed,
            suggestions=suggestions,
            library_detected=library_detected,
        )

    def _analyze_file(self, content: str, file_path: str) -> list[PropertySuggestion]:
        """Analyze a file for property suggestions."""
        suggestions = []

        # Check for roundtrip patterns
        for encode_pattern, decode_pattern in self.ROUNDTRIP_PATTERNS:
            encode_match = re.search(encode_pattern, content)
            decode_match = re.search(decode_pattern, content)

            if encode_match and decode_match:
                line_num = content[:encode_match.start()].count('\n') + 1
                func_name = self._extract_function_name(encode_match.group(0))

                suggestions.append(PropertySuggestion(
                    property_type=PropertyType.ROUNDTRIP,
                    description=f"Verify roundtrip property for {func_name}",
                    pattern_detected=f"{func_name} / {self._extract_function_name(decode_match.group(0))}",
                    file_path=file_path,
                    line_number=line_num,
                    strategy=TestStrategy.HIGH,
                    example_test=self._generate_roundtrip_test(func_name),
                    rationale="Serialization pairs should satisfy decode(encode(x)) == x for all valid inputs",
                ))

        # Check for idempotence patterns
        for pattern in self.IDEMPOTENCE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                func_name = self._extract_function_name(match.group(0))

                suggestions.append(PropertySuggestion(
                    property_type=PropertyType.IDEMPOTENCE,
                    description=f"Verify idempotence for {func_name}",
                    pattern_detected=func_name,
                    file_path=file_path,
                    line_number=line_num,
                    strategy=TestStrategy.MEDIUM,
                    example_test=self._generate_idempotence_test(func_name),
                    rationale="Normalization/formatting functions should be idempotent: f(f(x)) == f(x)",
                ))

        # Check for invariant patterns (smart contracts)
        for pattern, invariant_desc in self.INVARIANT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                func_name = self._extract_function_name(match.group(0))

                suggestions.append(PropertySuggestion(
                    property_type=PropertyType.INVARIANT,
                    description=f"Invariant for {func_name}: {invariant_desc}",
                    pattern_detected=func_name,
                    file_path=file_path,
                    line_number=line_num,
                    strategy=TestStrategy.HIGH,
                    example_test=self._generate_invariant_test(func_name, invariant_desc),
                    rationale=f"State invariant should hold after {func_name}: {invariant_desc}",
                ))

        return suggestions

    def _extract_function_name(self, pattern_match: str) -> str:
        """Extract function name from pattern match."""
        match = re.match(r'(\w+)\s*\(', pattern_match)
        return match.group(1) if match else "unknown"

    def _generate_roundtrip_test(self, func_name: str) -> str:
        """Generate example roundtrip test."""
        decode_name = func_name.replace("encode", "decode").replace("serialize", "deserialize")
        return f'''// Foundry fuzz test
function testFuzz_roundtrip_{func_name}(bytes memory input) public {{
    bytes memory encoded = {func_name}(input);
    bytes memory decoded = {decode_name}(encoded);
    assertEq(keccak256(input), keccak256(decoded), "Roundtrip failed");
}}

// Echidna invariant
function echidna_roundtrip() public returns (bool) {{
    // Generate random input
    bytes memory input = /* ... */;
    bytes memory encoded = {func_name}(input);
    bytes memory decoded = {decode_name}(encoded);
    return keccak256(input) == keccak256(decoded);
}}'''

    def _generate_idempotence_test(self, func_name: str) -> str:
        """Generate example idempotence test."""
        return f'''// Foundry fuzz test
function testFuzz_idempotence_{func_name}(bytes memory input) public {{
    bytes memory once = {func_name}(input);
    bytes memory twice = {func_name}(once);
    assertEq(keccak256(once), keccak256(twice), "Not idempotent");
}}'''

    def _generate_invariant_test(self, func_name: str, invariant: str) -> str:
        """Generate example invariant test."""
        return f'''// Echidna invariant
function echidna_{func_name}_invariant() public returns (bool) {{
    // {invariant}
    // Example: totalSupply check
    uint256 sumBalances = /* sum all balances */;
    return sumBalances == totalSupply();
}}

// Foundry invariant
function invariant_{func_name}() public {{
    // {invariant}
    assertEq(/* actual */, /* expected */, "Invariant violated");
}}'''


def suggest_properties(
    project_path: str,
    output_path: Optional[str] = None,
) -> PBTReport:
    """
    Suggest properties for property-based testing.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        PBTReport with suggestions
    """
    guide = PropertyBasedTestingGuide(project_path)
    report = guide.analyze()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
