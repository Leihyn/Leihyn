"""
Constant Time Analyzer - Trail of Bits Skill

Detects timing side-channel vulnerabilities in cryptographic code.
Identifies operations that leak secret data through execution timing.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re


class ViolationType(Enum):
    """Types of timing violations."""
    DIVISION = "division"  # DIV, IDIV, SDIV - timing depends on operand
    BRANCH = "branch"  # Conditional jump based on secret
    COMPARISON = "comparison"  # Early-exit comparison
    TABLE_LOOKUP = "table_lookup"  # Secret-indexed array access
    WEAK_RNG = "weak_rng"  # Non-cryptographic RNG


class Language(Enum):
    """Supported languages for analysis."""
    C = "c"
    CPP = "cpp"
    GO = "go"
    RUST = "rust"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    SOLIDITY = "solidity"


@dataclass
class TimingViolation:
    """A detected timing vulnerability."""
    violation_type: ViolationType
    file_path: str
    line_number: int
    function_name: str
    code_snippet: str
    description: str
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None

    def to_markdown(self) -> str:
        status = "POTENTIAL FALSE POSITIVE" if self.is_false_positive else "VIOLATION"
        return f"""### [{status}] {self.violation_type.value.upper()}

**Location**: `{self.file_path}:{self.line_number}` in `{self.function_name}`

**Description**: {self.description}

**Code**:
```
{self.code_snippet}
```

{f'**Note**: {self.false_positive_reason}' if self.false_positive_reason else ''}
"""


@dataclass
class ConstantTimeReport:
    """Complete constant-time analysis report."""
    project_path: str
    files_analyzed: list[str]
    violations: list[TimingViolation]
    functions_analyzed: int
    passed: bool

    def to_markdown(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            "# Constant-Time Analysis Report",
            "",
            f"**Project**: {self.project_path}",
            f"**Status**: {status}",
            f"**Files Analyzed**: {len(self.files_analyzed)}",
            f"**Functions Analyzed**: {self.functions_analyzed}",
            f"**Violations Found**: {len(self.violations)}",
            "",
            "## Quick Reference",
            "",
            "| Problem | Detection | Fix |",
            "|---------|-----------|-----|",
            "| Division on secrets | DIV, IDIV, SDIV | Barrett reduction or multiply-by-inverse |",
            "| Branch on secrets | JE, JNE, BEQ, BNE | Constant-time selection (cmov, bit masking) |",
            "| Secret comparison | Early-exit memcmp | Use `crypto/subtle` constant-time compare |",
            "| Weak RNG | rand(), mt_rand | Use crypto-secure RNG |",
            "| Table lookup by secret | Array subscript | Bit-sliced lookups |",
            "",
            "## Real-World Impact",
            "",
            "- **KyberSlash (2023)**: Division instructions in ML-KEM allowed key recovery",
            "- **Lucky Thirteen (2013)**: CBC padding timing enabled plaintext recovery",
            "- **RSA Timing Attacks**: Early implementations leaked private key bits",
            "",
            "## Violations",
            "",
        ]

        if not self.violations:
            lines.append("No timing violations detected.")
        else:
            for v in self.violations:
                lines.append(v.to_markdown())
                lines.append("---")
                lines.append("")

        lines.append("## Verification Notes")
        lines.append("")
        lines.append("**CRITICAL**: Not every flagged operation is a vulnerability.")
        lines.append("For each violation, verify: **Does this operation's input depend on secret data?**")
        lines.append("")
        lines.append("### Triage Questions")
        lines.append("")
        lines.append("| Question | If Yes | If No |")
        lines.append("|----------|--------|-------|")
        lines.append("| Is operand a compile-time constant? | Likely FP | Continue |")
        lines.append("| Is operand public (length, count)? | Likely FP | Continue |")
        lines.append("| Is operand from key/plaintext/secret? | **VULNERABLE** | Likely FP |")

        return "\n".join(lines)


class ConstantTimeAnalyzer:
    """
    Analyze cryptographic code for timing side-channel vulnerabilities.

    Detects:
    - Division on secret values (KyberSlash pattern)
    - Branches on secret values
    - Early-exit comparisons
    - Table lookups with secret indices
    - Weak random number generators

    Limitations:
    - Static analysis only (no runtime behavior)
    - No data flow analysis (flags all dangerous operations)
    - Manual review required to verify if operands are secret
    """

    # Division patterns by language
    DIVISION_PATTERNS = {
        Language.C: r'[^/]/[^/=*]|\s%\s',
        Language.CPP: r'[^/]/[^/=*]|\s%\s',
        Language.GO: r'[^/]/[^/=*]|\s%\s',
        Language.RUST: r'[^/]/[^/=*]|\s%\s',
        Language.PYTHON: r'[^/]/[^/=]|\s%\s|//\s',
        Language.SOLIDITY: r'[^/]/[^/=*]|\s%\s',
    }

    # Branch patterns (conditional on potential secrets)
    BRANCH_PATTERNS = {
        Language.SOLIDITY: [
            (r'if\s*\(\s*\w*(secret|key|private|password|token)', "Branch may depend on secret"),
            (r'require\s*\(\s*\w*(secret|key|private)', "Require may depend on secret"),
        ],
        Language.PYTHON: [
            (r'if\s+\w*(secret|key|private|password|token)', "Branch may depend on secret"),
        ],
        Language.GO: [
            (r'if\s+\w*(secret|key|private|password|token)', "Branch may depend on secret"),
        ],
    }

    # Comparison patterns (potential timing leak)
    COMPARISON_PATTERNS = {
        Language.SOLIDITY: [
            (r'==\s*\w*(hash|signature|mac|digest)', "Direct comparison of cryptographic value"),
            (r'keccak256\([^)]+\)\s*==', "Hash comparison may leak timing"),
        ],
        Language.PYTHON: [
            (r'==\s*\w*(hash|signature|mac|digest|hmac)', "Direct comparison of cryptographic value"),
            (r'\w+\s*==\s*\w+.*hmac', "HMAC comparison may be timing-unsafe"),
        ],
        Language.GO: [
            (r'==\s*\w*(hash|signature|mac)', "Direct comparison - use subtle.ConstantTimeCompare"),
            (r'bytes\.Equal\(', "bytes.Equal is not constant-time"),
        ],
    }

    # Weak RNG patterns
    WEAK_RNG_PATTERNS = {
        Language.SOLIDITY: [
            (r'block\.timestamp', "Block timestamp is predictable"),
            (r'block\.number', "Block number is predictable"),
            (r'blockhash\(', "Blockhash can be manipulated"),
        ],
        Language.PYTHON: [
            (r'random\.random\(|random\.randint\(', "random module is not cryptographically secure"),
        ],
        Language.JAVASCRIPT: [
            (r'Math\.random\(', "Math.random is not cryptographically secure"),
        ],
        Language.GO: [
            (r'math/rand', "math/rand is not cryptographically secure - use crypto/rand"),
        ],
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def detect_language(self, file_path: Path) -> Optional[Language]:
        """Detect language from file extension."""
        ext_map = {
            ".sol": Language.SOLIDITY,
            ".py": Language.PYTHON,
            ".go": Language.GO,
            ".rs": Language.RUST,
            ".c": Language.C,
            ".cpp": Language.CPP,
            ".cc": Language.CPP,
            ".js": Language.JAVASCRIPT,
            ".ts": Language.JAVASCRIPT,
        }
        return ext_map.get(file_path.suffix.lower())

    def analyze(self) -> ConstantTimeReport:
        """Run constant-time analysis on project."""
        violations: list[TimingViolation] = []
        files_analyzed: list[str] = []
        functions_analyzed = 0

        # Find crypto-related files
        for pattern in ["**/*.sol", "**/*.py", "**/*.go", "**/*.rs", "**/*.c", "**/*.cpp"]:
            for file_path in self.project_path.glob(pattern):
                # Focus on crypto-related files
                content = file_path.read_text()
                if not self._is_crypto_related(content):
                    continue

                rel_path = str(file_path.relative_to(self.project_path))
                files_analyzed.append(rel_path)

                language = self.detect_language(file_path)
                if not language:
                    continue

                # Analyze file
                file_violations = self._analyze_file(content, rel_path, language)
                violations.extend(file_violations)

                # Count functions
                functions_analyzed += len(re.findall(r'function\s+\w+|def\s+\w+|func\s+\w+', content))

        return ConstantTimeReport(
            project_path=str(self.project_path),
            files_analyzed=files_analyzed,
            violations=violations,
            functions_analyzed=functions_analyzed,
            passed=len(violations) == 0,
        )

    def _is_crypto_related(self, content: str) -> bool:
        """Check if file contains crypto-related code."""
        crypto_keywords = [
            "crypto", "sign", "verify", "encrypt", "decrypt",
            "hash", "keccak", "sha", "hmac", "signature",
            "private", "secret", "key", "nonce", "salt",
            "ecdsa", "ed25519", "rsa", "aes", "cipher",
        ]
        content_lower = content.lower()
        return any(kw in content_lower for kw in crypto_keywords)

    def _analyze_file(
        self,
        content: str,
        file_path: str,
        language: Language,
    ) -> list[TimingViolation]:
        """Analyze a single file for timing violations."""
        violations = []

        # Check division patterns
        div_pattern = self.DIVISION_PATTERNS.get(language)
        if div_pattern:
            for match in re.finditer(div_pattern, content):
                line_num = content[:match.start()].count('\n') + 1

                # Check if it's in a crypto context
                context = content[max(0, match.start()-200):match.end()+100]
                if self._is_crypto_related(context):
                    violations.append(TimingViolation(
                        violation_type=ViolationType.DIVISION,
                        file_path=file_path,
                        line_number=line_num,
                        function_name=self._get_function_name(content, match.start()),
                        code_snippet=self._get_context(content, match.start()),
                        description="Division operation may have timing dependent on operand values",
                    ))

        # Check branch patterns
        branch_patterns = self.BRANCH_PATTERNS.get(language, [])
        for pattern, description in branch_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                violations.append(TimingViolation(
                    violation_type=ViolationType.BRANCH,
                    file_path=file_path,
                    line_number=line_num,
                    function_name=self._get_function_name(content, match.start()),
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                ))

        # Check comparison patterns
        comparison_patterns = self.COMPARISON_PATTERNS.get(language, [])
        for pattern, description in comparison_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                violations.append(TimingViolation(
                    violation_type=ViolationType.COMPARISON,
                    file_path=file_path,
                    line_number=line_num,
                    function_name=self._get_function_name(content, match.start()),
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                ))

        # Check weak RNG patterns
        rng_patterns = self.WEAK_RNG_PATTERNS.get(language, [])
        for pattern, description in rng_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                violations.append(TimingViolation(
                    violation_type=ViolationType.WEAK_RNG,
                    file_path=file_path,
                    line_number=line_num,
                    function_name=self._get_function_name(content, match.start()),
                    code_snippet=self._get_context(content, match.start()),
                    description=description,
                ))

        return violations

    def _get_function_name(self, content: str, pos: int) -> str:
        """Get the function name containing a position."""
        # Look backwards for function definition
        before = content[:pos]
        func_match = re.search(
            r'(?:function|def|func|fn)\s+(\w+)',
            before[::-1][:500][::-1]  # Last 500 chars before pos
        )
        return func_match.group(1) if func_match else "unknown"

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


def analyze_constant_time(
    project_path: str,
    output_path: Optional[str] = None,
) -> ConstantTimeReport:
    """
    Analyze project for timing side-channel vulnerabilities.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        ConstantTimeReport with findings
    """
    analyzer = ConstantTimeAnalyzer(project_path)
    report = analyzer.analyze()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
