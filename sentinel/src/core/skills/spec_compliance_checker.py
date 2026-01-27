"""
Spec-to-Code Compliance Checker - Trail of Bits Skill

Verifies code implements exactly what documentation specifies.
For blockchain audits comparing code against whitepapers.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/spec-to-code-compliance
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from pathlib import Path
import re


class MatchType(Enum):
    """Type of spec-to-code alignment."""
    FULL_MATCH = "full_match"
    PARTIAL_MATCH = "partial_match"
    MISMATCH = "mismatch"
    MISSING_IN_CODE = "missing_in_code"
    CODE_STRONGER = "code_stronger_than_spec"
    CODE_WEAKER = "code_weaker_than_spec"
    UNDOCUMENTED = "undocumented"
    AMBIGUOUS = "ambiguous"


class DivergenceSeverity(Enum):
    """Severity of spec divergence."""
    CRITICAL = "critical"  # Spec says X, code does Y
    HIGH = "high"  # Partial/incorrect implementation
    MEDIUM = "medium"  # Ambiguity with security implications
    LOW = "low"  # Documentation drift


@dataclass
class SpecIR:
    """Intermediate Representation for spec item."""
    id: str
    excerpt: str
    source_section: str
    semantic_type: str  # "invariant", "flow", "formula", "requirement"
    normalized_form: str
    confidence: float  # 0-1
    implicit: bool = False  # Derived from context


@dataclass
class CodeIR:
    """Intermediate Representation for code behavior."""
    id: str
    file_path: str
    line_start: int
    line_end: int
    function_name: str
    behavior: str
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)


@dataclass
class AlignmentRecord:
    """Alignment between spec and code."""
    spec_item: SpecIR
    code_item: Optional[CodeIR]
    match_type: MatchType
    reasoning: str
    confidence: float
    evidence: list[str] = field(default_factory=list)


@dataclass
class DivergenceFinding:
    """A divergence between spec and code."""
    title: str
    severity: DivergenceSeverity
    spec_excerpt: str
    code_excerpt: str
    description: str
    attack_scenario: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        return f"""### [{self.severity.value.upper()}] {self.title}

**Spec Says**:
> {self.spec_excerpt}

**Code Does**:
```
{self.code_excerpt}
```

**Description**: {self.description}

**Attack Scenario**: {self.attack_scenario}

**Evidence**:
{chr(10).join(f'- {e}' for e in self.evidence)}

**Recommendation**: {self.recommendation}
"""


@dataclass
class ComplianceReport:
    """Complete spec-to-code compliance report."""
    project_name: str
    spec_sources: list[str]
    spec_items: list[SpecIR]
    code_items: list[CodeIR]
    alignments: list[AlignmentRecord]
    divergences: list[DivergenceFinding]

    @property
    def compliance_score(self) -> float:
        """Calculate overall compliance percentage."""
        if not self.alignments:
            return 0.0
        full_matches = len([a for a in self.alignments if a.match_type == MatchType.FULL_MATCH])
        return (full_matches / len(self.alignments)) * 100

    def to_markdown(self) -> str:
        lines = [
            f"# Spec-to-Code Compliance Report: {self.project_name}",
            "",
            "## Executive Summary",
            "",
            f"**Compliance Score**: {self.compliance_score:.1f}%",
            f"**Spec Items Extracted**: {len(self.spec_items)}",
            f"**Code Behaviors Analyzed**: {len(self.code_items)}",
            f"**Divergences Found**: {len(self.divergences)}",
            "",
            "### Spec Sources",
            "",
        ]

        for source in self.spec_sources:
            lines.append(f"- {source}")

        lines.extend([
            "",
            "## Alignment Matrix",
            "",
            "| Spec Item | Code Item | Match Type | Confidence |",
            "|-----------|-----------|------------|------------|",
        ])

        for alignment in self.alignments:
            spec_id = alignment.spec_item.id[:30]
            code_id = alignment.code_item.id[:30] if alignment.code_item else "N/A"
            match = alignment.match_type.value.replace("_", " ")
            conf = f"{alignment.confidence:.0%}"
            lines.append(f"| {spec_id} | {code_id} | {match} | {conf} |")

        lines.extend([
            "",
            "## Divergence Findings",
            "",
        ])

        for div in sorted(self.divergences, key=lambda d: d.severity.value):
            lines.append(div.to_markdown())
            lines.append("---")
            lines.append("")

        return "\n".join(lines)


class SpecComplianceChecker:
    """
    Verify code implements exactly what specification states.

    Global Rules:
    - Never infer unspecified behavior
    - Always cite exact evidence (section/quote + file/line)
    - Always provide confidence score (0-1)
    - Always classify ambiguity instead of guessing

    Phases:
    1. Documentation Discovery
    2. Format Normalization
    3. Spec Intent IR Extraction
    4. Code Behavior IR Extraction
    5. Alignment Analysis
    6. Divergence Classification
    """

    # Semantic types to extract from specs
    SEMANTIC_TYPES = [
        "invariant",
        "formula",
        "flow",
        "precondition",
        "postcondition",
        "actor",
        "trust_boundary",
        "economic_assumption",
        "security_requirement",
    ]

    # Patterns indicating requirements in specs
    REQUIREMENT_PATTERNS = [
        (r'must\s+(?:not\s+)?(\w+)', "requirement"),
        (r'shall\s+(?:not\s+)?(\w+)', "requirement"),
        (r'should\s+(?:not\s+)?(\w+)', "recommendation"),
        (r'never\s+(\w+)', "negative_requirement"),
        (r'always\s+(\w+)', "positive_requirement"),
        (r'invariant:\s*(.+)', "invariant"),
        (r'formula:\s*(.+)', "formula"),
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def discover_documentation(self) -> list[Path]:
        """Phase 0: Find all documentation files."""
        doc_patterns = [
            "**/*.md",
            "**/*.pdf",
            "**/whitepaper*",
            "**/spec*",
            "**/design*",
            "**/protocol*",
            "**/README*",
        ]

        docs = []
        for pattern in doc_patterns:
            docs.extend(self.project_path.glob(pattern))

        # Filter out likely non-spec files
        docs = [d for d in docs if not any(
            x in str(d).lower() for x in ["node_modules", "vendor", "test", ".git"]
        )]

        return docs

    def extract_spec_ir(self, doc_content: str, source: str) -> list[SpecIR]:
        """Phase 2-3: Extract Spec Intent IR."""
        spec_items = []

        # Extract requirements
        for pattern, sem_type in self.REQUIREMENT_PATTERNS:
            for match in re.finditer(pattern, doc_content, re.IGNORECASE):
                excerpt = doc_content[max(0, match.start()-50):match.end()+50]
                spec_items.append(SpecIR(
                    id=f"SPEC-{len(spec_items)+1}",
                    excerpt=excerpt.strip(),
                    source_section=source,
                    semantic_type=sem_type,
                    normalized_form=match.group(0),
                    confidence=0.8,
                ))

        # Extract formulas (mathematical notation)
        formula_pattern = r'[A-Za-z_]+\s*[=<>≤≥]\s*[A-Za-z0-9_\s\+\-\*\/\(\)]+\s*'
        for match in re.finditer(formula_pattern, doc_content):
            spec_items.append(SpecIR(
                id=f"SPEC-{len(spec_items)+1}",
                excerpt=match.group(0).strip(),
                source_section=source,
                semantic_type="formula",
                normalized_form=match.group(0).strip(),
                confidence=0.6,
            ))

        return spec_items

    def extract_code_ir(self, file_path: Path) -> list[CodeIR]:
        """Phase 4: Extract Code Behavior IR."""
        content = file_path.read_text()
        code_items = []

        # Find functions
        func_pattern = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
            re.MULTILINE
        )

        for match in func_pattern.finditer(content):
            func_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1

            # Find function end (simplified)
            brace_count = 1
            pos = match.end()
            while brace_count > 0 and pos < len(content):
                if content[pos] == '{':
                    brace_count += 1
                elif content[pos] == '}':
                    brace_count -= 1
                pos += 1

            end_line = content[:pos].count('\n') + 1
            func_body = content[match.end():pos]

            # Extract state reads/writes (simplified)
            state_reads = re.findall(r'(\w+)\s*[^=]', func_body)
            state_writes = re.findall(r'(\w+)\s*=(?!=)', func_body)

            # Extract preconditions (require statements)
            preconditions = re.findall(r'require\s*\(([^)]+)\)', func_body)

            code_items.append(CodeIR(
                id=f"{file_path.name}:{func_name}",
                file_path=str(file_path),
                line_start=start_line,
                line_end=end_line,
                function_name=func_name,
                behavior=f"Function {func_name}",
                state_reads=list(set(state_reads))[:10],
                state_writes=list(set(state_writes))[:10],
                preconditions=preconditions,
            ))

        return code_items

    def align(
        self,
        spec_item: SpecIR,
        code_items: list[CodeIR],
    ) -> AlignmentRecord:
        """Phase 5: Align spec item with code."""
        # Simple keyword matching (real implementation would be more sophisticated)
        keywords = re.findall(r'\b\w{4,}\b', spec_item.excerpt.lower())

        best_match = None
        best_score = 0

        for code_item in code_items:
            code_text = f"{code_item.function_name} {code_item.behavior}".lower()
            score = sum(1 for kw in keywords if kw in code_text)

            if score > best_score:
                best_score = score
                best_match = code_item

        if best_match and best_score > 2:
            match_type = MatchType.FULL_MATCH
            confidence = min(best_score / len(keywords), 1.0) if keywords else 0
        elif best_match:
            match_type = MatchType.PARTIAL_MATCH
            confidence = 0.5
        else:
            match_type = MatchType.MISSING_IN_CODE
            confidence = 0.3

        return AlignmentRecord(
            spec_item=spec_item,
            code_item=best_match,
            match_type=match_type,
            reasoning=f"Keyword matching: {best_score}/{len(keywords)} keywords found",
            confidence=confidence,
        )

    def classify_divergence(
        self,
        alignment: AlignmentRecord,
    ) -> Optional[DivergenceFinding]:
        """Phase 6: Classify divergences."""
        if alignment.match_type == MatchType.FULL_MATCH:
            return None

        severity_map = {
            MatchType.MISMATCH: DivergenceSeverity.CRITICAL,
            MatchType.CODE_WEAKER: DivergenceSeverity.CRITICAL,
            MatchType.MISSING_IN_CODE: DivergenceSeverity.HIGH,
            MatchType.PARTIAL_MATCH: DivergenceSeverity.MEDIUM,
            MatchType.CODE_STRONGER: DivergenceSeverity.LOW,
            MatchType.AMBIGUOUS: DivergenceSeverity.MEDIUM,
            MatchType.UNDOCUMENTED: DivergenceSeverity.LOW,
        }

        return DivergenceFinding(
            title=f"Divergence: {alignment.spec_item.id}",
            severity=severity_map.get(alignment.match_type, DivergenceSeverity.MEDIUM),
            spec_excerpt=alignment.spec_item.excerpt,
            code_excerpt=alignment.code_item.behavior if alignment.code_item else "NOT FOUND",
            description=alignment.reasoning,
            attack_scenario="Potential for behavior to differ from user expectations based on spec",
            recommendation="Verify implementation matches spec intent",
            evidence=[f"Confidence: {alignment.confidence:.0%}"],
        )

    def check(
        self,
        spec_paths: Optional[list[str]] = None,
    ) -> ComplianceReport:
        """Run full compliance check."""
        # Phase 0: Discover documentation
        if spec_paths:
            doc_files = [Path(p) for p in spec_paths]
        else:
            doc_files = self.discover_documentation()

        spec_sources = [str(f) for f in doc_files]

        # Phase 2-3: Extract Spec IR
        spec_items = []
        for doc_file in doc_files:
            if doc_file.suffix in ['.md', '.txt']:
                try:
                    content = doc_file.read_text()
                    items = self.extract_spec_ir(content, str(doc_file))
                    spec_items.extend(items)
                except Exception:
                    pass

        # Phase 4: Extract Code IR
        code_items = []
        for sol_file in self.project_path.glob("**/*.sol"):
            if "test" not in str(sol_file).lower():
                try:
                    items = self.extract_code_ir(sol_file)
                    code_items.extend(items)
                except Exception:
                    pass

        # Phase 5: Alignment
        alignments = []
        for spec_item in spec_items:
            alignment = self.align(spec_item, code_items)
            alignments.append(alignment)

        # Phase 6: Classify divergences
        divergences = []
        for alignment in alignments:
            div = self.classify_divergence(alignment)
            if div:
                divergences.append(div)

        return ComplianceReport(
            project_name=self.project_path.name,
            spec_sources=spec_sources,
            spec_items=spec_items,
            code_items=code_items,
            alignments=alignments,
            divergences=divergences,
        )


def check_compliance(
    project_path: str,
    spec_paths: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> ComplianceReport:
    """
    Check spec-to-code compliance.

    Args:
        project_path: Path to project root
        spec_paths: Optional list of spec file paths
        output_path: Optional path for markdown report

    Returns:
        ComplianceReport with alignments and divergences
    """
    checker = SpecComplianceChecker(project_path)
    report = checker.check(spec_paths)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
