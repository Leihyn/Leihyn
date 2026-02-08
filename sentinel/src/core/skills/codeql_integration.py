"""
CodeQL Integration - Trail of Bits Skill

CodeQL static analysis for security vulnerability detection with
interprocedural taint tracking and data flow analysis.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/static-analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess
import json


class CodeQLLanguage(Enum):
    """Supported CodeQL languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    JAVA = "java"
    CPP = "cpp"
    CSHARP = "csharp"
    RUBY = "ruby"
    RUST = "rust"
    SWIFT = "swift"


class CodeQLSeverity(Enum):
    """CodeQL finding severity."""
    ERROR = "error"
    WARNING = "warning"
    RECOMMENDATION = "recommendation"


@dataclass
class CodeQLQuery:
    """A CodeQL query definition."""
    name: str
    description: str
    kind: str  # "problem" or "path-problem"
    severity: CodeQLSeverity
    security_severity: float  # 0.0 - 10.0 CVSS
    precision: str  # "very-high", "high", "medium", "low"
    query_code: str
    cwe_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_ql(self) -> str:
        """Convert to QL file format."""
        lines = [
            "/**",
            f" * @name {self.name}",
            f" * @description {self.description}",
            f" * @kind {self.kind}",
            f" * @problem.severity {self.severity.value}",
            f" * @security-severity {self.security_severity}",
            f" * @precision {self.precision}",
            f" * @id custom/{self.name.lower().replace(' ', '-')}",
        ]

        if self.cwe_ids:
            for cwe in self.cwe_ids:
                lines.append(f" * @tags external/cwe/{cwe}")

        for tag in self.tags:
            lines.append(f" * @tags {tag}")

        lines.append(" */")
        lines.append("")
        lines.append(self.query_code)

        return "\n".join(lines)


@dataclass
class CodeQLResult:
    """A CodeQL finding."""
    query_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    code_flows: list[dict] = field(default_factory=list)  # For path-problems

    def to_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "message": self.message,
            "severity": self.severity,
            "location": f"{self.file_path}:{self.start_line}:{self.start_column}",
        }


@dataclass
class CodeQLReport:
    """Complete CodeQL analysis report."""
    project_path: str
    database_path: str
    language: CodeQLLanguage
    queries_run: list[str]
    results: list[CodeQLResult]
    errors: list[str]

    def to_markdown(self) -> str:
        lines = [
            "# CodeQL Analysis Report",
            "",
            f"**Project**: {self.project_path}",
            f"**Language**: {self.language.value}",
            f"**Database**: {self.database_path}",
            f"**Queries**: {', '.join(self.queries_run)}",
            f"**Findings**: {len(self.results)}",
            "",
            "## Why CodeQL?",
            "",
            "CodeQL tracks data flow across function boundaries:",
            "```",
            "HTTP Handler → Input Parser → Business Logic → Database Query",
            "     ↓              ↓              ↓              ↓",
            "   source      transforms       passes       sink (SQL)",
            "```",
            "",
            "Pattern-based tools miss this because they can't connect",
            "`request.param` in file A to `db.execute(query)` in file B.",
            "",
            "## Findings",
            "",
        ]

        for result in self.results:
            lines.append(f"### {result.query_id}")
            lines.append(f"**Severity**: {result.severity}")
            lines.append(f"**Location**: `{result.file_path}:{result.start_line}`")
            lines.append(f"**Message**: {result.message}")

            if result.code_flows:
                lines.append("")
                lines.append("**Data Flow Path**:")
                for i, step in enumerate(result.code_flows[:10]):
                    loc = step.get("location", {})
                    msg = step.get("message", "")
                    lines.append(f"{i+1}. `{loc}`: {msg}")

            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)


class CodeQLIntegration:
    """
    CodeQL static analysis integration.

    When to use CodeQL:
    - Need interprocedural data flow and taint tracking
    - Finding complex vulnerabilities requiring AST/CFG analysis
    - Open-source projects or GitHub Advanced Security license
    - Comprehensive security audits

    Consider Semgrep instead when:
    - No build capability for compiled languages
    - Need fast, lightweight pattern matching
    - Licensing constraints
    """

    # Language-specific requirements
    LANGUAGE_CONFIG = {
        CodeQLLanguage.PYTHON: {"build_required": False},
        CodeQLLanguage.JAVASCRIPT: {"build_required": False},
        CodeQLLanguage.GO: {"build_required": False},
        CodeQLLanguage.RUBY: {"build_required": False},
        CodeQLLanguage.JAVA: {"build_required": True, "command": "./gradlew build"},
        CodeQLLanguage.CPP: {"build_required": True, "command": "make -j8"},
        CodeQLLanguage.CSHARP: {"build_required": True, "command": "dotnet build"},
        CodeQLLanguage.RUST: {"build_required": True, "command": "cargo build"},
        CodeQLLanguage.SWIFT: {"build_required": True},
    }

    def __init__(self):
        self.available = self._check_installation()

    def _check_installation(self) -> bool:
        """Check if CodeQL is installed."""
        try:
            result = subprocess.run(
                ["codeql", "version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def create_database(
        self,
        project_path: str,
        language: CodeQLLanguage,
        database_path: str,
        build_command: Optional[str] = None,
    ) -> bool:
        """
        Create a CodeQL database for analysis.

        For compiled languages, build_command is required.
        """
        cmd = [
            "codeql", "database", "create",
            database_path,
            f"--language={language.value}",
            f"--source-root={project_path}",
        ]

        config = self.LANGUAGE_CONFIG.get(language, {})
        if config.get("build_required"):
            build_cmd = build_command or config.get("command")
            if build_cmd:
                cmd.extend(["--command", build_cmd])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout
            )
            return result.returncode == 0
        except Exception:
            return False

    def analyze(
        self,
        database_path: str,
        queries: Optional[list[str]] = None,
        output_format: str = "sarif-latest",
        output_path: str = "results.sarif",
    ) -> CodeQLReport:
        """
        Run CodeQL analysis on a database.

        Args:
            database_path: Path to CodeQL database
            queries: Query packs or paths (default: security-extended)
            output_format: Output format (sarif-latest, csv)
            output_path: Path for results file

        Returns:
            CodeQLReport with findings
        """
        queries = queries or ["codeql/python-queries:codeql-suites/python-security-extended.qls"]

        cmd = [
            "codeql", "database", "analyze",
            database_path,
            f"--format={output_format}",
            f"--output={output_path}",
            "--",
        ] + queries

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout
            )

            # Parse SARIF output
            results = []
            errors = []

            if Path(output_path).exists():
                sarif_data = json.loads(Path(output_path).read_text())

                for run in sarif_data.get("runs", []):
                    for finding in run.get("results", []):
                        # Get location
                        locations = finding.get("locations", [{}])
                        location = locations[0].get("physicalLocation", {}) if locations else {}
                        region = location.get("region", {})

                        # Get code flows for path-problems
                        code_flows = []
                        for flow in finding.get("codeFlows", []):
                            for thread_flow in flow.get("threadFlows", []):
                                for loc in thread_flow.get("locations", []):
                                    code_flows.append({
                                        "location": loc.get("location", {}).get("physicalLocation", {}),
                                        "message": loc.get("location", {}).get("message", {}).get("text", ""),
                                    })

                        results.append(CodeQLResult(
                            query_id=finding.get("ruleId", ""),
                            message=finding.get("message", {}).get("text", ""),
                            severity=finding.get("level", "warning"),
                            file_path=location.get("artifactLocation", {}).get("uri", ""),
                            start_line=region.get("startLine", 0),
                            start_column=region.get("startColumn", 0),
                            end_line=region.get("endLine", 0),
                            end_column=region.get("endColumn", 0),
                            code_flows=code_flows,
                        ))

            # Detect language from database
            language = CodeQLLanguage.PYTHON  # Default, would detect from database

            return CodeQLReport(
                project_path="",
                database_path=database_path,
                language=language,
                queries_run=queries,
                results=results,
                errors=errors,
            )

        except subprocess.TimeoutExpired:
            return CodeQLReport(
                project_path="",
                database_path=database_path,
                language=CodeQLLanguage.PYTHON,
                queries_run=queries,
                results=[],
                errors=["Analysis timed out after 1 hour"],
            )

    def create_taint_query(
        self,
        name: str,
        description: str,
        language: str,
        source_predicate: str,
        sink_predicate: str,
    ) -> CodeQLQuery:
        """
        Create a taint tracking query.

        Example:
            create_taint_query(
                "SQL Injection",
                "User input flows to SQL query",
                "python",
                source_predicate="exists(source)",
                sink_predicate="exists(sink)",
            )
        """
        query_code = f'''
import {language}
import semmle.{language}.dataflow.new.DataFlow
import semmle.{language}.dataflow.new.TaintTracking

module TaintConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    {source_predicate}
  }}

  predicate isSink(DataFlow::Node sink) {{
    {sink_predicate}
  }}
}}

module TaintFlow = TaintTracking::Global<TaintConfig>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "{description}"
'''

        return CodeQLQuery(
            name=name,
            description=description,
            kind="path-problem",
            severity=CodeQLSeverity.ERROR,
            security_severity=9.0,
            precision="high",
            query_code=query_code,
            tags=["security"],
        )


def run_codeql(
    database_path: str,
    queries: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> CodeQLReport:
    """
    Run CodeQL analysis.

    Args:
        database_path: Path to CodeQL database
        queries: Query packs to run
        output_path: Optional path for markdown report

    Returns:
        CodeQLReport with findings
    """
    integration = CodeQLIntegration()

    if not integration.available:
        return CodeQLReport(
            project_path="",
            database_path=database_path,
            language=CodeQLLanguage.PYTHON,
            queries_run=[],
            results=[],
            errors=["CodeQL not installed. Install with: brew install --cask codeql"],
        )

    report = integration.analyze(database_path, queries)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report


def create_codeql_database(
    project_path: str,
    language: str,
    database_path: str,
    build_command: Optional[str] = None,
) -> bool:
    """
    Create a CodeQL database for analysis.

    Args:
        project_path: Path to source code
        language: Language (python, javascript, go, java, cpp, etc.)
        database_path: Where to create the database
        build_command: Build command for compiled languages

    Returns:
        True if successful
    """
    integration = CodeQLIntegration()

    if not integration.available:
        return False

    lang = CodeQLLanguage(language)
    return integration.create_database(project_path, lang, database_path, build_command)
