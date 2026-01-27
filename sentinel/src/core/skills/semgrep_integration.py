"""
Semgrep Integration - Trail of Bits Skill

Run Semgrep static analysis and create custom rules for vulnerability detection.
Fast pattern matching with taint mode support.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/static-analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess
import json
import tempfile


class SemgrepSeverity(Enum):
    """Semgrep finding severity."""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class SemgrepRule:
    """A Semgrep rule definition."""
    id: str
    languages: list[str]
    message: str
    severity: SemgrepSeverity
    pattern: Optional[str] = None
    patterns: Optional[list[dict]] = None
    mode: str = "search"  # "search" or "taint"
    pattern_sources: Optional[list[dict]] = None
    pattern_sinks: Optional[list[dict]] = None
    pattern_sanitizers: Optional[list[dict]] = None
    metadata: dict = field(default_factory=dict)

    def to_yaml(self) -> str:
        """Convert to YAML format."""
        lines = [
            "rules:",
            f"  - id: {self.id}",
            f"    languages: [{', '.join(self.languages)}]",
            f"    message: \"{self.message}\"",
            f"    severity: {self.severity.value}",
        ]

        if self.mode == "taint":
            lines.append("    mode: taint")
            if self.pattern_sources:
                lines.append("    pattern-sources:")
                for source in self.pattern_sources:
                    lines.append(f"      - pattern: {source.get('pattern', '')}")
            if self.pattern_sinks:
                lines.append("    pattern-sinks:")
                for sink in self.pattern_sinks:
                    lines.append(f"      - pattern: {sink.get('pattern', '')}")
            if self.pattern_sanitizers:
                lines.append("    pattern-sanitizers:")
                for sanitizer in self.pattern_sanitizers:
                    lines.append(f"      - pattern: {sanitizer.get('pattern', '')}")
        elif self.pattern:
            lines.append(f"    pattern: {self.pattern}")
        elif self.patterns:
            lines.append("    patterns:")
            for p in self.patterns:
                for key, value in p.items():
                    lines.append(f"      - {key}: {value}")

        if self.metadata:
            lines.append("    metadata:")
            for key, value in self.metadata.items():
                lines.append(f"      {key}: \"{value}\"")

        return "\n".join(lines)


@dataclass
class SemgrepResult:
    """A Semgrep finding."""
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    code_snippet: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class SemgrepReport:
    """Complete Semgrep scan report."""
    project_path: str
    rules_used: list[str]
    results: list[SemgrepResult]
    errors: list[str]
    scan_time_ms: int = 0

    def to_markdown(self) -> str:
        lines = [
            "# Semgrep Scan Report",
            "",
            f"**Project**: {self.project_path}",
            f"**Rules**: {', '.join(self.rules_used)}",
            f"**Findings**: {len(self.results)}",
            "",
            "## Findings",
            "",
        ]

        # Group by severity
        for severity in ["ERROR", "WARNING", "INFO"]:
            findings = [r for r in self.results if r.severity == severity]
            if findings:
                lines.append(f"### {severity} ({len(findings)})")
                lines.append("")
                for f in findings:
                    lines.append(f"#### {f.rule_id}")
                    lines.append(f"**Location**: `{f.path}:{f.start_line}`")
                    lines.append(f"**Message**: {f.message}")
                    lines.append(f"```\n{f.code_snippet}\n```")
                    lines.append("")

        return "\n".join(lines)


class SemgrepIntegration:
    """
    Semgrep static analysis integration.

    When to use Semgrep:
    - Quick security scans (minutes, not hours)
    - Pattern-based bug detection
    - Single-file analysis without complex data flow
    - First-pass analysis before deeper tools

    Consider CodeQL instead when:
    - Need interprocedural taint tracking across files
    - Complex data flow analysis required
    """

    # Recommended rulesets
    SECURITY_RULESETS = [
        "p/security-audit",
        "p/owasp-top-ten",
        "p/trailofbits",
        "p/r2c-security-audit",
    ]

    def __init__(self):
        self._check_installation()

    def _check_installation(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            result = subprocess.run(["semgrep", "--version"], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def scan(
        self,
        project_path: str,
        rulesets: Optional[list[str]] = None,
        custom_rules: Optional[list[SemgrepRule]] = None,
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> SemgrepReport:
        """
        Run Semgrep scan on a project.

        Args:
            project_path: Path to scan
            rulesets: Rulesets to use (e.g., "p/security-audit")
            custom_rules: Custom rules to include
            include_patterns: File patterns to include
            exclude_patterns: File patterns to exclude

        Returns:
            SemgrepReport with findings
        """
        rulesets = rulesets or ["auto"]

        cmd = ["semgrep", "--json"]

        # Add rulesets
        for ruleset in rulesets:
            cmd.extend(["--config", ruleset])

        # Add custom rules
        temp_rule_file = None
        if custom_rules:
            temp_rule_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.yaml', delete=False
            )
            yaml_content = "\n".join(rule.to_yaml() for rule in custom_rules)
            temp_rule_file.write(yaml_content)
            temp_rule_file.close()
            cmd.extend(["--config", temp_rule_file.name])

        # Add include/exclude patterns
        if include_patterns:
            for pattern in include_patterns:
                cmd.extend(["--include", pattern])
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd.extend(["--exclude", pattern])

        cmd.append(project_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            # Parse JSON output
            data = json.loads(result.stdout) if result.stdout else {}

            results = []
            for finding in data.get("results", []):
                results.append(SemgrepResult(
                    rule_id=finding.get("check_id", ""),
                    path=finding.get("path", ""),
                    start_line=finding.get("start", {}).get("line", 0),
                    end_line=finding.get("end", {}).get("line", 0),
                    message=finding.get("extra", {}).get("message", ""),
                    severity=finding.get("extra", {}).get("severity", "INFO"),
                    code_snippet=finding.get("extra", {}).get("lines", ""),
                    metadata=finding.get("extra", {}).get("metadata", {}),
                ))

            errors = [e.get("message", "") for e in data.get("errors", [])]

            return SemgrepReport(
                project_path=project_path,
                rules_used=rulesets,
                results=results,
                errors=errors,
            )

        except subprocess.TimeoutExpired:
            return SemgrepReport(
                project_path=project_path,
                rules_used=rulesets,
                results=[],
                errors=["Scan timed out after 10 minutes"],
            )
        finally:
            if temp_rule_file:
                Path(temp_rule_file.name).unlink(missing_ok=True)

    def create_taint_rule(
        self,
        rule_id: str,
        languages: list[str],
        message: str,
        sources: list[str],
        sinks: list[str],
        sanitizers: Optional[list[str]] = None,
    ) -> SemgrepRule:
        """
        Create a taint-mode rule for data flow analysis.

        Taint mode tracks data through assignments and transformations:
        - Source: Where untrusted data enters
        - Propagators: How it flows (automatic)
        - Sanitizers: What makes it safe
        - Sink: Where it becomes dangerous

        Example:
            create_taint_rule(
                "command-injection",
                ["python"],
                "User input flows to command execution",
                sources=["request.args.get(...)", "request.form[...]"],
                sinks=["os.system($SINK)", "subprocess.call($SINK, shell=True)"],
                sanitizers=["shlex.quote(...)"],
            )
        """
        return SemgrepRule(
            id=rule_id,
            languages=languages,
            message=message,
            severity=SemgrepSeverity.ERROR,
            mode="taint",
            pattern_sources=[{"pattern": s} for s in sources],
            pattern_sinks=[{"pattern": s} for s in sinks],
            pattern_sanitizers=[{"pattern": s} for s in sanitizers] if sanitizers else None,
        )

    def create_pattern_rule(
        self,
        rule_id: str,
        languages: list[str],
        message: str,
        pattern: str,
        severity: SemgrepSeverity = SemgrepSeverity.WARNING,
    ) -> SemgrepRule:
        """Create a simple pattern-matching rule."""
        return SemgrepRule(
            id=rule_id,
            languages=languages,
            message=message,
            severity=severity,
            pattern=pattern,
        )


def run_semgrep(
    project_path: str,
    rulesets: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> SemgrepReport:
    """
    Run Semgrep security scan.

    Args:
        project_path: Path to project
        rulesets: Rulesets to use (default: auto)
        output_path: Optional path for markdown report

    Returns:
        SemgrepReport with findings
    """
    integration = SemgrepIntegration()
    report = integration.scan(project_path, rulesets)

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report


def create_semgrep_rule(
    rule_id: str,
    languages: list[str],
    message: str,
    pattern: Optional[str] = None,
    sources: Optional[list[str]] = None,
    sinks: Optional[list[str]] = None,
    sanitizers: Optional[list[str]] = None,
) -> SemgrepRule:
    """
    Create a custom Semgrep rule.

    For simple patterns:
        create_semgrep_rule("hardcoded-password", ["python"],
            "Hardcoded password", pattern='password = "..."')

    For taint tracking:
        create_semgrep_rule("sql-injection", ["python"],
            "SQL injection vulnerability",
            sources=["request.args.get(...)"],
            sinks=["cursor.execute(...)"])
    """
    integration = SemgrepIntegration()

    if sources and sinks:
        return integration.create_taint_rule(
            rule_id, languages, message, sources, sinks, sanitizers
        )
    elif pattern:
        return integration.create_pattern_rule(
            rule_id, languages, message, pattern
        )
    else:
        raise ValueError("Must provide either pattern or sources/sinks")
