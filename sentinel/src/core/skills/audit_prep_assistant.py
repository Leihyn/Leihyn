"""
Audit Prep Assistant - Trail of Bits Skill

Prepare codebase for security review using Trail of Bits' checklist.
Runs static analysis, increases test coverage, generates documentation.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import subprocess


class PrepStatus(Enum):
    """Status of preparation item."""
    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_STARTED = "not_started"
    BLOCKED = "blocked"


@dataclass
class PrepItem:
    """A preparation checklist item."""
    name: str
    description: str
    status: PrepStatus
    details: str = ""
    blockers: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        status_emoji = {
            PrepStatus.COMPLETE: "[x]",
            PrepStatus.PARTIAL: "[-]",
            PrepStatus.NOT_STARTED: "[ ]",
            PrepStatus.BLOCKED: "[!]",
        }
        line = f"- {status_emoji[self.status]} **{self.name}**: {self.description}"
        if self.details:
            line += f"\n  - {self.details}"
        if self.blockers:
            line += f"\n  - Blockers: {', '.join(self.blockers)}"
        return line


@dataclass
class PrepChecklist:
    """Complete audit preparation checklist."""
    project_name: str
    items: list[PrepItem]

    @property
    def completion_percentage(self) -> float:
        if not self.items:
            return 0.0
        complete = len([i for i in self.items if i.status == PrepStatus.COMPLETE])
        return (complete / len(self.items)) * 100

    def to_markdown(self) -> str:
        lines = [
            f"# Audit Preparation Checklist: {self.project_name}",
            "",
            f"**Completion**: {self.completion_percentage:.0f}%",
            "",
            "## Step 1: Set Review Goals",
            "",
        ]

        # Group items by step
        step1 = [i for i in self.items if "goal" in i.name.lower()]
        step2 = [i for i in self.items if "static" in i.name.lower() or "test" in i.name.lower() or "dead" in i.name.lower()]
        step3 = [i for i in self.items if "build" in i.name.lower() or "scope" in i.name.lower() or "freeze" in i.name.lower()]
        step4 = [i for i in self.items if "doc" in i.name.lower() or "diagram" in i.name.lower()]

        for item in step1 or [PrepItem("Review Goals", "Document security objectives", PrepStatus.NOT_STARTED)]:
            lines.append(item.to_markdown())

        lines.append("")
        lines.append("## Step 2: Resolve Easy Issues")
        lines.append("")

        for item in step2:
            lines.append(item.to_markdown())

        lines.append("")
        lines.append("## Step 3: Ensure Code Accessibility")
        lines.append("")

        for item in step3:
            lines.append(item.to_markdown())

        lines.append("")
        lines.append("## Step 4: Generate Documentation")
        lines.append("")

        for item in step4:
            lines.append(item.to_markdown())

        return "\n".join(lines)


@dataclass
class AuditPrepReport:
    """Complete audit preparation report."""
    project_name: str
    checklist: PrepChecklist
    static_analysis_results: dict
    test_coverage: Optional[float]
    dead_code_findings: list[str]
    documentation_status: dict
    build_instructions: str

    def to_markdown(self) -> str:
        lines = [
            f"# Audit Prep Package: {self.project_name}",
            "",
            "## Preparation Status",
            "",
            self.checklist.to_markdown(),
            "",
            "## Static Analysis Summary",
            "",
        ]

        if self.static_analysis_results:
            for tool, results in self.static_analysis_results.items():
                lines.append(f"### {tool}")
                lines.append(f"- High: {results.get('high', 0)}")
                lines.append(f"- Medium: {results.get('medium', 0)}")
                lines.append(f"- Low: {results.get('low', 0)}")
                lines.append("")

        lines.append("## Test Coverage")
        lines.append("")
        if self.test_coverage:
            lines.append(f"**Overall Coverage**: {self.test_coverage:.1f}%")
        else:
            lines.append("Coverage not measured")

        lines.append("")
        lines.append("## Build Instructions")
        lines.append("")
        lines.append("```bash")
        lines.append(self.build_instructions)
        lines.append("```")

        return "\n".join(lines)


class AuditPrepAssistant:
    """
    Prepare codebase for security audit.

    The Preparation Process:
    1. Set Review Goals - Security objectives, concerns, worst-case scenarios
    2. Resolve Easy Issues - Static analysis, test coverage, dead code
    3. Ensure Accessibility - Build instructions, scope, frozen version
    4. Generate Documentation - Diagrams, user stories, glossary
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def run_static_analysis(self) -> dict:
        """Run static analysis tools."""
        results = {}

        # Try Slither for Solidity
        if list(self.project_path.glob("**/*.sol")):
            try:
                result = subprocess.run(
                    ["slither", str(self.project_path), "--json", "-"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout) if result.stdout else {}
                    findings = data.get("results", {}).get("detectors", [])
                    results["slither"] = {
                        "high": len([f for f in findings if f.get("impact") == "High"]),
                        "medium": len([f for f in findings if f.get("impact") == "Medium"]),
                        "low": len([f for f in findings if f.get("impact") == "Low"]),
                    }
            except Exception:
                results["slither"] = {"error": "Failed to run"}

        return results

    def check_test_coverage(self) -> Optional[float]:
        """Check test coverage."""
        # Try Foundry
        try:
            result = subprocess.run(
                ["forge", "coverage", "--report", "summary"],
                cwd=str(self.project_path),
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode == 0:
                # Parse coverage from output
                import re
                match = re.search(r'(\d+\.?\d*)%', result.stdout)
                if match:
                    return float(match.group(1))
        except Exception:
            pass

        return None

    def find_dead_code(self) -> list[str]:
        """Find unused code."""
        dead_code = []

        # Check for unused imports/functions (simplified)
        for sol_file in self.project_path.glob("**/*.sol"):
            content = sol_file.read_text()

            # Find function definitions
            import re
            functions = re.findall(r'function\s+(\w+)', content)

            # Check if they're called (very simplified)
            for func in functions:
                if func.startswith("_"):  # Internal functions
                    if content.count(func) == 1:  # Only the definition
                        dead_code.append(f"{sol_file.name}: unused function {func}")

        return dead_code

    def generate_build_instructions(self) -> str:
        """Generate build instructions."""
        lines = ["# Prerequisites"]

        # Detect build system
        if (self.project_path / "foundry.toml").exists():
            lines.extend([
                "- Foundry",
                "",
                "# Setup",
                "git clone <repo>",
                "cd <repo>",
                "forge install",
                "forge build",
                "forge test",
            ])
        elif (self.project_path / "hardhat.config.js").exists() or (self.project_path / "hardhat.config.ts").exists():
            lines.extend([
                "- Node.js 18+",
                "- npm or yarn",
                "",
                "# Setup",
                "git clone <repo>",
                "cd <repo>",
                "npm install",
                "npx hardhat compile",
                "npx hardhat test",
            ])
        else:
            lines.extend([
                "# Manual setup required",
                "# Please document build steps",
            ])

        return "\n".join(lines)

    def check_documentation(self) -> dict:
        """Check documentation status."""
        docs = {
            "readme": (self.project_path / "README.md").exists(),
            "architecture": any(self.project_path.glob("**/*architecture*")),
            "natspec": False,
        }

        # Check for NatSpec
        for sol_file in self.project_path.glob("**/*.sol"):
            content = sol_file.read_text()
            if "@notice" in content or "@dev" in content:
                docs["natspec"] = True
                break

        return docs

    def prepare(self) -> AuditPrepReport:
        """Run full preparation check."""
        items = []

        # Step 1: Review Goals
        items.append(PrepItem(
            name="Review Goals Document",
            description="Document security objectives and concerns",
            status=PrepStatus.NOT_STARTED,
        ))

        # Step 2: Static Analysis
        static_results = self.run_static_analysis()
        if static_results:
            high_count = sum(r.get("high", 0) for r in static_results.values() if isinstance(r, dict))
            if high_count == 0:
                status = PrepStatus.COMPLETE
            else:
                status = PrepStatus.PARTIAL
            items.append(PrepItem(
                name="Static Analysis",
                description="Run and triage Slither/other tools",
                status=status,
                details=f"{high_count} high severity findings",
            ))
        else:
            items.append(PrepItem(
                name="Static Analysis",
                description="Run and triage Slither/other tools",
                status=PrepStatus.NOT_STARTED,
            ))

        # Test Coverage
        coverage = self.check_test_coverage()
        if coverage:
            status = PrepStatus.COMPLETE if coverage >= 80 else PrepStatus.PARTIAL
            items.append(PrepItem(
                name="Test Coverage",
                description="Achieve >80% test coverage",
                status=status,
                details=f"Current: {coverage:.1f}%",
            ))
        else:
            items.append(PrepItem(
                name="Test Coverage",
                description="Achieve >80% test coverage",
                status=PrepStatus.NOT_STARTED,
            ))

        # Dead Code
        dead_code = self.find_dead_code()
        items.append(PrepItem(
            name="Dead Code Removal",
            description="Remove unused code",
            status=PrepStatus.COMPLETE if not dead_code else PrepStatus.PARTIAL,
            details=f"{len(dead_code)} potentially unused items found",
        ))

        # Step 3: Accessibility
        build_instructions = self.generate_build_instructions()
        items.append(PrepItem(
            name="Build Instructions",
            description="Verified build steps",
            status=PrepStatus.PARTIAL,
        ))

        items.append(PrepItem(
            name="Scope Definition",
            description="List of in-scope files",
            status=PrepStatus.NOT_STARTED,
        ))

        items.append(PrepItem(
            name="Frozen Version",
            description="Stable commit/branch for review",
            status=PrepStatus.NOT_STARTED,
        ))

        # Step 4: Documentation
        docs = self.check_documentation()
        items.append(PrepItem(
            name="Documentation",
            description="README, architecture, NatSpec",
            status=PrepStatus.COMPLETE if all(docs.values()) else PrepStatus.PARTIAL,
            details=f"README: {'Yes' if docs['readme'] else 'No'}, NatSpec: {'Yes' if docs['natspec'] else 'No'}",
        ))

        items.append(PrepItem(
            name="Diagrams",
            description="Flowcharts and sequence diagrams",
            status=PrepStatus.NOT_STARTED,
        ))

        checklist = PrepChecklist(
            project_name=self.project_path.name,
            items=items,
        )

        return AuditPrepReport(
            project_name=self.project_path.name,
            checklist=checklist,
            static_analysis_results=static_results,
            test_coverage=coverage,
            dead_code_findings=dead_code,
            documentation_status=docs,
            build_instructions=build_instructions,
        )


def prepare_for_audit(
    project_path: str,
    output_path: Optional[str] = None,
) -> AuditPrepReport:
    """
    Prepare project for security audit.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        AuditPrepReport with checklist and findings
    """
    assistant = AuditPrepAssistant(project_path)
    report = assistant.prepare()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
