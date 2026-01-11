"""
Orchestrator Agent - Coordinates the entire audit process.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..core.llm import get_llm_client
from ..core.types import AuditState, Finding, Severity
from ..core.languages import Language, analyze_project
from .recon import ReconAgent
from .multi_language_recon import MultiLanguageReconAgent
from .hunters import (
    ReentrancyHunter,
    AccessControlHunter,
    OracleManipulationHunter,
    FlashLoanHunter,
)

console = Console()


class Orchestrator:
    """
    Master orchestrator that coordinates all agents in the audit.

    Phases:
    1. Reconnaissance - Map codebase, understand architecture
    2. Static Analysis - Run automated tools
    3. Deep Analysis - Run specialized vulnerability hunters
    4. Invariant Testing - Generate and test invariants
    5. Attack Synthesis - Combine findings into attack paths
    6. PoC Generation - Create working exploits
    7. Report Generation - Create final report
    """

    def __init__(
        self,
        target_path: Path,
        docs_path: Optional[Path] = None,
        verbose: bool = True,
        parallel_hunters: bool = True,
    ):
        self.target_path = target_path
        self.docs_path = docs_path
        self.verbose = verbose
        self.parallel_hunters = parallel_hunters

        # Initialize state
        self.state = AuditState(
            target_path=target_path,
            target_name=target_path.name,
        )

        # Detect project language
        try:
            project_info = analyze_project(target_path)
            self.language = project_info.language
            self.blockchain = project_info.blockchain
            self.framework = project_info.framework
        except ValueError:
            # Default to Solidity if detection fails
            self.language = Language.SOLIDITY
            self.blockchain = None
            self.framework = None

        # Load documentation if provided
        if docs_path and docs_path.exists():
            self.state.documentation = docs_path.read_text()

        # Initialize LLM client
        self.llm = get_llm_client()

    def log(self, message: str, style: str = "white") -> None:
        """Log a message."""
        if self.verbose:
            console.print(f"[{style}][Orchestrator][/{style}] {message}")
        self.state.add_log(f"[Orchestrator] {message}")

    async def run_phase_recon(self) -> None:
        """Phase 1: Reconnaissance."""
        self.log("Phase 1: Reconnaissance", style="bold magenta")
        self.log(f"Detected language: {self.language.value}")
        if self.blockchain:
            self.log(f"Blockchain: {self.blockchain.value}")
        if self.framework:
            self.log(f"Framework: {self.framework}")

        # Use multi-language recon agent
        if self.language != Language.SOLIDITY:
            agent = MultiLanguageReconAgent(state=self.state, verbose=self.verbose)
        else:
            agent = ReconAgent(state=self.state, verbose=self.verbose)

        await agent.run()

        if self.state.architecture:
            self.log(f"Architecture: {'DeFi' if self.state.architecture.is_defi else 'General'}")
            if self.state.architecture.external_protocols:
                self.log(f"External protocols: {', '.join(self.state.architecture.external_protocols)}")

    async def run_phase_static_analysis(self) -> None:
        """Phase 2: Static Analysis."""
        self.log("Phase 2: Static Analysis", style="bold magenta")

        from ..tools.slither import run_slither, filter_false_positives

        results, error = run_slither(self.target_path)

        if error:
            self.log(f"Slither error: {error}", style="red")
            return

        # Filter false positives
        filtered = filter_false_positives(results)
        self.state.slither_results = filtered

        self.log(f"Slither found {len(filtered)} issues after filtering")

        # Log by severity
        by_severity = {}
        for r in filtered:
            by_severity.setdefault(r.severity, []).append(r)

        for sev, items in by_severity.items():
            self.log(f"  {sev}: {len(items)}")

    async def run_phase_deep_analysis(self) -> None:
        """Phase 3: Deep Analysis with specialized hunters."""
        self.log("Phase 3: Deep Analysis (Vulnerability Hunting)", style="bold magenta")

        # Build list of hunters based on detected language and protocol type
        hunters = []

        # Core hunters - run for all languages
        hunters.append(
            AccessControlHunter(
                state=self.state,
                verbose=self.verbose,
                language=self.language,
            )
        )

        # Reentrancy - relevant for Solidity and Cairo
        if self.language in [Language.SOLIDITY, Language.CAIRO]:
            hunters.append(
                ReentrancyHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

        # DeFi-specific hunters
        if self.state.architecture and self.state.architecture.is_defi:
            hunters.append(
                OracleManipulationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                FlashLoanHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

        self.log(f"Running {len(hunters)} hunters for {self.language.value}...")

        if self.parallel_hunters:
            # Run hunters in parallel
            tasks = [hunter.run() for hunter in hunters]
            await asyncio.gather(*tasks)
        else:
            # Run hunters sequentially
            for hunter in hunters:
                self.log(f"Running {hunter.name}...")
                await hunter.run()

        self.log(f"Deep analysis complete: {len(self.state.findings)} total findings")

    async def run_phase_invariant_testing(self) -> None:
        """Phase 4: Invariant Testing."""
        self.log("Phase 4: Invariant Testing", style="bold magenta")
        # TODO: Implement InvariantAgent
        self.log("(Invariant testing not yet implemented)")

    async def run_phase_attack_synthesis(self) -> None:
        """Phase 5: Attack Synthesis."""
        self.log("Phase 5: Attack Synthesis", style="bold magenta")
        # TODO: Implement AttackAgent
        self.log("(Attack synthesis not yet implemented)")

    async def run_phase_poc_generation(self) -> None:
        """Phase 6: PoC Generation."""
        self.log("Phase 6: PoC Generation", style="bold magenta")
        # TODO: Implement PoCAgent
        self.log("(PoC generation not yet implemented)")

    async def run_phase_reporting(self) -> None:
        """Phase 7: Report Generation."""
        self.log("Phase 7: Report Generation", style="bold magenta")

        self.state.end_time = datetime.now()

        # Print summary
        self.print_summary()

        # Generate report
        report = self.generate_report()

        # Save report
        report_path = self.target_path / "sentinel_report.md"
        report_path.write_text(report)
        self.log(f"Report saved to: {report_path}", style="bold green")

    def print_summary(self) -> None:
        """Print a summary of findings."""
        console.print()
        console.print(Panel("[bold]Audit Summary[/bold]", expand=False))

        # Findings table
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Validated", justify="right")

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

        for sev in severity_order:
            findings = self.state.get_findings_by_severity(sev)
            validated = len([f for f in findings if f.validated])
            color = {
                Severity.CRITICAL: "red bold",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFORMATIONAL: "dim",
            }.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.value}[/{color}]",
                str(len(findings)),
                str(validated),
            )

        console.print(table)

        # Stats
        duration = (self.state.end_time - self.state.start_time).total_seconds() if self.state.end_time else 0
        console.print(f"\nDuration: {duration:.1f}s")
        console.print(f"API Cost: ${self.llm.total_cost:.4f}")
        console.print(f"Contracts Analyzed: {len(self.state.contracts)}")

    def generate_report(self) -> str:
        """Generate the final markdown report."""
        lines = [
            f"# Security Audit Report: {self.state.target_name}",
            "",
            f"**Generated by Sentinel**",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
        ]

        # Count findings
        critical = len(self.state.get_findings_by_severity(Severity.CRITICAL))
        high = len(self.state.get_findings_by_severity(Severity.HIGH))
        medium = len(self.state.get_findings_by_severity(Severity.MEDIUM))
        low = len(self.state.get_findings_by_severity(Severity.LOW))

        lines.append(f"This audit identified **{critical} Critical**, **{high} High**, "
                    f"**{medium} Medium**, and **{low} Low** severity issues.")
        lines.append("")

        # Architecture overview
        if self.state.architecture:
            lines.extend([
                "## Architecture Overview",
                "",
            ])
            arch = self.state.architecture
            if arch.is_defi:
                lines.append(f"- **Type:** DeFi Protocol ({', '.join(arch.defi_type)})")
            if arch.is_upgradeable:
                lines.append(f"- **Upgradeable:** Yes ({arch.proxy_type})")
            if arch.uses_oracles:
                lines.append(f"- **Oracles:** {', '.join(arch.oracle_type)}")
            if arch.external_protocols:
                lines.append(f"- **External Integrations:** {', '.join(arch.external_protocols)}")
            lines.append("")

        # Findings
        lines.extend([
            "## Findings",
            "",
        ])

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = self.state.get_findings_by_severity(severity)
            if not findings:
                continue

            lines.append(f"### {severity.value} Severity")
            lines.append("")

            for i, finding in enumerate(findings, 1):
                lines.extend([
                    f"#### [{finding.id}] {finding.title}",
                    "",
                    f"**Contract:** `{finding.contract}`" + (f" | **Function:** `{finding.function}`" if finding.function else ""),
                    "",
                    f"**Description:**",
                    finding.description,
                    "",
                ])

                if finding.impact:
                    lines.extend([
                        f"**Impact:**",
                        finding.impact,
                        "",
                    ])

                if finding.recommendation:
                    lines.extend([
                        f"**Recommendation:**",
                        finding.recommendation,
                        "",
                    ])

                if finding.poc and finding.poc.code:
                    lines.extend([
                        f"**Proof of Concept:**",
                        "```solidity",
                        finding.poc.code,
                        "```",
                        "",
                    ])

                lines.append("---")
                lines.append("")

        # Slither results summary
        if self.state.slither_results:
            lines.extend([
                "## Automated Analysis (Slither)",
                "",
                "| Detector | Severity | Contract |",
                "|----------|----------|----------|",
            ])
            for r in self.state.slither_results[:20]:
                lines.append(f"| {r.detector} | {r.severity} | {r.contract} |")
            lines.append("")

        # Footer
        lines.extend([
            "---",
            "",
            "*This report was generated by Sentinel, an AI-powered smart contract auditor.*",
            "*Always verify findings manually before acting on them.*",
        ])

        return "\n".join(lines)

    async def run(self) -> AuditState:
        """
        Execute the full audit pipeline.

        Returns:
            Final audit state with all findings
        """
        console.print(Panel(
            f"[bold]Sentinel Security Audit[/bold]\n\nTarget: {self.target_path}",
            expand=False
        ))

        try:
            # Phase 1: Recon
            await self.run_phase_recon()

            # Phase 2: Static Analysis
            await self.run_phase_static_analysis()

            # Phase 3: Deep Analysis
            await self.run_phase_deep_analysis()

            # Phase 4: Invariant Testing
            await self.run_phase_invariant_testing()

            # Phase 5: Attack Synthesis
            await self.run_phase_attack_synthesis()

            # Phase 6: PoC Generation
            await self.run_phase_poc_generation()

            # Phase 7: Reporting
            await self.run_phase_reporting()

        except Exception as e:
            self.log(f"Audit failed: {e}", style="bold red")
            raise

        return self.state


async def run_audit(
    target_path: Path,
    docs_path: Optional[Path] = None,
    verbose: bool = True,
) -> AuditState:
    """
    Convenience function to run a full audit.

    Args:
        target_path: Path to the target codebase
        docs_path: Optional path to documentation
        verbose: Whether to print progress

    Returns:
        Audit state with findings
    """
    orchestrator = Orchestrator(
        target_path=target_path,
        docs_path=docs_path,
        verbose=verbose,
    )
    return await orchestrator.run()
