"""
Orchestrator Agent - Coordinates the entire audit process.
"""

import asyncio
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..core.llm import get_llm_client
from ..core.types import (
    AgentRole,
    AuditState,
    ContractDependencyGraph,
    CrossContractCall,
    CrossContractFlow,
    Finding,
    PoC,
    Severity,
    VulnerabilityType,
)
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
    1.   Reconnaissance - Map codebase, understand architecture
    2.   Static Analysis - Run automated tools
    2.5  Cross-Contract Analysis - Build dependency graph + critical flows
    3.   Deep Analysis - Run specialized vulnerability hunters (HunterSwarm)
    3.5  Validation - Devil's Advocate challenges findings
    5.   Attack Synthesis - Combine findings into attack paths
    6.   PoC Generation - Create working exploits
    7.   Report Generation - Create final report
    """

    def __init__(
        self,
        target_path: Path,
        docs_path: Optional[Path] = None,
        verbose: bool = True,
        parallel_hunters: bool = True,
        depth: str = "standard",
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
    ):
        self.target_path = target_path
        self.docs_path = docs_path
        self.verbose = verbose
        self.parallel_hunters = parallel_hunters
        self.depth = depth
        self.fork_url = fork_url
        self.fork_block = fork_block

        # Initialize state
        self.state = AuditState(
            target_path=target_path,
            target_name=target_path.name,
            depth=depth,
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

    async def run_phase_cross_contract_analysis(self) -> None:
        """Phase 2.5: Cross-Contract Analysis - build dependency graph."""
        self.log("Phase 2.5: Cross-Contract Analysis", style="bold magenta")

        if not self.state.contracts:
            self.log("No contracts to analyze for cross-contract dependencies")
            return

        graph = ContractDependencyGraph()
        graph.nodes = [c.name for c in self.state.contracts]

        # Build edges from external calls detected during recon
        for contract in self.state.contracts:
            for func in contract.functions:
                for call in func.external_calls:
                    graph.edges.append(CrossContractCall(
                        source_contract=contract.name,
                        source_function=func.name,
                        target_contract=call.target,
                        target_function=call.function,
                        line_number=call.line_number,
                    ))

        # Scan for interface calls via regex (catches calls not in AST)
        contract_names = {c.name for c in self.state.contracts}
        for contract in self.state.contracts:
            # Match patterns like: ISomeContract(addr).func() or someContract.func()
            interface_calls = re.findall(
                r"(\w+)\s*\([^)]*\)\s*\.\s*(\w+)\s*\(",
                contract.source,
            )
            for target, func_name in interface_calls:
                # Strip I prefix for interface pattern matching
                bare_target = target[1:] if target.startswith("I") and len(target) > 1 else target
                if bare_target in contract_names or target in contract_names:
                    actual_target = bare_target if bare_target in contract_names else target
                    graph.edges.append(CrossContractCall(
                        source_contract=contract.name,
                        source_function="(regex-detected)",
                        target_contract=actual_target,
                        target_function=func_name,
                    ))

        # Identify critical flows
        flow_patterns = {
            "oracle->consumer": ["oracle", "price", "twap", "getPrice", "latestRoundData"],
            "balance->pricing": ["balanceOf", "totalSupply", "getReserves", "reserve"],
            "auth->proxy": ["owner", "admin", "authority", "upgrade", "implementation"],
        }

        for flow_type, keywords in flow_patterns.items():
            involved_contracts = set()
            relevant_calls = []

            for edge in graph.edges:
                if any(kw.lower() in edge.target_function.lower() for kw in keywords):
                    involved_contracts.add(edge.source_contract)
                    involved_contracts.add(edge.target_contract)
                    relevant_calls.append(edge)

            if len(involved_contracts) >= 2:
                graph.critical_flows.append(CrossContractFlow(
                    flow_type=flow_type,
                    description=f"Data flows across {', '.join(involved_contracts)} via {flow_type.split('->')[0]}",
                    contracts_involved=list(involved_contracts),
                    calls=relevant_calls,
                    risk_level="high" if "oracle" in flow_type else "medium",
                ))

        self.state.dependency_graph = graph
        self.log(f"Dependency graph: {len(graph.nodes)} contracts, {len(graph.edges)} edges, {len(graph.critical_flows)} critical flows")

    async def run_phase_deep_analysis(self) -> None:
        """Phase 3: Deep Analysis with specialized hunters via HunterSwarm."""
        self.log("Phase 3: Deep Analysis (Vulnerability Hunting)", style="bold magenta")

        # Build list of hunters based on depth, language, and architecture
        hunters = []

        # --- Fast depth: highest-signal hunters only ---
        # SlippageHunter and ParameterValidationHunter produce the most findings per API dollar.
        # At fast depth, we skip low-yield hunters (reentrancy, flash loan, oracle pattern matching)
        # and rely on these two plus AccessControl for broad coverage.
        if self.depth == "fast":
            from .hunters.slippage import SlippageHunter
            from .hunters.parameter_validation import ParameterValidationHunter

            hunters.append(
                SlippageHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                ParameterValidationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                AccessControlHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

        # --- Standard: core + standard hunters ---
        elif self.depth == "standard":
            from .hunters.slippage import SlippageHunter
            from .hunters.math_verification import MathVerificationHunter
            from .hunters.parameter_validation import ParameterValidationHunter

            hunters.append(
                AccessControlHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

            if self.language in [Language.SOLIDITY, Language.CAIRO]:
                hunters.append(
                    ReentrancyHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            if self.state.architecture and self.state.architecture.is_defi:
                hunters.append(
                    OracleManipulationHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            hunters.append(
                SlippageHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                MathVerificationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                ParameterValidationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

        # --- Deep: all hunters including algebraic verification ---
        else:  # depth == "deep"
            from .hunters.slippage import SlippageHunter
            from .hunters.math_verification import MathVerificationHunter
            from .hunters.parameter_validation import ParameterValidationHunter

            hunters.append(
                AccessControlHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

            if self.language in [Language.SOLIDITY, Language.CAIRO]:
                hunters.append(
                    ReentrancyHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

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

            hunters.append(
                SlippageHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                MathVerificationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )
            hunters.append(
                ParameterValidationHunter(
                    state=self.state,
                    verbose=self.verbose,
                    language=self.language,
                )
            )

            # AlgebraicVerificationHunter - catches tautologies, identities, and
            # mathematical simplifications that negate security checks (e.g., TWAP = spot)
            try:
                from .hunters.algebraic_verification import AlgebraicVerificationHunter
                hunters.append(
                    AlgebraicVerificationHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )
            except ImportError:
                self.log("AlgebraicVerificationHunter not available", style="yellow")

        # --- Deep-only: DeepHunter and InvariantAgent ---
        if self.depth == "deep":
            try:
                from .deep_hunter import DeepHunterAgent, DeepAnalysisConfig
                from .invariant_agent import InvariantAgent, InvariantConfig

                hunters.append(
                    DeepHunterAgent(
                        state=self.state,
                        config=DeepAnalysisConfig(ultrathink=True, thinking_budget=24000),
                        llm_client=self.llm,
                        verbose=self.verbose,
                    )
                )
                hunters.append(
                    InvariantAgent(
                        state=self.state,
                        config=InvariantConfig(ultrathink=True, thinking_budget=20000),
                        llm_client=self.llm,
                        verbose=self.verbose,
                    )
                )
            except Exception as e:
                self.log(f"Could not load deep hunters: {e}", style="yellow")

            # Protocol-specific hunters based on recon
            if self.state.architecture and self.state.architecture.external_protocols:
                try:
                    from .protocol_hunters import AaveV3Hunter, UniswapV3Hunter, CurveHunter

                    protocols = [p.lower() for p in self.state.architecture.external_protocols]
                    if any("aave" in p for p in protocols):
                        hunters.append(AaveV3Hunter(state=self.state, llm_client=self.llm, verbose=self.verbose))
                    if any("uniswap" in p for p in protocols):
                        hunters.append(UniswapV3Hunter(state=self.state, llm_client=self.llm, verbose=self.verbose))
                    if any("curve" in p or "balancer" in p for p in protocols):
                        hunters.append(CurveHunter(state=self.state, llm_client=self.llm, verbose=self.verbose))
                except Exception as e:
                    self.log(f"Could not load protocol hunters: {e}", style="yellow")

        self.log(f"Running {len(hunters)} hunters for {self.language.value} (depth={self.depth})...")

        if self.parallel_hunters:
            # Semaphore(1) = sequential execution with asyncio.gather error handling.
            # Most Anthropic API tiers have 30-80k input tokens/min -- even 2 concurrent
            # hunters with large contract contexts will cascade into 429 retries.
            # Sequential execution is slower but reliable.
            semaphore = asyncio.Semaphore(1)

            async def rate_limited_run(hunter):
                async with semaphore:
                    return await hunter.run()

            tasks = [rate_limited_run(hunter) for hunter in hunters]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for hunter, result in zip(hunters, results):
                if isinstance(result, Exception):
                    self.log(f"{hunter.name} failed: {result}", style="red")
        else:
            for hunter in hunters:
                self.log(f"Running {hunter.name}...")
                try:
                    await hunter.run()
                except Exception as e:
                    self.log(f"{hunter.name} failed: {e}", style="red")

        self.log(f"Deep analysis complete: {len(self.state.findings)} total findings")

    def _deduplicate_findings(self) -> None:
        """Merge findings with the same root cause into a single consolidated finding.

        SLIPPAGE-001 through SLIPPAGE-004 (same vuln type, same root cause pattern)
        become one finding with all affected locations listed. This saves 4x on
        DevilsAdvocate/PoC API calls.
        """
        if not self.state.findings:
            return

        from collections import defaultdict

        # Group by vulnerability_type + first 50 chars of recommendation (proxy for root cause)
        groups = defaultdict(list)
        for f in self.state.findings:
            # Key: same vuln type + similar recommendation = same root cause
            rec_key = f.recommendation[:50] if f.recommendation else ""
            key = (f.vulnerability_type.value, rec_key)
            groups[key].append(f)

        deduped = []
        for key, group in groups.items():
            if len(group) == 1:
                deduped.append(group[0])
                continue

            # Merge group into one finding
            primary = group[0]
            other_contracts = [f.contract for f in group[1:]]
            other_ids = [f.id for f in group[1:]]

            # Consolidate: keep primary, append other locations
            primary.description += "\n\n**Also affects:** " + ", ".join(
                f"{f.contract}:{f.function or 'N/A'}" for f in group[1:]
            )
            primary.related_findings.extend(other_ids)
            # Take highest severity and confidence from the group
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
            primary.severity = min((f.severity for f in group), key=lambda s: severity_order.index(s))
            primary.confidence = max(f.confidence for f in group)

            deduped.append(primary)
            self.log(f"  Deduped {len(group)} findings -> {primary.id} ({primary.title[:50]}...)")

        before = len(self.state.findings)
        self.state.findings = deduped
        after = len(self.state.findings)
        if before != after:
            self.log(f"Deduplication: {before} -> {after} findings ({before - after} merged)")

    def _save_checkpoint(self, phase: str) -> Path:
        """Save state checkpoint after a phase completes."""
        checkpoint_path = self.target_path / f"sentinel_checkpoint_{phase}.json"
        self.state.save_checkpoint(checkpoint_path)
        self.log(f"Checkpoint saved: {checkpoint_path}", style="dim")
        return checkpoint_path

    async def run_phase_validation(self) -> None:
        """Phase 3.5: Devil's Advocate - challenge and validate findings."""
        self.log("Phase 3.5: Finding Validation (Devil's Advocate)", style="bold magenta")

        if not self.state.findings:
            self.log("No findings to validate")
            return

        try:
            from .devils_advocate import DevilsAdvocateAgent, DevilsAdvocateConfig

            config = DevilsAdvocateConfig(
                ultrathink=True,
                thinking_budget=16000,
                strict_mode=False,
                filter_low_confidence=True,
            )
            advocate = DevilsAdvocateAgent(
                state=self.state,
                config=config,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            pre_count = len(self.state.findings)
            validated = await advocate.run(findings=self.state.findings)
            self.state.findings = validated
            post_count = len(self.state.findings)

            filtered = pre_count - post_count
            self.log(f"Validated {post_count}/{pre_count} findings ({filtered} filtered as false positives)")

        except Exception as e:
            self.log(f"Validation failed: {e}", style="red")
            self.log("Keeping all findings unvalidated")

    async def run_phase_attack_synthesis(self) -> None:
        """Phase 5: Attack Synthesis - combine findings into attack chains."""
        self.log("Phase 5: Attack Synthesis", style="bold magenta")

        if len(self.state.findings) < 2:
            self.log("Not enough findings to synthesize attack chains")
            return

        try:
            from .attack_synthesizer import AttackSynthesizerAgent, AttackSynthesisConfig

            config = AttackSynthesisConfig(
                ultrathink=True,
                thinking_budget=24000,
                consider_flash_loans=True,
                consider_mev=True,
            )
            synthesizer = AttackSynthesizerAgent(
                state=self.state,
                config=config,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            chains = await synthesizer.run(findings=self.state.findings)
            if chains:
                self.log(f"Synthesized {len(chains)} attack chains")
                # Add chain findings to state
                for chain in chains:
                    chain_finding = Finding(
                        id=f"CHAIN-{chain.id}",
                        title=f"Attack Chain: {chain.name}",
                        severity=chain.severity,
                        vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                        description=chain.description + "\n\n**Attack Steps:**\n" + "\n".join(f"{i+1}. {step}" for i, step in enumerate(chain.attack_steps)),
                        contract=", ".join({n.contract for n in chain.nodes}),
                        impact=f"Max extractable value: ${chain.max_extractable_value:,.0f}" if chain.max_extractable_value else "",
                        root_cause=getattr(chain, "poc_concept", "") or "",
                        recommendation="See individual findings for specific fixes.",
                        confidence=chain.feasibility,
                        found_by=AgentRole.ATTACKER,
                        related_findings=chain.findings_used,
                    )
                    self.state.add_finding(chain_finding)
            else:
                self.log("No attack chains found")

        except Exception as e:
            self.log(f"Attack synthesis failed: {e}", style="red")

    # Vulnerability types that are observational (not exploitable with a PoC)
    OBSERVATION_TYPES = {
        VulnerabilityType.CENTRALIZATION,
        VulnerabilityType.SINGLE_POINT_FAILURE,
        VulnerabilityType.MISSING_TIMELOCK,
        VulnerabilityType.GAS_OPTIMIZATION,
    }

    # Severities eligible for PoC generation
    POC_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}

    def _get_poc_eligible_findings(self) -> list[Finding]:
        """Filter findings eligible for PoC generation."""
        return [
            f for f in self.state.findings
            if f.severity in self.POC_SEVERITIES
            and f.vulnerability_type not in self.OBSERVATION_TYPES
        ]

    def _apply_poc_results(self, poc_results: list, findings_map: dict[str, Finding]) -> None:
        """Apply PoC results back to findings."""
        from .poc_generator import PoCGeneratorAgent

        for poc in poc_results:
            finding = findings_map.get(poc.finding_id)
            if not finding:
                continue

            core_poc = PoCGeneratorAgent._to_core_poc(poc)

            if poc.verified:
                finding.validated = True
                finding.poc = core_poc
                self.state.pocs.append(core_poc)
                self.log(f"  [VERIFIED] {finding.id}: {finding.title}", style="bold green")
            else:
                finding.validated = False
                finding.confidence = finding.confidence * 0.5
                self.log(f"  [UNVERIFIED] {finding.id}: PoC failed, confidence halved to {finding.confidence:.2f}", style="yellow")

    async def run_phase_poc_generation(self) -> None:
        """Phase 6: PoC Generation - create and verify exploits for findings."""
        self.log("Phase 6: PoC Generation", style="bold magenta")

        eligible = self._get_poc_eligible_findings()
        if not eligible:
            self.log("No findings eligible for PoC generation")
            return

        self.log(f"{len(eligible)} findings eligible for PoC generation")

        if not self.fork_url:
            self.log("WARNING: No --fork-url provided. PoC code will be generated but not executed.", style="yellow")

        try:
            from .poc_generator import PoCGeneratorAgent, PoCConfig

            config = PoCConfig(
                fork_url=self.fork_url,
                fork_block=self.fork_block,
                output_dir=self.target_path / "sentinel_pocs" if self.fork_url else None,
                run_tests=bool(self.fork_url),
                ultrathink=True,
            )

            poc_agent = PoCGeneratorAgent(
                state=self.state,
                config=config,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            findings_map = {f.id: f for f in eligible}
            poc_results = await poc_agent.run(findings=eligible)

            self._apply_poc_results(poc_results, findings_map)

            # Mark findings with no PoC generated as unvalidated
            for finding in eligible:
                if finding.poc is None and finding.validated is False:
                    self.log(f"  [NO POC] {finding.id}: No PoC generated", style="dim")

            verified = sum(1 for f in eligible if f.validated)
            self.log(f"PoC results: {verified}/{len(eligible)} verified", style="bold")

        except Exception as e:
            self.log(f"PoC generation failed: {e}", style="red")
            self.log("All findings remain unverified")

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
        console.print(f"Depth: {self.depth}")

    def _write_finding_to_report(self, lines: list[str], finding: Finding, include_poc: bool = False) -> None:
        """Write a single finding to the report lines."""
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

        if include_poc and finding.poc and finding.poc.code:
            lines.extend([
                f"**Proof of Concept:**",
                "```solidity",
                finding.poc.code,
                "```",
                "",
            ])
            if finding.poc.output:
                lines.extend([
                    f"**PoC Output:**",
                    "```",
                    finding.poc.output[:2000],
                    "```",
                    "",
                ])

        lines.append("---")
        lines.append("")

    def generate_report(self) -> str:
        """Generate the final markdown report."""
        lines = [
            f"# Security Audit Report: {self.state.target_name}",
            "",
            f"**Generated by Sentinel**",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Depth:** {self.depth}",
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

        # Cross-contract analysis
        if self.state.dependency_graph and self.state.dependency_graph.critical_flows:
            lines.extend([
                "## Cross-Contract Data Flows",
                "",
            ])
            for flow in self.state.dependency_graph.critical_flows:
                lines.append(f"- **{flow.flow_type}** [{flow.risk_level.upper()}]: {flow.description}")
            lines.append("")

        # Categorize findings
        verified = [f for f in self.state.findings if f.validated and f.poc]
        unverified_exploitable = [
            f for f in self.state.findings
            if not f.validated
            and f.severity in self.POC_SEVERITIES
            and f.vulnerability_type not in self.OBSERVATION_TYPES
        ]
        observations = [
            f for f in self.state.findings
            if f.vulnerability_type in self.OBSERVATION_TYPES
        ]
        low_info = [
            f for f in self.state.findings
            if f.severity in (Severity.LOW, Severity.INFORMATIONAL, Severity.GAS)
            and f.vulnerability_type not in self.OBSERVATION_TYPES
            and f not in verified and f not in unverified_exploitable
        ]

        # Verified Findings (with PoC)
        if verified:
            lines.extend([
                "## Verified Findings (with Proof of Concept)",
                "",
            ])

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                sev_findings = [f for f in verified if f.severity == severity]
                if not sev_findings:
                    continue

                lines.append(f"### {severity.value} Severity")
                lines.append("")

                for finding in sev_findings:
                    self._write_finding_to_report(lines, finding, include_poc=True)

        # Unverified Findings
        if unverified_exploitable:
            lines.extend([
                "## Unverified Findings (Manual Review Recommended)",
                "",
                "> These findings were identified by analysis but could not be verified with a working PoC.",
                "> Manual review is recommended before acting on them.",
                "",
            ])

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                sev_findings = [f for f in unverified_exploitable if f.severity == severity]
                if not sev_findings:
                    continue

                lines.append(f"### {severity.value} Severity")
                lines.append("")

                for finding in sev_findings:
                    self._write_finding_to_report(lines, finding, include_poc=False)

        # Low/Informational
        if low_info:
            lines.extend([
                "## Low / Informational",
                "",
            ])
            for finding in low_info:
                self._write_finding_to_report(lines, finding, include_poc=False)

        # Design Observations
        if observations:
            lines.extend([
                "## Design Observations",
                "",
                "> These are architectural or design observations, not directly exploitable.",
                "",
            ])
            for finding in observations:
                self._write_finding_to_report(lines, finding, include_poc=False)

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

    async def run(self, resume_from: Optional[str] = None) -> AuditState:
        """
        Execute the full audit pipeline.

        Args:
            resume_from: Path to a checkpoint JSON to resume from.
                         Skips Phases 1-3 and goes straight to validation/PoC.

        Returns:
            Final audit state with all findings
        """
        console.print(Panel(
            f"[bold]Sentinel Security Audit[/bold]\n\nTarget: {self.target_path}\nDepth: {self.depth}"
            + (f"\nResuming from checkpoint" if resume_from else ""),
            expand=False
        ))

        # Credit exhaustion error string to catch
        CREDIT_ERROR = "credit balance is too low"

        try:
            if resume_from:
                # Resume mode: load state from checkpoint, skip expensive phases
                from ..core.types import AuditState
                self.state = AuditState.load_checkpoint(Path(resume_from))
                self.log(f"Resumed from checkpoint: {len(self.state.findings)} findings loaded", style="bold green")
            else:
                # Phase 1: Recon
                await self.run_phase_recon()

                # Phase 2: Static Analysis
                await self.run_phase_static_analysis()

                # Phase 2.5: Cross-Contract Analysis (standard+)
                if self.depth in ("standard", "deep"):
                    await self.run_phase_cross_contract_analysis()

                # Phase 3: Deep Analysis (all hunters based on depth)
                await self.run_phase_deep_analysis()

                # Save checkpoint after hunters — this is the expensive part
                self._save_checkpoint("hunters")

            # Deduplicate before expensive LLM phases
            self._deduplicate_findings()

            # Phase 3.5: Validation (standard+)
            if self.depth in ("standard", "deep"):
                await self.run_phase_validation()

            # Phase 5: Attack Synthesis (deep only)
            if self.depth == "deep":
                await self.run_phase_attack_synthesis()

            # Phase 6: PoC Generation (standard+ depth, when findings exist)
            if self.depth in ("standard", "deep") and self.state.findings:
                await self.run_phase_poc_generation()

            # Phase 7: Reporting
            await self.run_phase_reporting()

        except Exception as e:
            error_msg = str(e)
            if CREDIT_ERROR in error_msg.lower():
                # Graceful credit exhaustion: save checkpoint + partial report
                self.log("Credit balance exhausted. Saving checkpoint and partial report...", style="bold yellow")
                checkpoint = self._save_checkpoint("partial")
                self.state.end_time = datetime.now()
                self.print_summary()
                report = self.generate_report()
                report_path = self.target_path / "sentinel_report.md"
                report_path.write_text(report)
                self.log(f"Partial report saved: {report_path}", style="yellow")
                self.log(f"Resume with: sentinel audit {self.target_path} --resume {checkpoint}", style="bold yellow")
                return self.state
            else:
                self.log(f"Audit failed: {e}", style="bold red")
                raise

        return self.state


async def run_audit(
    target_path: Path,
    docs_path: Optional[Path] = None,
    verbose: bool = True,
    depth: str = "standard",
    fork_url: Optional[str] = None,
    fork_block: Optional[int] = None,
    resume_from: Optional[str] = None,
) -> AuditState:
    """
    Convenience function to run a full audit.

    Args:
        target_path: Path to the target codebase
        docs_path: Optional path to documentation
        verbose: Whether to print progress
        depth: Audit depth - "fast", "standard", or "deep"
        fork_url: RPC URL for fork-based PoC execution
        fork_block: Block number for fork
        resume_from: Path to checkpoint JSON to resume from

    Returns:
        Audit state with findings
    """
    orchestrator = Orchestrator(
        target_path=target_path,
        docs_path=docs_path,
        verbose=verbose,
        depth=depth,
        fork_url=fork_url,
        fork_block=fork_block,
    )
    return await orchestrator.run(resume_from=resume_from)
