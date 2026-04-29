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
        include_pashov: bool = False,
        batched_hunters: bool = False,
        max_concurrent_hunters: int = 3,
        eval_mode: bool = False,
        audits_dir: Optional[Path] = None,
    ):
        self.target_path = target_path
        self.docs_path = docs_path
        self.verbose = verbose
        self.parallel_hunters = parallel_hunters
        self.depth = depth
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.include_pashov = include_pashov
        self.batched_hunters = batched_hunters
        self.max_concurrent_hunters = max(1, int(max_concurrent_hunters))
        self.audits_dir = audits_dir
        # eval_mode skips phases that are useful only for human-readable
        # output (test plan, C4 gate, PoC, report). The audit still produces
        # state.findings with full hunter attribution, which is all the
        # eval runner needs for recall scoring.
        self.eval_mode = bool(eval_mode)

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

    def _print_cost_status(self, phase_label: str = "") -> None:
        """Print current API spend. Called before/after expensive phases."""
        stats = self.llm.get_stats()
        cost = stats["total_cost"]
        input_t = stats["total_input_tokens"]
        output_t = stats["total_output_tokens"]
        thinking_t = stats["total_thinking_tokens"]
        cache_savings = stats["prompt_cache_savings"]

        label = f" (after {phase_label})" if phase_label else ""
        console.print(
            f"[bold cyan]  $ {cost:.4f} spent{label}[/bold cyan]"
            f"  [dim]| {input_t:,} in | {output_t:,} out | {thinking_t:,} think"
            f" | ${cache_savings:.4f} saved via cache[/dim]"
        )

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

    def run_phase_audit_intel(self) -> None:
        """Phase 1.5: Audit Intel — detect prior audit reports + bounty known issues.

        Zero API cost: just pdftotext + regex. Populates state.known_findings
        and state.priority_files; hunters dedupe via state.get_known_findings_prompt().
        """
        from ..core.audit_intel import (
            detect_audit_reports,
            extract_all_known_findings,
            detect_post_audit_changes,
            load_audit_intel,
        )

        self.log("Phase 1.5: Audit Intel", style="bold magenta")

        # Honor explicit --audits-dir if given, else auto-detect
        if self.audits_dir is not None:
            audit_dir = Path(self.audits_dir)
            if not audit_dir.exists():
                self.log(f"  --audits-dir not found: {audit_dir}", style="yellow")
                return
            reports = []
            for ext in ("*.pdf", "*.md", "*.markdown"):
                reports.extend(sorted(audit_dir.rglob(ext)))
            findings = extract_all_known_findings(reports)
            priority = detect_post_audit_changes(self.target_path, reports)
        else:
            audit_dir, findings, priority = load_audit_intel(self.target_path)

        self.state.audit_dir = audit_dir
        self.state.known_findings = findings
        self.state.priority_files = priority

        if audit_dir:
            self.log(f"  audit dir: {audit_dir}")
        if findings:
            self.log(
                f"  loaded {len(findings)} known findings from prior audits "
                f"(hunters will dedupe)",
                style="bold green",
            )
            # Show top 5 so the user sees what was loaded
            for kf in findings[:5]:
                sev = f"[{kf.severity}]" if kf.severity else ""
                self.log(f"    {kf.id} {sev} {kf.title[:80]}")
            if len(findings) > 5:
                self.log(f"    ... and {len(findings) - 5} more")
        else:
            self.log("  no prior audit reports detected")
        if priority:
            self.log(
                f"  {len(priority)} files changed since latest audit "
                f"(highest-EV targets)",
                style="bold green",
            )

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

    async def run_phase_test_plan(self) -> None:
        """Phase 2.6: Test Plan - generate testing-diagram.md and test-setup.md."""
        self.log("Phase 2.6: Test Plan Generation", style="bold magenta")

        if not self.state.contracts:
            self.log("No contracts to generate test plan for")
            return

        try:
            from .test_plan import TestPlanAgent

            agent = TestPlanAgent(
                state=self.state,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            diagram_md, setup_md = await agent.run()

            # Write output files
            if diagram_md:
                diagram_path = self.target_path / "testing-diagram.md"
                try:
                    diagram_path.write_text(diagram_md)
                    self.log(f"Testing diagram saved: {diagram_path}", style="bold green")
                except OSError:
                    fallback = Path.cwd() / f"testing-diagram-{self.state.target_name}.md"
                    fallback.write_text(diagram_md)
                    self.log(f"Testing diagram saved (fallback): {fallback}", style="bold yellow")

            if setup_md:
                setup_path = self.target_path / "test-setup.md"
                try:
                    setup_path.write_text(setup_md)
                    self.log(f"Test setup saved: {setup_path}", style="bold green")
                except OSError:
                    fallback = Path.cwd() / f"test-setup-{self.state.target_name}.md"
                    fallback.write_text(setup_md)
                    self.log(f"Test setup saved (fallback): {fallback}", style="bold yellow")

        except Exception as e:
            self.log(f"Test plan generation failed: {e}", style="red")
            self.log("Continuing without test plan")

    async def run_phase_deep_analysis(self) -> None:
        """Phase 3: Deep Analysis with specialized hunters via HunterSwarm."""
        self.log("Phase 3: Deep Analysis (Vulnerability Hunting)", style="bold magenta")

        # Build list of hunters based on depth, language, and architecture
        hunters = []

        # --- Fast depth: highest-signal hunters only ---
        # KnownBugReplayHunter goes FIRST in all depths: mostly regex (cheapest),
        # catches the highest-value M/H bugs from real audit findings.
        # SlippageHunter and ParameterValidationHunter produce the most findings per API dollar.
        # At fast depth, we skip low-yield hunters (reentrancy, flash loan, oracle pattern matching)
        # and rely on these two plus AccessControl for broad coverage.
        if self.depth == "fast":
            from .hunters.slippage import SlippageHunter
            from .hunters.parameter_validation import ParameterValidationHunter
            from .hunters.known_bug_replay import KnownBugReplayHunter

            # KnownBugReplayHunter first: cheap regex + LLM only on matches
            hunters.append(
                KnownBugReplayHunter(
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

        # --- Standard: core + standard hunters + invariant fuzzer ---
        elif self.depth == "standard":
            from .hunters.slippage import SlippageHunter
            from .hunters.math_verification import MathVerificationHunter
            from .hunters.parameter_validation import ParameterValidationHunter
            from .hunters.invariant_fuzzer import InvariantFuzzerHunter
            from .hunters.known_bug_replay import KnownBugReplayHunter
            from .hunters.halmos_prover import HalmosProverHunter
            from .hunters.reasoning_hunter import ReasoningHunter, ReasoningHunterConfig

            # KnownBugReplayHunter first: cheap regex + LLM only on matches
            hunters.append(
                KnownBugReplayHunter(
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

            # ReasoningHunter: concrete execution tracing (before fuzzer/prover)
            if self.language == Language.SOLIDITY:
                reasoning_config = ReasoningHunterConfig(
                    max_contracts=2,
                    max_functions_per_contract=5,
                    trace_thinking_budget=16000,
                )
                hunters.append(
                    ReasoningHunter(
                        state=self.state,
                        config=reasoning_config,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            # InvariantFuzzerHunter: generates and runs Foundry invariant tests
            if self.language == Language.SOLIDITY:
                hunters.append(
                    InvariantFuzzerHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            # HalmosProverHunter last: most expensive (symbolic execution)
            if self.language == Language.SOLIDITY:
                hunters.append(
                    HalmosProverHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

        # --- Deep: all hunters including algebraic verification, invariant fuzzer, sequence explorer ---
        else:  # depth == "deep"
            from .hunters.slippage import SlippageHunter
            from .hunters.math_verification import MathVerificationHunter
            from .hunters.parameter_validation import ParameterValidationHunter
            from .hunters.invariant_fuzzer import InvariantFuzzerHunter
            from .hunters.sequence_explorer import SequenceExplorerHunter
            from .hunters.known_bug_replay import KnownBugReplayHunter
            from .hunters.halmos_prover import HalmosProverHunter
            from .hunters.reasoning_hunter import ReasoningHunter, ReasoningHunterConfig

            # KnownBugReplayHunter first: cheap regex + LLM only on matches
            hunters.append(
                KnownBugReplayHunter(
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

            # ReasoningHunter: concrete execution tracing (before fuzzer/prover)
            if self.language == Language.SOLIDITY:
                reasoning_config = ReasoningHunterConfig(
                    max_contracts=3,
                    max_functions_per_contract=7,
                    trace_thinking_budget=24000,
                )
                hunters.append(
                    ReasoningHunter(
                        state=self.state,
                        config=reasoning_config,
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

            # InvariantFuzzerHunter: generates and runs Foundry invariant tests
            if self.language == Language.SOLIDITY:
                hunters.append(
                    InvariantFuzzerHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            # SequenceExplorerHunter: multi-step attack sequences (deep only)
            if self.language == Language.SOLIDITY:
                hunters.append(
                    SequenceExplorerHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

            # HalmosProverHunter last: most expensive (symbolic execution)
            if self.language == Language.SOLIDITY:
                hunters.append(
                    HalmosProverHunter(
                        state=self.state,
                        verbose=self.verbose,
                        language=self.language,
                    )
                )

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

        # Opt-in: swap eligible native hunters for batched variants that do one
        # cached-prefix LLM call over the full source bundle instead of a
        # tool-use loop per contract. First-pass coverage: Slippage only.
        if self.batched_hunters and self.language == Language.SOLIDITY:
            try:
                from .hunters.slippage_batched import SlippageBatchedHunter
                swapped = 0
                new_hunters = []
                for h in hunters:
                    if type(h).__name__ == "SlippageHunter":
                        new_hunters.append(
                            SlippageBatchedHunter(
                                state=self.state,
                                llm_client=self.llm,
                                verbose=self.verbose,
                                language=self.language,
                                ultrathink=(self.depth != "fast"),
                            )
                        )
                        swapped += 1
                    else:
                        new_hunters.append(h)
                hunters = new_hunters
                if swapped:
                    self.log(f"Swapped {swapped} native hunter(s) for batched variants", style="cyan")
            except Exception as e:
                self.log(f"Could not swap to batched hunters: {e}", style="yellow")

        # Opt-in: append Pashov Audit Group specialist personas (8 hunters).
        # Only Solidity — vendored personas assume EVM.
        if self.include_pashov and self.language == Language.SOLIDITY:
            # Drop native hunters whose coverage is redundant with a Pashov persona.
            # pashov-access-control subsumes AccessControlHunter; pashov-math-precision
            # subsumes MathVerificationHunter; pashov-invariant subsumes InvariantFuzzerHunter.
            # Saves ~30% of the hunter API budget on standard/deep audits.
            _redundant_class_names = {
                "AccessControlHunter",
                "MathVerificationHunter",
                "InvariantFuzzerHunter",
            }
            before = len(hunters)
            hunters = [h for h in hunters if type(h).__name__ not in _redundant_class_names]
            dropped = before - len(hunters)
            if dropped:
                self.log(
                    f"Dropped {dropped} native hunter(s) redundant with Pashov personas",
                    style="yellow",
                )

            try:
                from .hunters.pashov import build_all_pashov_hunters
                pashov_hunters = build_all_pashov_hunters(
                    state=self.state,
                    llm_client=self.llm,
                    ultrathink=(self.depth != "fast"),
                    thinking_budget=16000,
                    verbose=self.verbose,
                )
                hunters.extend(pashov_hunters)
                self.log(f"Added {len(pashov_hunters)} Pashov specialist hunters", style="cyan")
            except Exception as e:
                self.log(f"Could not load Pashov hunters: {e}", style="yellow")

        # Soroban/Stellar specialist — auto-added when the target is a Stellar
        # smart contract project. The Solana-flavored hunters (access_control,
        # flash_loan, oracle) cover different primitives than Soroban, so the
        # specialist compensates with TTL/require_auth/storage-tier coverage.
        try:
            from ..core.languages import Blockchain
            is_soroban = getattr(self, "blockchain", None) == Blockchain.STELLAR
        except Exception:
            is_soroban = False

        if is_soroban:
            try:
                from .hunters.soroban import SorobanHunter
                from ..core.languages import Blockchain as _Bc
                hunters.append(
                    SorobanHunter(
                        state=self.state,
                        language=self.language,
                        blockchain=_Bc.STELLAR,
                        verbose=self.verbose,
                    )
                )
                self.log("Added SorobanHunter (Stellar/Soroban specialist)", style="cyan")
            except Exception as e:
                self.log(f"Could not load SorobanHunter: {e}", style="yellow")

        # Solana specialist — auto-added when the target is a Solana program.
        # Loads safe-solana-builder rule packs (Anchor / Native / Pinocchio)
        # based on framework markers detected in the target tree.
        try:
            from ..core.languages import Blockchain
            is_solana = getattr(self, "blockchain", None) == Blockchain.SOLANA
        except Exception:
            is_solana = False

        if is_solana:
            try:
                from .hunters.solana import SolanaHunter
                from ..core.languages import Blockchain as _Bc
                hunters.append(
                    SolanaHunter(
                        state=self.state,
                        language=self.language,
                        blockchain=_Bc.SOLANA,
                        verbose=self.verbose,
                    )
                )
                self.log("Added SolanaHunter (Anchor/Native/Pinocchio specialist)", style="cyan")
            except Exception as e:
                self.log(f"Could not load SolanaHunter: {e}", style="yellow")

        self.log(f"Running {len(hunters)} hunters for {self.language.value} (depth={self.depth})...")

        # Snapshot per-hunter findings count + runtime so telemetry can attribute
        # each finding to a specific hunter even when concurrent runs interleave.
        import time as _time

        async def _attributed_run(hunter):
            label = hunter.name
            pre_findings = len(self.state.findings)
            t0 = _time.monotonic()
            try:
                with self.llm.attribute(label):
                    result = await hunter.run()
                ok = True
                err = None
            except Exception as e:
                ok = False
                err = e
                result = e
            dt = _time.monotonic() - t0
            post_findings = len(self.state.findings)
            telem = self.state.hunter_telemetry.setdefault(label, {})
            telem["runtime_seconds"] = telem.get("runtime_seconds", 0.0) + dt
            telem["findings"] = telem.get("findings", 0) + max(0, post_findings - pre_findings)
            telem["status"] = "ok" if ok else f"error: {type(err).__name__ if err else ''}"
            return result

        if self.parallel_hunters:
            # Real concurrency, gated by max_concurrent_hunters. The LLM client
            # already retries on RateLimitError (core/llm.py:270), so cascading
            # 429s self-heal — this used to be Semaphore(1) (sequential) out of
            # paranoia. Tune via Orchestrator(max_concurrent_hunters=N).
            semaphore = asyncio.Semaphore(self.max_concurrent_hunters)
            self.log(
                f"Parallel hunters: max_concurrent={self.max_concurrent_hunters}",
                style="dim",
            )

            async def rate_limited_run(hunter):
                async with semaphore:
                    return await _attributed_run(hunter)

            tasks = [rate_limited_run(hunter) for hunter in hunters]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for hunter, result in zip(hunters, results):
                if isinstance(result, Exception):
                    self.log(f"{hunter.name} failed: {result}", style="red")
        else:
            for hunter in hunters:
                self.log(f"Running {hunter.name}...")
                try:
                    await _attributed_run(hunter)
                except Exception as e:
                    self.log(f"{hunter.name} failed: {e}", style="red")

        # Merge LLM-side per-attribution stats into hunter_telemetry so the
        # eval can read tokens+cost+findings from a single state field.
        for label, bucket in self.llm.per_attribution.items():
            telem = self.state.hunter_telemetry.setdefault(label, {})
            for k, v in bucket.items():
                telem[k] = v

        self.log(f"Deep analysis complete: {len(self.state.findings)} total findings")

    def _deduplicate_findings(self) -> None:
        """Merge findings reporting the same site (multiple hunters firing on
        the same vuln in the same function) into a single consolidated finding.

        Key: (vuln_type, contract, function, line_bucket)
          - line_bucket = first(line_numbers) // 10  — collapses near-line dupes
            (hunter A reports L42, hunter B reports L45 → same bucket).
          - When line_numbers is empty, the bucket is "" so we still merge by
            (vuln_type, contract, function).

        Cross-site *root-cause* dedup (e.g. one slippage bug pattern repeated
        across 4 unrelated contracts) is handled later by DevilsAdvocate's
        deduplicate_root_cause pass — this stage is intentionally local so we
        don't collapse genuinely distinct findings before validation.
        """
        if not self.state.findings:
            return

        from collections import defaultdict

        def _line_bucket(f: Finding) -> str:
            lns = getattr(f, "line_numbers", None) or []
            if not lns:
                return ""
            return str(min(lns) // 10)

        groups: dict[tuple, list[Finding]] = defaultdict(list)
        for f in self.state.findings:
            key = (
                f.vulnerability_type.value,
                (f.contract or "").lower(),
                (f.function or "").lower(),
                _line_bucket(f),
            )
            groups[key].append(f)

        deduped: list[Finding] = []
        severity_order = [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFORMATIONAL,
        ]
        for group in groups.values():
            if len(group) == 1:
                deduped.append(group[0])
                continue

            # Pick the highest-severity, highest-confidence finding as primary
            # so the merged record carries the strongest claim.
            primary = sorted(
                group,
                key=lambda f: (
                    severity_order.index(f.severity)
                    if f.severity in severity_order else len(severity_order),
                    -float(getattr(f, "confidence", 0.0) or 0.0),
                ),
            )[0]
            others = [f for f in group if f is not primary]
            other_ids = [f.id for f in others]

            primary.description += (
                "\n\n**Also reported by:** "
                + ", ".join(f"{f.id} ({f.found_by.value if hasattr(f.found_by, 'value') else f.found_by})"
                            for f in others)
            )
            primary.related_findings.extend(other_ids)
            primary.confidence = max(getattr(f, "confidence", 0.0) or 0.0 for f in group)

            deduped.append(primary)
            self.log(
                f"  Deduped {len(group)} findings (same site) -> {primary.id} "
                f"({primary.title[:50]}...)"
            )

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

    async def run_phase_protocol_intent(self) -> None:
        """Phase 2.75: Protocol Intent - understand design before hunting."""
        self.log("Phase 2.75: Protocol Intent Analysis", style="bold magenta")

        try:
            from .protocol_intent import ProtocolIntentAgent, ProtocolIntentConfig

            config = ProtocolIntentConfig(
                ultrathink=True,
                thinking_budget=16000,
            )
            agent = ProtocolIntentAgent(
                state=self.state,
                config=config,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            intent = await agent.run()
            self.log(f"Protocol type: {intent.protocol_type}", style="green")
            if intent.intentional_restrictions:
                self.log(f"Intentional restrictions: {len(intent.intentional_restrictions)}")
            if intent.trust_model:
                self.log(f"Trust model roles: {', '.join(intent.trust_model.keys())}")

        except Exception as e:
            self.log(f"Protocol intent analysis failed: {e}", style="red")
            self.log("Continuing without protocol intent")

    def _enrich_call_chains(self) -> None:
        """Phase 3.25: Call-Chain Enrichment - trace callers for each finding."""
        self.log("Phase 3.25: Call-Chain Enrichment", style="bold magenta")

        if not self.state.findings:
            self.log("No findings to enrich")
            return

        try:
            from .call_chain_enricher import CallChainEnricher

            enricher = CallChainEnricher(state=self.state, verbose=self.verbose)
            self.state.findings = enricher.enrich(self.state.findings, self.state)

        except Exception as e:
            self.log(f"Call-chain enrichment failed: {e}", style="red")
            self.log("Continuing without call-chain context")

    def _calibrate_finding_severities(self) -> None:
        """Phase 3.27: Severity calibration via competitive_audit_intel.

        Cross-checks each finding's severity against C4/Sherlock/Immunefi
        keyword priors. If a finding's severity disagrees with the prior by
        more than one tier, log it (do NOT silently override - LLM judgment
        usually wins). Cheap: pure keyword matching, no LLM.
        """
        if not self.state.findings:
            return
        try:
            from ..core.skills.competitive_audit_intel import (
                CompetitiveAuditIntel, Platform,
            )
        except ImportError:
            return

        self.log("Phase 3.27: Severity Calibration", style="bold magenta")
        intel = CompetitiveAuditIntel()
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        adjusted = 0
        for finding in self.state.findings:
            try:
                desc = (finding.description or "") + " " + (finding.title or "")
                suggested = intel.calibrate_severity(desc, Platform.IMMUNEFI)
                current = (finding.severity.value if hasattr(finding.severity, "value")
                           else str(finding.severity)).lower()
                if sev_order.get(suggested, -1) - sev_order.get(current, -1) >= 2:
                    self.log(
                        f"  severity gap: {finding.title[:60]} "
                        f"(hunter={current}, prior={suggested})",
                        style="yellow",
                    )
                    adjusted += 1
            except Exception:
                continue
        if adjusted:
            self.log(f"  flagged {adjusted} findings for severity review")
        else:
            self.log("  no severity gaps detected")

    def _surface_finding_variants(self) -> None:
        """Phase 3.28: For each finding, search the rest of the codebase for
        similar patterns. Surfaces adjacent code that may have the same bug.
        Output is appended to the finding's description as a 'Potential variants'
        section so the report writer / downstream phases see it.

        Pure ripgrep / regex - no LLM cost.
        """
        if not self.state.findings:
            return
        try:
            from ..core.skills.variant_analyzer import (
                VariantAnalyzer, VulnerabilityPattern, SearchTool,
            )
        except ImportError:
            return

        self.log("Phase 3.28: Variant Surface", style="bold magenta")
        analyzer = VariantAnalyzer(target_path=self.target_path)

        for finding in self.state.findings:
            # Need a code snippet to anchor the search
            snippet = finding.code_snippet or finding.affected_code or ""
            if not snippet or len(snippet) < 20:
                continue
            try:
                pattern = VulnerabilityPattern(
                    name=finding.title[:80],
                    original_code=snippet,
                    root_cause=finding.description[:300] if finding.description else "",
                    impact="theft" if "theft" in (finding.description or "").lower() else "loss",
                    exploitability="high",
                )
                report = analyzer.find_variants(
                    pattern, tool=SearchTool.RIPGREP, max_fp_rate=0.5,
                )
                # Filter to high/medium confidence only
                hits = [v for v in report.variants
                        if str(getattr(v.confidence, "value", v.confidence)).lower()
                        in ("high", "medium")]
                if hits:
                    extra = "\n\n## Potential Variants (auto-surfaced)\n"
                    for v in hits[:5]:
                        extra += f"- {v.file_path}:{v.line_number} (confidence: {v.confidence})\n"
                    finding.description = (finding.description or "") + extra
            except Exception:
                continue

    async def _confirm_findings(self) -> None:
        """Phase 3.3: Deterministic finding confirmation via Semgrep.

        For each confirmable finding, generates a Semgrep pattern that would
        match the specific code claim, then runs it. Boosts confidence for
        confirmed findings, reduces it for unconfirmed ones.
        """
        if not self.state.findings:
            self.log("No findings to confirm")
            return

        self.log("Phase 3.3: Finding Confirmation (Semgrep)", style="bold magenta")

        try:
            from .finding_confirmer import FindingConfirmer

            confirmer = FindingConfirmer(
                state=self.state,
                llm_client=self.llm,
                verbose=self.verbose,
            )
            self.state.findings = await confirmer.apply(
                self.state.findings, self.state,
            )

        except Exception as e:
            self.log(f"Finding confirmation failed: {e}", style="red")
            self.log("Continuing without Semgrep confirmation")

    async def run_phase_c4_gate(self) -> None:
        """Phase 3.75: C4 Severity Gate - apply hard C4 judging rules."""
        self.log("Phase 3.75: C4 Severity Gate", style="bold magenta")

        if not self.state.findings:
            self.log("No findings to gate")
            return

        try:
            from .c4_severity_gate import C4SeverityGate

            gate = C4SeverityGate(
                state=self.state,
                llm_client=self.llm,
                verbose=self.verbose,
            )
            self.state.findings = await gate.apply(self.state.findings, self.state)

        except Exception as e:
            self.log(f"C4 severity gate failed: {e}", style="red")
            self.log("Continuing without C4 gate")

    async def run_phase_validation(self) -> None:
        """Phase 3.5: Unified validation - severity calibration + feasibility challenge + dedup.

        Pipeline:
          1. Haiku triage — score each finding for plausibility in one cheap batch call.
             Obvious FPs (score < 30) get dropped so the expensive Sonnet ultrathink
             pass doesn't waste cycles re-examining them.
          2. DevilsAdvocate on survivors — severity calibration, feasibility challenge,
             root-cause dedup. Batches of 4 findings per ultrathink call.
        """
        self.log("Phase 3.5: Finding Validation (Calibration + Challenge)", style="bold magenta")

        if not self.state.findings:
            self.log("No findings to validate")
            return

        try:
            pre_count = len(self.state.findings)

            # Step 1: Haiku pre-triage — drop obvious false positives cheaply.
            survivors = await self._haiku_triage_findings(self.state.findings)
            triaged_out = pre_count - len(survivors)
            if triaged_out:
                self.log(
                    f"Haiku triage dropped {triaged_out} obvious FPs before Sonnet validation",
                    style="yellow",
                )
            self.state.findings = survivors

            if not survivors:
                self.log("All findings dropped by triage — skipping DevilsAdvocate")
                return

            from .devils_advocate import DevilsAdvocateAgent, DevilsAdvocateConfig

            config = DevilsAdvocateConfig(
                ultrathink=True,
                thinking_budget=16000,
                strict_mode=False,
                filter_low_confidence=True,
                # Severity calibration (merged from SeverityCalibrator)
                read_source=True,
                deduplicate_root_cause=True,
                # Batch processing: 4 findings per LLM call
                batch_size=4,
            )
            advocate = DevilsAdvocateAgent(
                state=self.state,
                config=config,
                llm_client=self.llm,
                verbose=self.verbose,
            )

            validated = await advocate.run(findings=self.state.findings)
            self.state.findings = validated
            post_count = len(self.state.findings)

            filtered = pre_count - post_count
            self.log(f"Validated {post_count}/{pre_count} findings ({filtered} filtered/merged)")

        except Exception as e:
            self.log(f"Validation failed: {e}", style="red")
            self.log("Keeping all findings unvalidated")

    async def _haiku_triage_findings(
        self,
        findings: list[Finding],
        min_plausibility: int = 30,
    ) -> list[Finding]:
        """Cheap Haiku pass scoring each finding 0-100 for plausibility.

        Returns the survivors (plausibility >= min_plausibility). Findings whose
        score can't be parsed default to keep (fail-open: we'd rather pay for an
        extra DevilsAdvocate call than silently drop a real bug).
        """
        if not findings:
            return findings

        from ..core.llm import HAIKU_MODEL

        manifest_lines = []
        for i, f in enumerate(findings):
            desc = (f.description or "")[:400].replace("\n", " ")
            manifest_lines.append(
                f'{i}: [{f.severity.value}] {f.title} | contract={f.contract} | {desc}'
            )
        manifest = "\n".join(manifest_lines)

        prompt = (
            "For each finding below, rate how PLAUSIBLE it is that this is a real "
            "exploitable bug (not a false positive or pattern-match without context). "
            "Score 0-100 where:\n"
            "  0-29  = obvious false positive (missing context, pattern only, no real impact)\n"
            "  30-59 = uncertain — needs deeper review\n"
            "  60-100 = likely real bug worth challenging\n\n"
            "Do NOT judge severity — only plausibility. Err on the side of keeping findings.\n\n"
            f"Findings:\n{manifest}\n\n"
            "Output exactly one line per finding as `index:score` (no extra text). "
            "Example: `0:75\\n1:20\\n2:55`."
        )

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system="You are a smart-contract security triage assistant. Be concise and numeric.",
                max_tokens=256 + 8 * len(findings),
                model_override=HAIKU_MODEL,
                enable_prompt_cache=False,
            )
        except Exception as e:
            self.log(f"Haiku triage failed: {e} — keeping all findings", style="yellow")
            return findings

        import re as _re
        scores: dict[int, int] = {}
        for line in (response.text or "").splitlines():
            m = _re.match(r"\s*(\d+)\s*:\s*(\d+)", line)
            if m:
                idx, sc = int(m.group(1)), int(m.group(2))
                if 0 <= idx < len(findings):
                    scores[idx] = max(0, min(100, sc))

        survivors: list[Finding] = []
        for i, f in enumerate(findings):
            if scores.get(i, 100) >= min_plausibility:
                survivors.append(f)
        return survivors

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

            # Always save PoC to state and finding (even if unverified)
            finding.poc = core_poc
            self.state.pocs.append(core_poc)

            if poc.verified:
                finding.validated = True
                self.log(f"  [VERIFIED] {finding.id}: {finding.title}", style="bold green")
            else:
                finding.validated = False
                finding.confidence = finding.confidence * 0.5
                self.log(f"  [UNVERIFIED] {finding.id}: PoC failed, confidence halved to {finding.confidence:.2f}", style="yellow")

    def _run_soroban_poc_generation(self, eligible: list) -> None:
        """
        Emit Soroban PoC stubs for each eligible finding. Output is a
        standalone Rust file per finding under `sentinel_pocs_soroban/`
        that extends the C4 `tests/c4/src/lib.rs` template's
        `test_submission_validity` function.

        This is deliberately not an LLM-driven agent — PoC templates are
        deterministic renderings indexed by finding.vulnerability_type.
        A warden using the output is expected to tune argument values and
        assertions to the specific bug; the generator provides the
        scaffold, not the final exploit.
        """
        from ..core.poc_generator_soroban import (
            SorobanPoCRequest,
            generate_soroban_poc,
            infer_poc_type,
            patch_submission_file,
            WARDEN_MARKER,
        )

        out_dir = self.target_path / "sentinel_pocs_soroban"
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            out_dir = Path.cwd() / f"sentinel_pocs_soroban_{self.state.target_name}"
            out_dir.mkdir(parents=True, exist_ok=True)

        # Locate the C4 submission template if present — then we also emit
        # a ready-to-run patched copy for the top-severity finding.
        c4_template = self.target_path / "tests" / "c4" / "src" / "lib.rs"

        written = 0
        for finding in eligible:
            poc_type = infer_poc_type(finding.vulnerability_type)
            target_contract = (finding.contract or "unknown").split("::")[0] or "unknown"
            target_function = finding.function or finding.contract or "target_fn"

            req = SorobanPoCRequest(
                poc_type=poc_type,
                title=finding.title,
                target_function=target_function,
                target_contract=target_contract,
                attack_steps_narrative=finding.description.split("\n")[0][:240],
            )
            snippet = generate_soroban_poc(req)

            snippet_path = out_dir / f"{finding.id}.rs"
            try:
                snippet_path.write_text(snippet)
                written += 1
            except OSError as e:
                self.log(f"  [WRITE-FAIL] {finding.id}: {e}", style="red")
                continue

            # Attach the snippet to the finding so the reporter can include it.
            try:
                from ..core.types import PoC

                finding.poc = PoC(
                    finding_id=finding.id,
                    code=snippet,
                    language="rust",
                    template_used=poc_type.value,
                )
            except Exception:
                pass

            # For the first finding (highest severity post-sort), also
            # render a patched lib.rs so the warden can run it immediately.
            if written == 1 and c4_template.exists():
                try:
                    patched = patch_submission_file(c4_template, snippet)
                    patched_path = out_dir / f"{finding.id}_lib.rs"
                    patched_path.write_text(patched)
                    self.log(
                        f"  [PATCHED] {finding.id}: {patched_path.relative_to(self.target_path)} "
                        f"(drop-in replacement for tests/c4/src/lib.rs)",
                        style="cyan",
                    )
                except ValueError:
                    # WARDEN_MARKER missing — report once and keep going.
                    self.log(
                        f"Warden marker {WARDEN_MARKER!r} not found in "
                        f"{c4_template}; skipping patched-template output",
                        style="yellow",
                    )
                except OSError as e:
                    self.log(f"Could not write patched template: {e}", style="yellow")

        self.log(
            f"Soroban PoC scaffolds written: {written}/{len(eligible)} "
            f"-> {out_dir}",
            style="bold green" if written else "yellow",
        )

    async def run_phase_poc_generation(self) -> None:
        """Phase 6: PoC Generation - create and verify exploits for findings."""
        self.log("Phase 6: PoC Generation", style="bold magenta")

        eligible = self._get_poc_eligible_findings()
        if not eligible:
            self.log("No findings eligible for PoC generation")
            return

        self.log(f"{len(eligible)} findings eligible for PoC generation")

        # Soroban/Stellar projects bypass the Foundry PoC agent entirely —
        # its output is Solidity/forge. Emit Rust/Soroban PoC stubs for the
        # C4 `tests/c4/src/lib.rs` template instead.
        try:
            from ..core.languages import Blockchain
            if getattr(self, "blockchain", None) == Blockchain.STELLAR:
                self._run_soroban_poc_generation(eligible)
                return
        except Exception as e:
            self.log(f"Soroban PoC gen dispatch failed: {e}", style="yellow")

        if not self.fork_url:
            self.log("WARNING: No --fork-url provided. PoC code will be generated but not executed.", style="yellow")

        try:
            from .poc_generator import PoCGeneratorAgent, PoCConfig

            config = PoCConfig(
                fork_url=self.fork_url,
                fork_block=self.fork_block,
                output_dir=self.target_path / "sentinel_pocs",
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

        # Save report — try target_path first, fall back to cwd
        report_path = self.target_path / "sentinel_report.md"
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report)
            self.log(f"Report saved to: {report_path}", style="bold green")
        except OSError as e:
            # target_path may not be writable (removed, read-only, etc.)
            fallback_path = Path.cwd() / f"sentinel_report_{self.state.target_name}.md"
            self.log(f"Cannot write to {report_path}: {e}", style="red")
            try:
                fallback_path.write_text(report)
                self.log(f"Report saved to fallback: {fallback_path}", style="bold yellow")
            except OSError as e2:
                self.log(f"Cannot write report anywhere: {e2}", style="bold red")
                self.log("Report content is in memory — use generate_report() to retrieve it", style="yellow")

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
        stats = self.llm.get_stats()
        console.print(f"\nDuration: {duration:.1f}s")
        console.print(f"Contracts Analyzed: {len(self.state.contracts)}")
        console.print(f"Depth: {self.depth}")

        # Final cost breakdown
        console.print()
        console.print("[bold cyan]--- Final Cost Summary ---[/bold cyan]")
        console.print(f"  Total API Cost:     [bold]${stats['total_cost']:.4f}[/bold]")
        console.print(f"  Cache Savings:      [green]${stats['prompt_cache_savings']:.4f}[/green]")
        console.print(f"  Input Tokens:       {stats['total_input_tokens']:,}")
        console.print(f"  Output Tokens:      {stats['total_output_tokens']:,}")
        console.print(f"  Thinking Tokens:    {stats['total_thinking_tokens']:,}")
        console.print(f"  Disk Cache Hits:    {stats['cache_hits']}")
        console.print("[dim]  Check remaining balance at console.anthropic.com > Billing[/dim]")

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

    async def run(self, resume_from: Optional[str] = None, poc_only: bool = False) -> AuditState:
        """
        Execute the full audit pipeline.

        Args:
            resume_from: Path to a checkpoint JSON to resume from.
                         Skips Phases 1-3 and goes straight to validation/PoC.
            poc_only: Skip validation and attack synthesis, jump straight to PoC generation.
                      Use with resume_from to save API credits.

        Returns:
            Final audit state with all findings
        """
        console.print(Panel(
            f"[bold]Sentinel Security Audit[/bold]\n\nTarget: {self.target_path}\nDepth: {self.depth}"
            + (f"\nResuming from checkpoint" if resume_from else "")
            + (f"\nMode: PoC generation only" if poc_only else ""),
            expand=False
        ))

        # Show starting cost (should be $0 unless client was reused)
        console.print("[bold cyan]--- API Credit Tracker ---[/bold cyan]")
        self._print_cost_status()
        console.print("[dim]  (Check remaining balance at console.anthropic.com > Billing)[/dim]")
        console.print()

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
                self._print_cost_status("Recon")

                # Phase 1.5: Audit intel (zero API cost - pdftotext + regex)
                # Detects prior audit reports + acknowledged issues so hunters
                # dedupe instead of re-reporting them.
                self.run_phase_audit_intel()

                # Generate vulnerability cheatsheet (zero API cost — pure YAML parsing)
                from ..knowledge.vulnerability_registry import VulnerabilityRegistry
                registry = VulnerabilityRegistry.get_instance()
                self.state.vulnerability_cheatsheet = registry.generate_cheatsheet(
                    language=self.language.value, depth=self.depth,
                )

                # Phase 2: Static Analysis
                await self.run_phase_static_analysis()

                # Phase 2.5: Cross-Contract Analysis (standard+)
                if self.depth in ("standard", "deep"):
                    await self.run_phase_cross_contract_analysis()
                self._print_cost_status("Static + Cross-Contract")

                # Phase 2.6: Test Plan (~$0.10) — skipped in eval_mode (human-only output).
                if not self.eval_mode:
                    await self.run_phase_test_plan()
                    self._print_cost_status("Test Plan")

                # Phase 2.75: Protocol Intent (standard+)
                if self.depth in ("standard", "deep"):
                    await self.run_phase_protocol_intent()
                    self._print_cost_status("Protocol Intent")

                # Phase 3: Deep Analysis (all hunters based on depth)
                await self.run_phase_deep_analysis()
                self._print_cost_status("Hunters")

                # Save checkpoint after hunters — this is the expensive part
                self._save_checkpoint("hunters")

            # Deduplicate before expensive LLM phases
            self._deduplicate_findings()

            # Phase 3.25: Call-Chain Enrichment (all depths, free — no LLM)
            self._enrich_call_chains()

            # Phase 3.27: Severity calibration vs C4/Sherlock/Immunefi priors (free)
            self._calibrate_finding_severities()

            # Phase 3.28: Surface adjacent variants of each finding (free, ripgrep)
            if self.depth in ("standard", "deep"):
                self._surface_finding_variants()

            # Phase 3.3: Semgrep confirmation (standard+, cheap — one Haiku batch + local Semgrep)
            if self.depth in ("standard", "deep"):
                await self._confirm_findings()
                self._print_cost_status("Finding Confirmation")

            if poc_only:
                self.log("--poc-only: Skipping validation and attack synthesis", style="bold cyan")
            else:
                # Phase 3.5: Validation (standard+)
                if self.depth in ("standard", "deep"):
                    await self.run_phase_validation()
                    self._print_cost_status("Validation")

                # Phase 3.75: C4 Severity Gate (all depths) — skip in eval_mode
                # (we're not submitting; raw hunter severity is what eval scores).
                if not self.eval_mode:
                    await self.run_phase_c4_gate()
                    self._print_cost_status("C4 Gate")

                # Phase 5: Attack Synthesis (deep only)
                if self.depth == "deep":
                    await self.run_phase_attack_synthesis()
                    self._print_cost_status("Attack Synthesis")

            # Phase 6: PoC Generation — eval_mode skips this entirely (eval
            # scoring is location/class-based, not PoC-validity-based, so the
            # most expensive phase in the pipeline is dead weight here).
            if (
                not self.eval_mode
                and self.depth in ("standard", "deep")
                and self.state.findings
            ):
                await self.run_phase_poc_generation()
                self._print_cost_status("PoC Generation")

            # Save checkpoint before reporting — all expensive work is done
            self._save_checkpoint("pre_report")

            # Phase 7: Reporting — skip in eval_mode (no markdown report needed).
            if not self.eval_mode:
                await self.run_phase_reporting()
            else:
                self.state.end_time = datetime.now()
                self.print_summary()

        except Exception as e:
            error_msg = str(e)
            is_credit_error = CREDIT_ERROR in error_msg.lower()

            if is_credit_error:
                self.log("Credit balance exhausted. Saving checkpoint and partial report...", style="bold yellow")
            else:
                self.log(f"Audit failed: {e}", style="bold red")

            # Always try to save checkpoint + partial report on failure
            try:
                checkpoint = self._save_checkpoint("partial")
                self.state.end_time = datetime.now()
                self.print_summary()
                report = self.generate_report()
                report_path = self.target_path / "sentinel_report.md"
                report_path.write_text(report)
                self.log(f"Partial report saved: {report_path}", style="yellow")
                self.log(f"Resume with: sentinel audit {self.target_path} --resume {checkpoint}", style="bold yellow")
            except Exception as save_err:
                self.log(f"Could not save checkpoint/report: {save_err}", style="bold red")

            if is_credit_error:
                return self.state
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
    poc_only: bool = False,
    include_pashov: bool = False,
    batched_hunters: bool = False,
    eval_mode: bool = False,
    audits_dir: Optional[Path] = None,
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
        poc_only: Skip validation/synthesis, jump to PoC generation

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
        include_pashov=include_pashov,
        batched_hunters=batched_hunters,
        eval_mode=eval_mode,
        audits_dir=audits_dir,
    )
    return await orchestrator.run(resume_from=resume_from, poc_only=poc_only)
