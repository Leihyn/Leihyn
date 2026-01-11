"""
Hunter Swarm - Multi-agent parallel vulnerability hunting.

World-class audits use multiple perspectives:
- Different hunters find different bugs
- Parallel analysis for speed
- Deduplication and synthesis of findings

This orchestrator:
1. Runs multiple specialized hunters in parallel
2. Deduplicates and merges findings
3. Synthesizes attack chains
4. Ranks by severity and confidence
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Type
from enum import Enum

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType

# Import specialized hunters
from .deep_hunter import DeepHunterAgent, DeepAnalysisConfig
from .invariant_agent import InvariantAgent, InvariantConfig
from .attack_synthesizer import AttackSynthesizerAgent, AttackSynthesisConfig
from .protocol_hunters import AaveV3Hunter, UniswapV3Hunter, UniswapV4Hunter, CurveHunter

console = Console()


class HunterType(Enum):
    """Types of hunters in the swarm."""
    DEEP = "deep"           # Deep business logic analysis
    INVARIANT = "invariant" # Invariant-based analysis
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ORACLE = "oracle"
    FLASH_LOAN = "flash_loan"
    AAVE = "aave"
    UNISWAP = "uniswap"
    CURVE = "curve"


@dataclass
class HunterConfig:
    """Configuration for a single hunter."""
    hunter_type: HunterType
    enabled: bool = True
    ultrathink: bool = True
    thinking_budget: int = 16000
    weight: float = 1.0  # Weight for ranking


@dataclass
class SwarmConfig:
    """Configuration for the hunter swarm."""
    hunters: list[HunterConfig] = field(default_factory=list)
    parallel: bool = True
    max_concurrent: int = 5
    deduplicate: bool = True
    synthesize_attacks: bool = True
    min_confidence: float = 0.5
    ultrathink: bool = True

    def __post_init__(self):
        if not self.hunters:
            # Default hunter configuration
            self.hunters = [
                HunterConfig(HunterType.DEEP, ultrathink=True, thinking_budget=24000),
                HunterConfig(HunterType.INVARIANT, ultrathink=True, thinking_budget=20000),
                HunterConfig(HunterType.AAVE, ultrathink=True, thinking_budget=16000),
                HunterConfig(HunterType.UNISWAP, ultrathink=True, thinking_budget=16000),
                HunterConfig(HunterType.CURVE, ultrathink=True, thinking_budget=16000),
            ]


class HunterSwarm:
    """
    Orchestrate multiple hunters in parallel.

    Features:
    - Parallel execution of specialized hunters
    - Finding deduplication and merging
    - Attack chain synthesis
    - Confidence-weighted ranking
    """

    def __init__(
        self,
        state: AuditState,
        config: Optional[SwarmConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        self.state = state
        self.config = config or SwarmConfig()
        self.llm = llm_client or get_llm_client()
        self.verbose = verbose
        self.all_findings: list[Finding] = []
        self.hunter_results: dict[HunterType, list[Finding]] = {}

    def log(self, message: str, style: str = "") -> None:
        """Log a message."""
        if self.verbose:
            console.print(f"[{style}]{message}[/{style}]" if style else message)

    def _create_hunter(self, config: HunterConfig) -> Optional[HunterAgent]:
        """Create a hunter instance from config."""
        hunter_map = {
            HunterType.DEEP: (DeepHunterAgent, DeepAnalysisConfig),
            HunterType.INVARIANT: (InvariantAgent, InvariantConfig),
            HunterType.AAVE: (AaveV3Hunter, None),
            HunterType.UNISWAP: (UniswapV3Hunter, None),
            HunterType.CURVE: (CurveHunter, None),
        }

        if config.hunter_type not in hunter_map:
            return None

        hunter_class, config_class = hunter_map[config.hunter_type]

        if config_class:
            hunter_config = config_class(
                ultrathink=config.ultrathink,
                thinking_budget=config.thinking_budget,
            )
            return hunter_class(
                state=self.state,
                config=hunter_config,
                llm_client=self.llm,
                verbose=self.verbose,
            )
        else:
            return hunter_class(
                state=self.state,
                llm_client=self.llm,
                verbose=self.verbose,
            )

    async def hunt(self) -> list[Finding]:
        """Run all hunters and aggregate findings."""
        self.log("Starting Hunter Swarm...", style="bold magenta")
        self.log(f"Hunters: {len([h for h in self.config.hunters if h.enabled])}")
        self.log(f"Contracts: {len(self.state.contracts)}")

        # Create hunters
        hunters: list[tuple[HunterConfig, HunterAgent]] = []
        for config in self.config.hunters:
            if not config.enabled:
                continue
            hunter = self._create_hunter(config)
            if hunter:
                hunters.append((config, hunter))

        if not hunters:
            self.log("No hunters enabled!", style="red")
            return []

        # Run hunters
        if self.config.parallel:
            findings = await self._run_parallel(hunters)
        else:
            findings = await self._run_sequential(hunters)

        # Store all findings
        self.all_findings = findings

        # Deduplicate
        if self.config.deduplicate:
            self.log("Deduplicating findings...", style="cyan")
            findings = self._deduplicate(findings)
            self.log(f"Unique findings: {len(findings)}")

        # Filter by confidence
        findings = [f for f in findings if f.confidence >= self.config.min_confidence]

        # Synthesize attacks
        if self.config.synthesize_attacks and len(findings) > 1:
            self.log("Synthesizing attack chains...", style="cyan")
            await self._synthesize_attacks(findings)

        # Rank findings
        findings = self._rank_findings(findings)

        self.print_summary(findings)
        return findings

    async def _run_parallel(
        self,
        hunters: list[tuple[HunterConfig, HunterAgent]],
    ) -> list[Finding]:
        """Run hunters in parallel with semaphore."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def run_with_semaphore(config: HunterConfig, hunter: HunterAgent):
            async with semaphore:
                self.log(f"Starting {hunter.name}...", style="cyan")
                try:
                    findings = await hunter.run()
                    self.hunter_results[config.hunter_type] = findings
                    self.log(f"{hunter.name}: {len(findings)} findings", style="green")
                    return findings
                except Exception as e:
                    self.log(f"{hunter.name} failed: {e}", style="red")
                    return []

        # Run all hunters
        results = await asyncio.gather(*[
            run_with_semaphore(config, hunter)
            for config, hunter in hunters
        ])

        # Flatten results
        all_findings = []
        for findings in results:
            all_findings.extend(findings)

        return all_findings

    async def _run_sequential(
        self,
        hunters: list[tuple[HunterConfig, HunterAgent]],
    ) -> list[Finding]:
        """Run hunters sequentially."""
        all_findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running hunters...", total=len(hunters))

            for config, hunter in hunters:
                progress.update(task, description=f"Running {hunter.name}...")
                try:
                    findings = await hunter.run()
                    self.hunter_results[config.hunter_type] = findings
                    all_findings.extend(findings)
                except Exception as e:
                    self.log(f"{hunter.name} failed: {e}", style="red")

                progress.advance(task)

        return all_findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings based on similarity."""
        unique = []
        seen_signatures = set()

        for finding in findings:
            # Create signature from key attributes
            sig = self._finding_signature(finding)

            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique.append(finding)
            else:
                # Merge with existing (keep higher confidence)
                for i, existing in enumerate(unique):
                    if self._finding_signature(existing) == sig:
                        if finding.confidence > existing.confidence:
                            unique[i] = finding
                        break

        return unique

    def _finding_signature(self, finding: Finding) -> str:
        """Create a signature for deduplication."""
        # Normalize key fields
        contract = finding.contract.lower()
        vuln_type = finding.vulnerability_type.value
        title_words = set(finding.title.lower().split()[:5])

        # Include line numbers if available
        lines = ""
        if finding.line_numbers:
            lines = f"{finding.line_numbers[0]}"

        return f"{contract}:{vuln_type}:{sorted(title_words)}:{lines}"

    async def _synthesize_attacks(self, findings: list[Finding]) -> None:
        """Synthesize attack chains from findings."""
        config = AttackSynthesisConfig(
            ultrathink=self.config.ultrathink,
            thinking_budget=20000,
        )
        synthesizer = AttackSynthesizerAgent(
            state=self.state,
            config=config,
            llm_client=self.llm,
            verbose=self.verbose,
        )

        try:
            chains = await synthesizer.run(findings=findings)
            if chains:
                self.log(f"Found {len(chains)} attack chains", style="yellow")
        except Exception as e:
            self.log(f"Attack synthesis failed: {e}", style="red")

    def _rank_findings(self, findings: list[Finding]) -> list[Finding]:
        """Rank findings by severity and confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
            Severity.GAS: 5,
        }

        def score(finding: Finding) -> tuple:
            sev_score = severity_order.get(finding.severity, 5)
            conf_score = 1 - finding.confidence
            return (sev_score, conf_score)

        return sorted(findings, key=score)

    def print_summary(self, findings: list[Finding]) -> None:
        """Print summary of findings."""
        console.print("\n[bold magenta]═══ HUNTER SWARM RESULTS ═══[/bold magenta]\n")

        # Summary by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_table = Table(title="Findings Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")

        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = severity_counts.get(sev, 0)
            style = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue"}.get(sev, "white")
            if count > 0:
                summary_table.add_row(sev.upper(), str(count), style=style)

        console.print(summary_table)

        # Findings by hunter
        if self.hunter_results:
            hunter_table = Table(title="Findings by Hunter")
            hunter_table.add_column("Hunter", style="cyan")
            hunter_table.add_column("Findings", justify="right")

            for hunter_type, hunter_findings in self.hunter_results.items():
                hunter_table.add_row(hunter_type.value, str(len(hunter_findings)))

            console.print(hunter_table)

        # Top findings
        if findings:
            top_table = Table(title="Top Findings")
            top_table.add_column("ID", style="cyan")
            top_table.add_column("Severity")
            top_table.add_column("Title", max_width=50)
            top_table.add_column("Confidence", justify="right")

            for f in findings[:10]:
                sev_style = {"critical": "red", "high": "orange1", "medium": "yellow"}.get(f.severity.value, "white")
                top_table.add_row(
                    f.id,
                    f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
                    f.title[:50],
                    f"{f.confidence:.0%}",
                )

            console.print(top_table)


# Convenience function
async def hunt_with_swarm(
    state: AuditState,
    parallel: bool = True,
    ultrathink: bool = True,
) -> list[Finding]:
    """Hunt with the full swarm."""
    config = SwarmConfig(parallel=parallel, ultrathink=ultrathink)
    swarm = HunterSwarm(state=state, config=config)
    return await swarm.hunt()
