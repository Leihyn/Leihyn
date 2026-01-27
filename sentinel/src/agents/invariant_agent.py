"""
Invariant Agent - Deep invariant analysis with extended thinking.

Top auditors think in invariants:
- What MUST always be true?
- What sequence breaks it?
- What's the impact?

This agent:
1. Infers invariants from code and docs
2. Uses ultrathink to find subtle invariant violations
3. Generates Foundry tests to prove violations
4. Synthesizes findings from broken invariants
5. Generates Chimera-compatible fuzzing suites (Recon Magic methodology)

Recon Magic Integration:
- Identifies functions of interest (state-changing only)
- Generates clamping strategies from contract state
- Builds shortcut functions for multi-step exploit paths
- Achieves high standardized line coverage (38x efficiency gain)

Reference: https://getrecon.xyz/blog/recon-magic
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType
from ..knowledge.invariants import (
    Invariant,
    InvariantCategory,
    InvariantInferenceEngine,
    InvariantTestGenerator,
    InvariantViolation,
)
from ..core.fuzzing_generator import (
    ContractAnalyzer,
    ClampingEngine,
    ShortcutGenerator,
    ChimeraGenerator,
    StandardizedCoverageAnalyzer,
    FuzzingConfig,
    ClampedHandler,
    ShortcutFunction,
    generate_fuzzing_suite,
    analyze_standardized_coverage,
)

console = Console()


@dataclass
class InvariantConfig:
    """Configuration for invariant analysis."""
    ultrathink: bool = True
    thinking_budget: int = 20000
    infer_from_code: bool = True
    infer_from_docs: bool = True
    generate_tests: bool = True
    run_fuzzing: bool = False  # Requires Foundry setup
    max_invariants_per_contract: int = 20
    # Recon Magic: Fuzzing suite generation
    generate_fuzzing_suite: bool = True
    include_clamped_handlers: bool = True
    include_shortcuts: bool = True
    fuzzing_actors: list[str] = None  # Defaults set in __post_init__

    def __post_init__(self):
        if self.fuzzing_actors is None:
            self.fuzzing_actors = ["actor1", "actor2", "actor3"]


class InvariantAgent(HunterAgent, ReconMagicMixin):
    """
    World-class invariant analysis agent.

    Analysis Flow:
    1. Static Inference - Extract invariants from code patterns
    2. LLM Inference - Use ultrathink to find deeper invariants
    3. Violation Hunting - Try to find sequences that break invariants
    4. Test Generation - Create Foundry tests for violations
    5. Finding Synthesis - Convert violations to structured findings
    6. Fuzzing Suite Generation - Create Chimera-compatible tests (Recon Magic)

    Recon Magic Integration:
    - Identifies functions of interest for standardized coverage
    - Generates clamped handlers with intelligent input restriction
    - Creates shortcut functions for deep state exploration
    - Outputs Echidna/Medusa compatible test suites
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "InvariantHunter"
    description = "Deep invariant-based vulnerability analysis with Recon Magic fuzzing"

    def __init__(
        self,
        state: AuditState,
        config: Optional[InvariantConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or InvariantConfig()
        self.inference_engine = InvariantInferenceEngine(llm_client=self.llm)
        self.test_generator = InvariantTestGenerator()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at invariant-based smart contract analysis.

Your mindset:
1. WHAT MUST ALWAYS BE TRUE? - Identify fundamental properties
2. CAN IT BE BROKEN? - Think adversarially about violations
3. WHAT'S THE IMPACT? - Quantify damage if broken

Invariant Categories:
- BALANCE: sum(balances) <= totalSupply, reserves >= liabilities
- STATE: initialized => configured, paused => no mutations
- TRANSITION: balance_before - amount = balance_after
- ECONOMIC: no arbitrage in single tx, collateral >= debt * ratio
- ACCESS: owner != address(0), roles properly assigned
- ORDERING: deposit before withdraw, approve before transfer
- BOUND: fee <= MAX_FEE, amount > 0 && amount < MAX

For each invariant violation:
1. Describe the invariant clearly
2. Show the exact sequence that breaks it
3. Explain why it matters (impact)
4. Provide Foundry test concept
5. Suggest the fix

Focus on CRITICAL invariants - those whose violation leads to loss of funds."""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Execute invariant analysis on all contracts."""
        self.log("Starting invariant-based vulnerability analysis...", style="bold magenta")

        all_findings = []
        all_invariants = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for contract in self.state.contracts:
                task = progress.add_task(f"Analyzing {contract.name}...", total=None)

                # Phase 1: Infer invariants
                invariants = await self.infer_invariants(contract)
                all_invariants.extend(invariants)
                self.log(f"Inferred {len(invariants)} invariants for {contract.name}")

                # Phase 2: Hunt for violations
                findings = await self.hunt_violations(contract, invariants)
                all_findings.extend(findings)

                progress.update(task, completed=True)

        # Generate test file if requested
        if self.config.generate_tests and all_invariants:
            self.generate_tests(all_invariants)

        # Generate Chimera fuzzing suite (Recon Magic)
        if self.config.generate_fuzzing_suite:
            self.log("Generating Chimera fuzzing suites (Recon Magic)...", style="bold cyan")
            for contract in self.state.contracts:
                fuzzing_result = self.analyze_for_fuzzing(
                    contract.source, contract.name
                )
                self._write_fuzzing_suite(contract.name, fuzzing_result)
                self.log(
                    f"  {contract.name}: {fuzzing_result.standardized_coverage_target} "
                    f"target functions, {len(fuzzing_result.clamped_handlers)} clamped handlers, "
                    f"{len(fuzzing_result.shortcut_functions)} shortcuts"
                )

        self.log(f"Total: {len(all_findings)} invariant-based findings", style="bold green")
        return all_findings

    def _write_fuzzing_suite(
        self,
        contract_name: str,
        result: FuzzingAnalysisResult,
    ) -> None:
        """Write generated fuzzing suite to project."""
        if self.state.project_path:
            output_path = (
                Path(self.state.project_path) / "test" / "fuzzing" /
                f"{contract_name}.TargetFunctions.sol"
            )
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(result.chimera_suite)
            self.log(f"  Wrote fuzzing suite to {output_path}")
        else:
            self.log(f"  Generated fuzzing suite for {contract_name} (no project path set)")

    async def infer_invariants(self, contract) -> list[Invariant]:
        """Infer all invariants for a contract."""
        invariants = []

        # Static inference from code
        if self.config.infer_from_code:
            self.log(f"Static invariant inference for {contract.name}...")
            static_invariants = self.inference_engine.infer_from_code(
                contract.source, contract.name
            )
            invariants.extend(static_invariants)
            self.log(f"  Found {len(static_invariants)} from code patterns")

        # LLM inference with ultrathink
        if self.config.infer_from_docs and self.llm:
            self.log(f"Deep invariant inference with ultrathink...")
            llm_invariants = await self.inference_engine.infer_with_llm(
                contract.source, contract.name
            )
            invariants.extend(llm_invariants)
            self.log(f"  Found {len(llm_invariants)} from LLM analysis")

        # Deduplicate
        seen = set()
        unique = []
        for inv in invariants:
            key = inv.expression[:100]
            if key not in seen:
                seen.add(key)
                unique.append(inv)

        return unique[:self.config.max_invariants_per_contract]

    async def hunt_violations(
        self,
        contract,
        invariants: list[Invariant]
    ) -> list[Finding]:
        """Use ultrathink to find invariant violations."""
        if not invariants:
            return []

        self.log(f"Hunting for invariant violations in {contract.name}...")

        # Group critical invariants
        critical = [i for i in invariants if i.critical]
        other = [i for i in invariants if not i.critical]

        findings = []

        # Deep analysis on critical invariants
        if critical:
            self.log(f"Deep analysis of {len(critical)} critical invariants...")
            critical_findings = await self._analyze_invariants(
                contract, critical, thinking_budget=24000
            )
            findings.extend(critical_findings)

        # Standard analysis on others
        if other:
            self.log(f"Analyzing {len(other)} other invariants...")
            other_findings = await self._analyze_invariants(
                contract, other, thinking_budget=16000
            )
            findings.extend(other_findings)

        return findings

    async def _analyze_invariants(
        self,
        contract,
        invariants: list[Invariant],
        thinking_budget: int = 16000,
    ) -> list[Finding]:
        """Deep analysis of invariants with ultrathink."""
        invariant_list = "\n".join([
            f"{i+1}. [{inv.category.value.upper()}] {inv.description}\n   Expression: {inv.expression}\n   Critical: {'YES' if inv.critical else 'No'}"
            for i, inv in enumerate(invariants)
        ])

        prompt = f"""Analyze this contract for invariant violations.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Invariants to Verify:**
{invariant_list}

**Analysis Task:**

For each invariant, determine:
1. CAN IT BE VIOLATED? Think about:
   - Flash loans that temporarily change state
   - Reentrancy during callbacks
   - Edge cases (first user, empty pool, max values)
   - Multi-transaction sequences
   - Compromised oracles or external calls
   - Race conditions and front-running

2. IF VIOLABLE, provide:
   - Step-by-step attack sequence
   - Solidity code snippet for PoC
   - Quantified impact (funds at risk)
   - Severity (Critical/High/Medium/Low)

3. IF NOT VIOLABLE, explain:
   - What prevents violation
   - Any assumptions made

Format findings as:
INVARIANT: [number from list]
STATUS: VIOLABLE | SAFE
ATTACK_SEQUENCE:
1. Step one
2. Step two
...
POC_CONCEPT:
```solidity
// Foundry test concept
```
IMPACT: [funds at risk, severity]
ROOT_CAUSE: [why this is possible]
FIX: [how to prevent]
---

Think deeply. Miss nothing."""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=thinking_budget,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        # Parse findings
        findings = self._parse_invariant_findings(
            response.content, contract.name, invariants
        )
        return findings

    def _parse_invariant_findings(
        self,
        response: str,
        contract_name: str,
        invariants: list[Invariant]
    ) -> list[Finding]:
        """Parse invariant violation findings from LLM response."""
        findings = []
        blocks = response.split('---')

        for block in blocks:
            if 'VIOLABLE' not in block:
                continue

            try:
                # Extract invariant number
                inv_match = re.search(r'INVARIANT:\s*(\d+)', block)
                if not inv_match:
                    continue

                inv_num = int(inv_match.group(1)) - 1
                if inv_num < 0 or inv_num >= len(invariants):
                    continue

                invariant = invariants[inv_num]

                # Extract attack sequence
                attack_match = re.search(
                    r'ATTACK_SEQUENCE:\s*(.+?)(?=POC_CONCEPT:|IMPACT:|$)',
                    block, re.DOTALL
                )
                attack_sequence = attack_match.group(1).strip() if attack_match else ""

                # Extract PoC
                poc_match = re.search(r'```solidity\s*(.+?)```', block, re.DOTALL)
                poc_code = poc_match.group(1).strip() if poc_match else ""

                # Extract impact
                impact_match = re.search(r'IMPACT:\s*(.+?)(?=ROOT_CAUSE:|FIX:|$)', block, re.DOTALL)
                impact = impact_match.group(1).strip() if impact_match else ""

                # Extract root cause
                root_match = re.search(r'ROOT_CAUSE:\s*(.+?)(?=FIX:|$)', block, re.DOTALL)
                root_cause = root_match.group(1).strip() if root_match else ""

                # Extract fix
                fix_match = re.search(r'FIX:\s*(.+?)$', block, re.DOTALL)
                fix = fix_match.group(1).strip() if fix_match else ""

                # Determine severity
                severity = Severity.HIGH  # Default for invariant violations
                if invariant.critical or 'critical' in impact.lower():
                    severity = Severity.CRITICAL
                elif 'medium' in impact.lower():
                    severity = Severity.MEDIUM

                # Create finding
                findings.append(Finding(
                    id=f"{contract_name}-INV-{invariant.id}",
                    title=f"Invariant Violation: {invariant.description[:60]}",
                    severity=severity,
                    vulnerability_type=self._categorize_vuln_type(invariant),
                    description=f"""**Invariant:** {invariant.description}
**Expression:** `{invariant.expression}`

**Attack Sequence:**
{attack_sequence}

**Proof of Concept:**
```solidity
{poc_code}
```""",
                    contract=contract_name,
                    impact=impact,
                    root_cause=root_cause,
                    recommendation=fix,
                    confidence=0.85,
                    references=[f"Invariant category: {invariant.category.value}"],
                ))

            except Exception:
                continue

        return findings

    def _categorize_vuln_type(self, invariant: Invariant) -> VulnerabilityType:
        """Map invariant category to vulnerability type."""
        mapping = {
            InvariantCategory.BALANCE: VulnerabilityType.ACCOUNTING_ERROR,
            InvariantCategory.STATE: VulnerabilityType.STATE_MANIPULATION,
            InvariantCategory.TRANSITION: VulnerabilityType.BUSINESS_LOGIC,
            InvariantCategory.ECONOMIC: VulnerabilityType.ECONOMIC_ATTACK,
            InvariantCategory.ACCESS: VulnerabilityType.ACCESS_CONTROL,
            InvariantCategory.ORDERING: VulnerabilityType.RACE_CONDITION,
            InvariantCategory.BOUND: VulnerabilityType.ARITHMETIC_OVERFLOW,
        }
        return mapping.get(invariant.category, VulnerabilityType.OTHER)

    def generate_tests(self, invariants: list[Invariant]) -> None:
        """Generate Foundry invariant tests."""
        if not invariants:
            return

        # Group by contract
        by_contract: dict[str, list[Invariant]] = {}
        for inv in invariants:
            for contract in inv.contracts_involved:
                if contract not in by_contract:
                    by_contract[contract] = []
                by_contract[contract].append(inv)

        # Generate test file for each contract
        for contract_name, contract_invariants in by_contract.items():
            content = self.test_generator.generate_test_file(
                contract_invariants,
                contract_name,
            )

            # Write to project if path available
            if self.state.project_path:
                output_path = Path(self.state.project_path) / "test" / "invariants" / f"{contract_name}.invariant.t.sol"
                self.test_generator.write_test_file(content, output_path)
            else:
                self.log(f"Generated invariant test for {contract_name} ({len(contract_invariants)} invariants)")


# Import re for parsing
import re


# ===========================================================================
# RECON MAGIC: STATEFUL FUZZING GENERATION
# ===========================================================================

@dataclass
class FuzzingAnalysisResult:
    """Result of fuzzing analysis using Recon Magic methodology."""
    functions_of_interest: list[str]
    excluded_functions: list[str]
    clamped_handlers: list[ClampedHandler]
    shortcut_functions: list[ShortcutFunction]
    chimera_suite: str
    standardized_coverage_target: int


class ReconMagicMixin:
    """
    Mixin providing Recon Magic fuzzing capabilities.

    Based on methodology from https://getrecon.xyz/blog/recon-magic

    Key concepts:
    - Standardized Line Coverage: Focus only on state-changing functions
    - Clamped Handlers: Restrict inputs to reach deeper states faster
    - Shortcut Functions: Multi-step sequences for complex state transitions
    """

    def analyze_for_fuzzing(
        self,
        contract_source: str,
        contract_name: str,
    ) -> FuzzingAnalysisResult:
        """
        Analyze a contract using Recon Magic methodology.

        Returns functions of interest, clamping strategies, and shortcuts.
        """
        # Analyze contract
        analyzer = ContractAnalyzer(contract_source, contract_name)
        config = FuzzingConfig(
            contract_name=contract_name,
            actors=self.config.fuzzing_actors if hasattr(self, 'config') else ["actor1", "actor2"],
            include_shortcuts=self.config.include_shortcuts if hasattr(self, 'config') else True,
        )

        # Identify functions of interest (state-changing only)
        foi = analyzer.get_functions_of_interest()
        excluded = analyzer.get_view_functions()

        self.log(f"Functions of interest: {len(foi)} (state-changing)")
        self.log(f"Excluded from coverage: {len(excluded)} (view/pure)")

        # Generate clamped handlers
        clamping_engine = ClampingEngine(analyzer, config)
        clamped_handlers = [
            clamping_engine.generate_clamped_handler(f)
            for f in foi
        ]
        self.log(f"Generated {len(clamped_handlers)} clamped handlers")

        # Generate shortcut functions
        shortcut_gen = ShortcutGenerator(analyzer, config)
        shortcuts = shortcut_gen.generate_shortcuts()
        self.log(f"Generated {len(shortcuts)} shortcut functions")

        # Generate complete Chimera suite
        chimera_gen = ChimeraGenerator(config)
        chimera_suite = chimera_gen.generate_suite(analyzer, clamped_handlers, shortcuts)

        return FuzzingAnalysisResult(
            functions_of_interest=[f.name for f in foi],
            excluded_functions=[f.name for f in excluded],
            clamped_handlers=clamped_handlers,
            shortcut_functions=shortcuts,
            chimera_suite=chimera_suite,
            standardized_coverage_target=len(foi),
        )

    def generate_clamping_strategies(
        self,
        contract_source: str,
        contract_name: str,
    ) -> list[dict]:
        """
        Generate intelligent clamping strategies for each function.

        Returns list of dicts with function name, parameters, and clamping rationale.
        """
        analyzer = ContractAnalyzer(contract_source, contract_name)
        config = FuzzingConfig(contract_name=contract_name)
        clamping_engine = ClampingEngine(analyzer, config)

        strategies = []
        for func in analyzer.get_functions_of_interest():
            handler = clamping_engine.generate_clamped_handler(func)
            strategies.append({
                "function": func.name,
                "parameters": [(t, n) for t, n in func.parameters],
                "clamped_params": handler.clamped_params,
                "strategy": handler.clamping_strategy.value,
                "rationale": handler.rationale,
            })

        return strategies

    def identify_shortcut_opportunities(
        self,
        contract_source: str,
        contract_name: str,
    ) -> list[dict]:
        """
        Identify opportunities for shortcut functions.

        Shortcuts combine multiple handlers to reach deep states faster.
        """
        analyzer = ContractAnalyzer(contract_source, contract_name)
        config = FuzzingConfig(contract_name=contract_name)
        shortcut_gen = ShortcutGenerator(analyzer, config)

        shortcuts = shortcut_gen.generate_shortcuts()
        return [
            {
                "name": s.name,
                "handlers_combined": s.handlers_called,
                "description": s.description,
                "pattern": self._identify_pattern(s),
            }
            for s in shortcuts
        ]

    def _identify_pattern(self, shortcut: ShortcutFunction) -> str:
        """Identify the DeFi pattern a shortcut represents."""
        handlers = shortcut.handlers_called

        if "deposit" in handlers and "borrow" in handlers:
            return "lending_collateralization"
        if "approve" in handlers and "transferFrom" in handlers:
            return "token_allowance"
        if "stake" in handlers:
            return "staking_lifecycle"
        if any("liquidity" in h.lower() for h in handlers):
            return "amm_liquidity"
        if any("position" in h.lower() for h in handlers):
            return "perp_position"

        return "custom_sequence"

    def get_standardized_coverage_report(
        self,
        contract_source: str,
        contract_name: str,
        covered_functions: set[str] = None,
    ) -> dict:
        """
        Generate standardized coverage report.

        Standardized coverage excludes view/pure functions that don't
        contribute to state exploration.
        """
        analyzer = ContractAnalyzer(contract_source, contract_name)
        coverage_analyzer = StandardizedCoverageAnalyzer(analyzer)

        foi = coverage_analyzer.get_standardized_functions()
        excluded = coverage_analyzer.get_excluded_functions()

        coverage = 0.0
        if covered_functions:
            coverage = coverage_analyzer.calculate_standardized_coverage(covered_functions)

        return {
            "contract": contract_name,
            "standardized_coverage_pct": coverage,
            "functions_of_interest": {
                "count": len(foi),
                "names": [f.name for f in foi],
            },
            "excluded_from_coverage": {
                "count": len(excluded),
                "names": [f.name for f in excluded],
                "reason": "view/pure functions do not alter state",
            },
            "coverage_formula": "covered_foi / total_foi * 100",
            "methodology": "Recon Magic - Standardized Line Coverage",
        }


# Convenience function
async def hunt_invariants(state: AuditState, ultrathink: bool = True) -> list[Finding]:
    """Convenience function for invariant-based hunting."""
    config = InvariantConfig(ultrathink=ultrathink)
    agent = InvariantAgent(state=state, config=config)
    return await agent.run()
