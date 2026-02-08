"""
Attack Path Synthesis Agent - Combine findings into attack chains.

World-class auditors don't just find bugs - they chain them:
- Finding A: Oracle can be manipulated
- Finding B: Collateral check uses oracle
- Attack: Flash loan -> manipulate oracle -> borrow max -> profit

This agent:
1. Builds an attack graph from findings
2. Uses ultrathink to find attack chains
3. Calculates maximum extractable value
4. Generates combined PoCs
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import Finding, Severity, VulnerabilityType

console = Console()


class NodeType(Enum):
    """Types of nodes in attack graph."""
    ENTRY_POINT = "entry_point"       # External/public functions
    STATE_CHANGE = "state_change"     # Functions that modify state
    VALUE_FLOW = "value_flow"         # ETH/token transfers
    CALLBACK = "callback"             # Callbacks (receive, hooks, etc.)
    ORACLE = "oracle"                 # Price/data dependencies
    ACCESS_CHECK = "access_check"     # Access control checks
    GOAL = "goal"                     # Attack goals (profit, DoS, etc.)


@dataclass
class AttackNode:
    """Node in the attack graph."""
    id: str
    node_type: NodeType
    contract: str
    function: str
    description: str
    finding_id: Optional[str] = None
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    value_at_risk: float = 0.0


@dataclass
class AttackEdge:
    """Edge connecting attack nodes."""
    from_node: str
    to_node: str
    action: str
    prerequisites: list[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """A complete attack path from entry to goal."""
    id: str
    name: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    findings_used: list[str]
    severity: Severity
    max_extractable_value: float
    feasibility: float  # 0-1, how feasible is this attack?
    description: str
    attack_steps: list[str]
    poc_concept: str


@dataclass
class AttackSynthesisConfig:
    """Configuration for attack synthesis."""
    ultrathink: bool = True
    thinking_budget: int = 24000
    max_chain_length: int = 10
    min_chain_findings: int = 2
    generate_poc: bool = True
    consider_flash_loans: bool = True
    consider_mev: bool = True


class AttackSynthesizerAgent(HunterAgent):
    """
    Synthesize attack chains from individual findings.

    Analysis Flow:
    1. Build Attack Graph - Model protocol as nodes and edges
    2. Find Chains - Use graph search + LLM reasoning
    3. Rank Chains - By MEV, feasibility, severity
    4. Generate PoCs - Combined exploits
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "AttackSynthesizer"
    description = "Combine findings into attack chains"

    def __init__(
        self,
        state,
        config: Optional[AttackSynthesisConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or AttackSynthesisConfig()
        self.nodes: list[AttackNode] = []
        self.edges: list[AttackEdge] = []
        self.chains: list[AttackChain] = []

    @property
    def system_prompt(self) -> str:
        return """You are an expert at synthesizing attack chains from individual vulnerabilities.

Your approach:
1. UNDERSTAND each finding's root cause and impact
2. IDENTIFY dependencies between findings
3. MODEL value flows through the protocol
4. FIND sequences that maximize extraction
5. CONSIDER flash loans, MEV, and multi-tx attacks

Attack Chain Patterns:
- Oracle Manipulation + Lending: Manipulate price -> borrow at wrong rate
- Reentrancy + Business Logic: Reenter during callback -> bypass checks
- Access Control + Upgrade: Take ownership -> upgrade to malicious impl
- Flash Loan + Governance: Borrow votes -> pass malicious proposal
- First Depositor + Vault: Donate to manipulate shares -> steal deposits

For each chain:
1. List the findings combined
2. Explain how they connect
3. Provide step-by-step attack
4. Calculate maximum extractable value
5. Assess feasibility (prerequisites, costs, risks)

The best chains are:
- Simple (fewer steps = less can go wrong)
- Profitable (high MEV after costs)
- Feasible (realistic prerequisites)
- Demonstrable (clear PoC)"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[AttackChain]:
        """Synthesize attack chains from findings."""
        findings: list[Finding] = kwargs.get("findings", [])

        if len(findings) < self.config.min_chain_findings:
            self.log("Not enough findings to synthesize chains", style="yellow")
            return []

        self.log(f"Synthesizing attack chains from {len(findings)} findings...", style="bold magenta")

        # Step 1: Build attack graph
        self.log("Building attack graph...", style="cyan")
        await self._build_attack_graph(findings)
        self.log(f"  Graph: {len(self.nodes)} nodes, {len(self.edges)} edges")

        # Step 2: Find attack chains with ultrathink
        self.log("Finding attack chains with extended thinking...", style="cyan")
        chains = await self._find_attack_chains(findings)
        self.chains.extend(chains)
        self.log(f"  Found {len(chains)} potential attack chains")

        # Step 3: Rank and filter chains
        self.log("Ranking attack chains...", style="cyan")
        ranked_chains = self._rank_chains(chains)

        # Step 4: Generate PoC concepts
        if self.config.generate_poc:
            self.log("Generating PoC concepts...", style="cyan")
            for chain in ranked_chains[:5]:  # Top 5 chains
                chain.poc_concept = await self._generate_chain_poc(chain, findings)

        self.print_chains(ranked_chains)
        return ranked_chains

    async def _build_attack_graph(self, findings: list[Finding]) -> None:
        """Build attack graph from findings."""
        # Create nodes from findings
        for finding in findings:
            node = AttackNode(
                id=f"finding-{finding.id}",
                node_type=self._classify_node_type(finding),
                contract=finding.contract,
                function=finding.title,
                description=finding.description[:200],
                finding_id=finding.id,
                value_at_risk=self._estimate_value(finding),
            )
            self.nodes.append(node)

        # Create entry point nodes
        for contract in self.state.contracts:
            # Find external/public functions
            for match in re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*(external|public)', contract.source):
                func_name = match.group(1)
                self.nodes.append(AttackNode(
                    id=f"entry-{contract.name}-{func_name}",
                    node_type=NodeType.ENTRY_POINT,
                    contract=contract.name,
                    function=func_name,
                    description=f"Entry point: {func_name}",
                ))

        # Create goal nodes
        self.nodes.append(AttackNode(
            id="goal-profit",
            node_type=NodeType.GOAL,
            contract="",
            function="",
            description="Extract value from protocol",
        ))
        self.nodes.append(AttackNode(
            id="goal-dos",
            node_type=NodeType.GOAL,
            contract="",
            function="",
            description="Deny service to users",
        ))

        # Create edges based on finding relationships
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if self._findings_related(f1, f2):
                    self.edges.append(AttackEdge(
                        from_node=f"finding-{f1.id}",
                        to_node=f"finding-{f2.id}",
                        action=f"Chain {f1.id} to {f2.id}",
                    ))

    def _classify_node_type(self, finding: Finding) -> NodeType:
        """Classify finding into node type."""
        vuln_type = finding.vulnerability_type

        if "oracle" in vuln_type.value.lower():
            return NodeType.ORACLE
        elif "access" in vuln_type.value.lower():
            return NodeType.ACCESS_CHECK
        elif "reentrancy" in vuln_type.value.lower():
            return NodeType.CALLBACK
        elif any(x in vuln_type.value.lower() for x in ["transfer", "withdraw", "drain"]):
            return NodeType.VALUE_FLOW
        else:
            return NodeType.STATE_CHANGE

    def _estimate_value(self, finding: Finding) -> float:
        """Estimate value at risk from finding."""
        # Try to extract from impact text
        impact = finding.impact or finding.description
        for match in re.finditer(r'\$?([\d,]+(?:\.\d+)?)\s*(?:million|M|k|K)?', impact):
            value_str = match.group(1).replace(',', '')
            try:
                value = float(value_str)
                if 'million' in impact.lower() or 'M' in match.group(0):
                    value *= 1_000_000
                elif 'k' in match.group(0).lower():
                    value *= 1_000
                return value
            except ValueError:
                continue

        # Default based on severity
        defaults = {
            Severity.CRITICAL: 1_000_000,
            Severity.HIGH: 100_000,
            Severity.MEDIUM: 10_000,
            Severity.LOW: 1_000,
        }
        return defaults.get(finding.severity, 0)

    def _findings_related(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings could be chained."""
        # Same contract
        if f1.contract == f2.contract:
            return True

        # Complementary vulnerability types
        chain_pairs = [
            ("oracle", "lending"),
            ("oracle", "collateral"),
            ("flash_loan", "oracle"),
            ("flash_loan", "governance"),
            ("reentrancy", "accounting"),
            ("access", "upgrade"),
            ("first_deposit", "vault"),
        ]

        f1_type = f1.vulnerability_type.value.lower()
        f2_type = f2.vulnerability_type.value.lower()

        for t1, t2 in chain_pairs:
            if (t1 in f1_type and t2 in f2_type) or (t2 in f1_type and t1 in f2_type):
                return True

        return False

    async def _find_attack_chains(self, findings: list[Finding]) -> list[AttackChain]:
        """Use ultrathink to find attack chains."""
        # Prepare findings summary
        findings_summary = "\n\n".join([
            f"""**Finding {i+1}: {f.id}**
- Title: {f.title}
- Type: {f.vulnerability_type.value}
- Severity: {f.severity.value}
- Contract: {f.contract}
- Description: {f.description[:300]}...
- Root Cause: {f.root_cause or "N/A"}
- Impact: {f.impact or "N/A"}"""
            for i, f in enumerate(findings)
        ])

        prompt = f"""Analyze these vulnerabilities and find attack chains that combine multiple findings.

**Findings:**
{findings_summary}

**Your Task:**
1. Identify which findings can be COMBINED for greater impact
2. Determine the optimal SEQUENCE of exploitation
3. Calculate MAXIMUM EXTRACTABLE VALUE
4. Assess FEASIBILITY (prerequisites, costs, timing)

**Consider:**
- Flash loans to amplify attacks
- MEV to front-run or sandwich
- Multi-transaction attacks
- Cross-contract interactions
- State dependencies between exploits

**For each attack chain, provide:**

CHAIN: [name]
FINDINGS_USED: [list of finding IDs]
SEVERITY: [Critical/High/Medium]
MAX_VALUE: [estimated $ at risk]
FEASIBILITY: [0-100%]
ATTACK_STEPS:
1. [Step 1]
2. [Step 2]
...
POC_CONCEPT:
```
[High-level pseudocode/steps]
```
EXPLANATION: [Why these findings chain together]
---

Find ALL viable attack chains, then rank by MEV * Feasibility."""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=self.config.thinking_budget,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        # Parse chains from response
        return self._parse_chains(response.content)

    def _parse_chains(self, response: str) -> list[AttackChain]:
        """Parse attack chains from LLM response."""
        chains = []
        blocks = response.split('---')

        for i, block in enumerate(blocks):
            if 'CHAIN:' not in block:
                continue

            try:
                # Extract fields
                name_match = re.search(r'CHAIN:\s*(.+?)(?=\n|FINDINGS)', block)
                findings_match = re.search(r'FINDINGS_USED:\s*(.+?)(?=\n|SEVERITY)', block)
                severity_match = re.search(r'SEVERITY:\s*(\w+)', block)
                value_match = re.search(r'MAX_VALUE:\s*\$?([\d,]+)', block)
                feasibility_match = re.search(r'FEASIBILITY:\s*(\d+)', block)
                steps_match = re.search(r'ATTACK_STEPS:\s*\n((?:\d+\..*\n?)+)', block)
                poc_match = re.search(r'POC_CONCEPT:\s*```(.*?)```', block, re.DOTALL)
                explanation_match = re.search(r'EXPLANATION:\s*(.+?)(?=---|$)', block, re.DOTALL)

                if not all([name_match, findings_match]):
                    continue

                # Parse findings used
                findings_str = findings_match.group(1)
                findings_used = re.findall(r'[\w-]+', findings_str)

                # Parse severity
                severity = Severity.HIGH
                if severity_match:
                    sev_str = severity_match.group(1).lower()
                    if sev_str == 'critical':
                        severity = Severity.CRITICAL
                    elif sev_str == 'medium':
                        severity = Severity.MEDIUM

                # Parse attack steps
                attack_steps = []
                if steps_match:
                    steps_text = steps_match.group(1)
                    attack_steps = [s.strip() for s in re.split(r'\d+\.', steps_text) if s.strip()]

                chain = AttackChain(
                    id=f"chain-{i:02d}",
                    name=name_match.group(1).strip(),
                    nodes=[],
                    edges=[],
                    findings_used=findings_used,
                    severity=severity,
                    max_extractable_value=float(value_match.group(1).replace(',', '')) if value_match else 0,
                    feasibility=int(feasibility_match.group(1)) / 100 if feasibility_match else 0.5,
                    description=explanation_match.group(1).strip() if explanation_match else "",
                    attack_steps=attack_steps,
                    poc_concept=poc_match.group(1).strip() if poc_match else "",
                )
                chains.append(chain)

            except Exception as e:
                continue

        return chains

    def _rank_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Rank chains by expected value."""
        def score(chain: AttackChain) -> float:
            # Expected value = MEV * feasibility
            ev = chain.max_extractable_value * chain.feasibility

            # Bonus for critical severity
            if chain.severity == Severity.CRITICAL:
                ev *= 1.5

            # Penalty for complexity
            ev *= (1 - len(chain.findings_used) * 0.1)

            return ev

        return sorted(chains, key=score, reverse=True)

    async def _generate_chain_poc(self, chain: AttackChain, findings: list[Finding]) -> str:
        """Generate PoC concept for attack chain."""
        # Get details of findings used
        used_findings = [f for f in findings if f.id in chain.findings_used]

        prompt = f"""Generate a Foundry PoC concept for this attack chain.

**Attack Chain: {chain.name}**
**Steps:**
{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(chain.attack_steps))}

**Findings Used:**
{chr(10).join(f"- {f.id}: {f.title}" for f in used_findings)}

**Expected Profit:** ${chain.max_extractable_value:,.0f}

Generate high-level Foundry test structure showing:
1. Setup (fork, contracts, funding)
2. Each attack step as a separate section
3. Profit verification at the end

Keep it concise but complete enough to implement."""

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=self.system_prompt,
            max_tokens=2000,
        )

        return response.content

    def print_chains(self, chains: list[AttackChain]) -> None:
        """Print attack chains in a nice format."""
        if not chains:
            console.print("[yellow]No attack chains found[/yellow]")
            return

        console.print("\n[bold magenta]Attack Chains[/bold magenta]\n")

        for chain in chains[:5]:  # Top 5
            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
            }.get(chain.severity, "white")

            tree = Tree(f"[bold]{chain.name}[/bold]")
            tree.add(f"[{severity_color}]Severity: {chain.severity.value}[/{severity_color}]")
            tree.add(f"Max Value: ${chain.max_extractable_value:,.0f}")
            tree.add(f"Feasibility: {chain.feasibility:.0%}")
            tree.add(f"Findings: {', '.join(chain.findings_used)}")

            steps_branch = tree.add("Attack Steps:")
            for i, step in enumerate(chain.attack_steps[:5]):
                steps_branch.add(f"{i+1}. {step[:60]}...")

            console.print(tree)
            console.print()


# Convenience function
async def synthesize_attacks(findings: list[Finding]) -> list[AttackChain]:
    """Synthesize attack chains from findings."""
    from ..core.types import AuditState
    state = AuditState(project_path="")
    config = AttackSynthesisConfig()
    agent = AttackSynthesizerAgent(state=state, config=config)
    return await agent.run(findings=findings)
