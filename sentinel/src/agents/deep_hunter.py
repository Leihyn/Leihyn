"""
Deep Hunter Agent - World-class vulnerability hunting with extended thinking.

Features:
- Historical exploit pattern matching
- Multi-pass analysis (surface -> deep -> attack synthesis)
- Invariant-based reasoning
- Economic/game theory analysis
- Automatic PoC generation
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
from ..knowledge.exploit_matcher import ExploitMatcher, ExploitMatch

console = Console()


@dataclass
class DeepAnalysisConfig:
    """Configuration for deep analysis."""
    ultrathink: bool = True
    thinking_budget: int = 24000  # Higher for deep analysis
    multi_pass: bool = True
    exploit_matching: bool = True
    invariant_analysis: bool = True
    economic_analysis: bool = True
    generate_poc: bool = True
    max_findings_per_contract: int = 10


class DeepHunterAgent(HunterAgent):
    """
    World-class vulnerability hunter using extended thinking.

    Analysis Phases:
    1. Surface Scan - Quick pattern matching and static analysis
    2. Historical Matching - Compare to known exploits
    3. Deep Analysis - Extended thinking on business logic
    4. Invariant Check - What properties must hold?
    5. Economic Analysis - Game theory and incentives
    6. Attack Synthesis - Combine findings into attack paths
    7. PoC Generation - Prove exploitability
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "DeepHunter"
    description = "World-class deep vulnerability analysis"

    def __init__(
        self,
        state: AuditState,
        config: Optional[DeepAnalysisConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or DeepAnalysisConfig()
        self.exploit_matcher = ExploitMatcher()

    @property
    def system_prompt(self) -> str:
        return """You are an elite smart contract security researcher.

Your approach:
1. Think like an attacker - what would you exploit?
2. Question every assumption - what if X is not true?
3. Follow the money - where does value flow?
4. Check the edges - what happens at 0, max, boundaries?
5. Consider combinations - how do findings chain together?

When analyzing code:
- First understand what it's supposed to do
- Then find where it fails to do that
- Consider all entry points and exit points
- Think about state before, during, and after each call
- Model economic incentives for all actors

Severity Assessment:
- CRITICAL: Unconditional loss of funds, complete protocol compromise
- HIGH: Conditional loss of funds, significant value extraction
- MEDIUM: Limited impact, temporary issues, griefing
- LOW: Best practices, minor issues

For each finding, you MUST provide:
1. Clear root cause
2. Step-by-step attack path
3. Quantified impact ($ at risk if possible)
4. Working PoC concept
5. Specific fix

Never report a finding without understanding how to exploit it.
"""

    def get_tools(self) -> list[Tool]:
        return []  # Uses direct analysis

    async def run(self, **kwargs) -> list[Finding]:
        """Execute deep analysis on all contracts."""
        self.log("Starting deep vulnerability analysis...", style="bold magenta")

        all_findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for contract in self.state.contracts:
                task = progress.add_task(f"Analyzing {contract.name}...", total=None)

                findings = await self.analyze_contract(contract)
                all_findings.extend(findings)

                progress.update(task, completed=True)
                self.log(f"Found {len(findings)} issues in {contract.name}")

        # Attack synthesis
        if len(all_findings) > 1:
            self.log("Synthesizing attack paths...", style="cyan")
            attack_chains = await self.synthesize_attacks(all_findings)
            for chain in attack_chains:
                self.log(f"Attack chain: {chain}", style="red")

        return all_findings

    async def analyze_contract(self, contract) -> list[Finding]:
        """
        Deep analysis of a single contract.
        """
        findings = []
        code = contract.source

        # Phase 1: Historical Exploit Matching
        if self.config.exploit_matching:
            self.log(f"Phase 1: Checking against {len(self.exploit_matcher.exploits)} known exploits...")
            exploit_matches = self.exploit_matcher.analyze_code(code)

            if exploit_matches["matches"]:
                self.log(f"Found {len(exploit_matches['matches'])} patterns matching known exploits!", style="yellow")
                for match in exploit_matches["matches"]:
                    # Investigate each match with ultrathink
                    finding = await self.investigate_exploit_match(contract, match)
                    if finding:
                        findings.append(finding)

        # Phase 2: Invariant Analysis
        if self.config.invariant_analysis:
            self.log("Phase 2: Invariant analysis...")
            invariant_findings = await self.analyze_invariants(contract)
            findings.extend(invariant_findings)

        # Phase 3: Deep Business Logic Analysis
        self.log("Phase 3: Deep business logic analysis with extended thinking...")
        logic_findings = await self.deep_logic_analysis(contract)
        findings.extend(logic_findings)

        # Phase 4: Economic Analysis
        if self.config.economic_analysis:
            self.log("Phase 4: Economic/game theory analysis...")
            economic_findings = await self.analyze_economics(contract)
            findings.extend(economic_findings)

        # Deduplicate and rank
        findings = self.deduplicate_findings(findings)

        return findings[:self.config.max_findings_per_contract]

    async def investigate_exploit_match(
        self,
        contract,
        match: ExploitMatch
    ) -> Optional[Finding]:
        """
        Investigate a potential exploit match with extended thinking.
        """
        prompt = f"""A pattern in this code matches a known exploit.

**Historical Exploit:**
- Name: {match.exploit.name}
- Date: {match.exploit.date}
- Amount Lost: ${match.exploit.amount_lost:,}
- Root Cause: {match.exploit.root_cause}
- Attack Vector: {match.exploit.attack_vector}

**Matched Code (Line {match.matched_line}):**
```solidity
{match.matched_code}
```

**Full Contract:**
```solidity
{contract.source[:8000]}
```

**Analysis Task:**
1. Is this code actually vulnerable to the same attack?
2. What are the exact preconditions needed?
3. Can this be exploited in the current context?
4. What's the realistic impact?

If this IS exploitable:
- Provide step-by-step attack path
- Estimate funds at risk
- Write the PoC concept

If this is NOT exploitable:
- Explain what mitigations are in place
- State clearly it's a false positive

Be rigorous. Don't report if you can't explain how to exploit it.
"""

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

        # Parse response
        content = response.content.lower()

        # Check if it's exploitable
        if "not exploitable" in content or "false positive" in content or "not vulnerable" in content:
            self.log(f"Match at line {match.matched_line} - FALSE POSITIVE", style="dim")
            return None

        # It's a real finding
        return Finding(
            id=f"{contract.name}-HIST-{match.matched_line}",
            title=f"Pattern matches {match.exploit.name} exploit",
            severity=Severity.HIGH,  # Historical matches are usually serious
            vulnerability_type=VulnerabilityType(match.exploit.vulnerability_type) if match.exploit.vulnerability_type in [v.value for v in VulnerabilityType] else VulnerabilityType.OTHER,
            description=response.content,
            contract=contract.name,
            line_numbers=(match.matched_line, match.matched_line + 10),
            impact=f"Similar to {match.exploit.name} which resulted in ${match.exploit.amount_lost:,} loss",
            root_cause=match.exploit.root_cause,
            recommendation=match.exploit.fix_applied,
            confidence=match.similarity_score,
            references=[f"Historical exploit: {match.exploit.name} ({match.exploit.date})"],
        )

    async def analyze_invariants(self, contract) -> list[Finding]:
        """
        Identify and check protocol invariants.
        """
        prompt = f"""Analyze this contract for invariant violations.

**Contract: {contract.name}**
```solidity
{contract.source[:10000]}
```

**Invariant Analysis:**

1. **Identify Invariants** - What properties MUST always hold?
   Examples:
   - Balance invariants: sum(balances) <= totalSupply
   - State invariants: initialized => owner != address(0)
   - Economic invariants: collateral >= debt * ratio

2. **Check Each Invariant** - Can it be violated?
   - What sequence of calls could break it?
   - What edge cases might violate it?
   - Are there reentrancy paths that break it?

3. **Report Violations** - For each breakable invariant:
   - The invariant that's violated
   - How to violate it
   - The impact of violation

Focus on invariants that if broken would cause fund loss or protocol malfunction.
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=20000,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        # Parse findings from response
        findings = self.parse_findings_from_analysis(response.content, contract.name, "INVARIANT")
        return findings

    async def deep_logic_analysis(self, contract) -> list[Finding]:
        """
        Deep business logic analysis with extended thinking.
        """
        prompt = f"""Perform deep security analysis on this contract.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Deep Analysis Checklist:**

1. **Access Control**
   - Who can call each function?
   - Are there privilege escalation paths?
   - Can initialization be front-run?

2. **Value Flows**
   - Where does ETH/tokens enter?
   - Where do they exit?
   - Can an attacker redirect value?

3. **State Machine**
   - What states can the contract be in?
   - Are there invalid state transitions?
   - Can state be manipulated?

4. **External Interactions**
   - What external calls are made?
   - Are return values checked?
   - Reentrancy possible?

5. **Edge Cases**
   - What happens at 0?
   - What happens at max uint256?
   - First user vs subsequent users?
   - Empty arrays/mappings?

6. **Oracle Dependencies**
   - What prices/data is consumed?
   - Can it be manipulated?
   - What if it's stale/wrong?

7. **Flash Loan Scenarios**
   - Can any logic be abused within single tx?
   - Balance-based calculations?
   - Timing assumptions?

For each vulnerability found:
- Severity (Critical/High/Medium/Low)
- Root cause
- Attack path
- Impact
- Fix
"""

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
                max_tokens=8000,
            )

        findings = self.parse_findings_from_analysis(response.content, contract.name, "LOGIC")
        return findings

    async def analyze_economics(self, contract) -> list[Finding]:
        """
        Economic and game theory analysis.
        """
        prompt = f"""Analyze economic incentives and game theory for this contract.

**Contract: {contract.name}**
```solidity
{contract.source[:10000]}
```

**Economic Analysis:**

1. **Actors & Incentives**
   - Who are the participants? (users, LPs, arbitrageurs, keepers)
   - What are their incentives?
   - Any misaligned incentives?

2. **Value Extraction**
   - MEV opportunities?
   - Sandwich attack vectors?
   - JIT liquidity attacks?

3. **Game Theory**
   - Are there dominant strategies that harm the protocol?
   - Nash equilibria?
   - Profitable deviations from intended behavior?

4. **Economic Attacks**
   - Can collateral be manipulated?
   - Can fees be gamed?
   - Can governance be captured?

5. **Death Spirals**
   - Feedback loops that could crash the protocol?
   - Bank run scenarios?
   - Depegging risks?

Report any economic vulnerabilities found.
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=20000,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        findings = self.parse_findings_from_analysis(response.content, contract.name, "ECON")
        return findings

    async def synthesize_attacks(self, findings: list[Finding]) -> list[str]:
        """
        Combine individual findings into attack chains.
        """
        if len(findings) < 2:
            return []

        findings_summary = "\n".join([
            f"- [{f.severity.value}] {f.title}: {f.description[:200]}..."
            for f in findings
        ])

        prompt = f"""Given these individual vulnerabilities, identify attack chains.

**Findings:**
{findings_summary}

**Attack Chain Analysis:**

1. Which findings can be combined?
2. What's the optimal attack sequence?
3. What's the maximum extractable value?
4. What preconditions are needed?

For each attack chain:
- List the steps
- Estimate profit
- Assess feasibility
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=16000,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        # Extract attack chains (simplified)
        chains = []
        for line in response.content.split("\n"):
            if "chain" in line.lower() or "attack" in line.lower():
                chains.append(line.strip())

        return chains[:5]  # Top 5 chains

    def parse_findings_from_analysis(
        self,
        analysis: str,
        contract_name: str,
        prefix: str
    ) -> list[Finding]:
        """
        Parse structured findings from LLM analysis.
        """
        findings = []

        # Look for severity markers
        severity_markers = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        # Simple heuristic: look for sections with severity
        lines = analysis.split("\n")
        current_finding = None
        current_text = []

        for line in lines:
            line_lower = line.lower()

            # Check for new finding
            for marker, severity in severity_markers.items():
                if marker in line_lower and ("vulnerability" in line_lower or "issue" in line_lower or "finding" in line_lower or ":" in line):
                    # Save previous finding
                    if current_finding and current_text:
                        current_finding.description = "\n".join(current_text)
                        findings.append(current_finding)

                    # Start new finding
                    current_finding = Finding(
                        id=f"{contract_name}-{prefix}-{len(findings)+1:02d}",
                        title=line.strip()[:100],
                        severity=severity,
                        vulnerability_type=VulnerabilityType.OTHER,
                        description="",
                        contract=contract_name,
                        confidence=0.7,
                    )
                    current_text = []
                    break
            else:
                if current_finding:
                    current_text.append(line)

        # Save last finding
        if current_finding and current_text:
            current_finding.description = "\n".join(current_text)
            findings.append(current_finding)

        return findings

    def deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.contract, finding.title[:50])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
            Severity.GAS: 5,
        }
        unique.sort(key=lambda f: severity_order.get(f.severity, 5))

        return unique


async def deep_hunt(state: AuditState, ultrathink: bool = True) -> list[Finding]:
    """Convenience function for deep hunting."""
    config = DeepAnalysisConfig(ultrathink=ultrathink)
    hunter = DeepHunterAgent(state=state, config=config)
    return await hunter.run()
