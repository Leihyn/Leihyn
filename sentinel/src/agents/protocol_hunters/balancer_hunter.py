"""
Balancer Hunter - Specialized vulnerability hunting for Balancer V2/V3.

Deep knowledge of:
- Weighted pools and invariant math
- Stable pools (composable stable)
- Boosted pools and linear pools
- Rate providers and manipulation
- Flash loans (zero fee!)
- Read-only reentrancy patterns
"""

from dataclasses import dataclass
from typing import Optional
import re

from rich.console import Console

from ...core.agent import HunterAgent, AgentRole
from ...core.llm import LLMClient, Tool
from ...core.types import AuditState, Finding, Severity, VulnerabilityType

console = Console()


@dataclass
class BalancerHunterConfig:
    """Configuration for Balancer hunting."""
    ultrathink: bool = True
    thinking_budget: int = 24000
    check_rate_providers: bool = True
    check_reentrancy: bool = True
    check_flash_loans: bool = True
    check_pool_math: bool = True


class BalancerHunter(HunterAgent):
    """
    Specialized hunter for Balancer V2/V3 integrations.

    Balancer Architecture:
    - Vault: Single vault holds all pool tokens
    - Pools: Various pool types (Weighted, Stable, Linear, Boosted)
    - Flash Loans: Zero-fee flash loans from vault
    - Rate Providers: External contracts for token rates

    Vulnerability Categories:
    1. Read-Only Reentrancy - getRate() during callbacks
    2. Rate Provider Manipulation - Malicious rate providers
    3. Flash Loan Attacks - Zero-fee flash for manipulation
    4. Pool Math Issues - Invariant calculation edge cases
    5. BPT Price Manipulation - Pool token price attacks
    6. Join/Exit Imbalance - Single-sided liquidity attacks
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "BalancerHunter"
    description = "Deep Balancer V2/V3 vulnerability analysis"

    # Balancer vulnerability patterns
    BALANCER_PATTERNS = {
        "rate_provider_usage": {
            "regex": r"getRate\(\)|IRateProvider|rateProvider",
            "description": "Rate provider usage - CRITICAL for read-only reentrancy",
            "severity": Severity.CRITICAL,
        },
        "vault_callback": {
            "regex": r"onJoinPool|onExitPool|onSwap|flashLoan",
            "description": "Vault callback - check for reentrancy vectors",
            "severity": Severity.HIGH,
        },
        "bpt_price_usage": {
            "regex": r"getActualSupply|getBptPrice|getPoolTokens",
            "description": "BPT price calculation - can be manipulated",
            "severity": Severity.HIGH,
        },
        "invariant_calculation": {
            "regex": r"_calculateInvariant|getInvariant|onSwapGivenIn",
            "description": "Invariant math - check for precision issues",
            "severity": Severity.MEDIUM,
        },
        "flash_loan_receiver": {
            "regex": r"receiveFlashLoan|IFlashLoanRecipient",
            "description": "Flash loan receiver - zero fee, high risk",
            "severity": Severity.HIGH,
        },
    }

    # Balancer invariants
    BALANCER_INVARIANTS = [
        "vault.getPoolTokens() sum >= BPT.totalSupply value",
        "rate providers return consistent values (not manipulable)",
        "flash loans repaid in same transaction",
        "pool invariant maintained after swaps/joins/exits",
        "BPT price reflects underlying token values",
    ]

    # Historical Balancer issues
    BALANCER_HISTORICAL = [
        {
            "name": "Sentiment Read-Only Reentrancy",
            "date": "2023-04",
            "loss": "$1M",
            "cause": "getRate() called during join, returned stale value",
        },
        {
            "name": "Multiple Rate Provider Attacks",
            "date": "2023",
            "loss": "Various",
            "cause": "Rate providers manipulated during callbacks",
        },
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[BalancerHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or BalancerHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Balancer V2/V3 integrations.

**Balancer V2 Architecture:**

1. **Vault Design**
   - Single Vault contract holds ALL tokens for ALL pools
   - Pools are logic contracts, vault is storage
   - Internal balances for gas efficiency
   - Flash loans are FREE (zero fee)

2. **Pool Types**
   - Weighted Pools: x^w * y^(1-w) = k (like Uniswap with weights)
   - Stable Pools: StableSwap invariant for pegged assets
   - Linear Pools: Linear price between bounds
   - Boosted Pools: Nested pools with yield-bearing assets
   - Composable Stable: Stable pools with BPT in pool

3. **Rate Providers**
   - External contracts that return exchange rates
   - Used for yield-bearing tokens (wstETH, rETH, etc.)
   - Called during swaps/joins/exits
   - CRITICAL: Can be exploited via read-only reentrancy

4. **Flash Loans**
   - Zero fee (unlike Aave 0.09%)
   - Can borrow any token from vault
   - Must repay in same transaction
   - Massive attack amplification potential

**CRITICAL: Read-Only Reentrancy Pattern**

This is THE most dangerous Balancer vulnerability:

```
1. Attacker calls join() with ETH
2. During join, vault sends ETH to attacker
3. Attacker's receive() callback executes
4. Attacker calls getRate() on rate provider
5. Rate provider reads vault state (STALE during join!)
6. Attacker exploits stale rate in other protocol
7. Join completes, rate becomes correct
```

Affected functions during callback:
- getRate() on rate providers
- getPoolTokens() on vault
- getBptPrice() calculations
- ANY function reading pool state

**Analysis Approach:**
1. Find all rate provider usages
2. Check if called during callbacks
3. Trace call paths from external protocols
4. Model flash loan amplification
5. Check invariant math edge cases

For each vulnerability:
- Explain Balancer-specific mechanics
- Show attack with realistic values
- Calculate profit (remember: 0% flash loan fee!)
- Provide specific mitigation"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Balancer-specific vulnerabilities."""
        self.log("Starting Balancer V2/V3 analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_balancer_integration(contract.source):
                continue

            self.log(f"Analyzing Balancer integration: {contract.name}", style="cyan")

            # Pattern detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep analysis
            if self.config.ultrathink:
                # Rate provider analysis (CRITICAL)
                if self.config.check_rate_providers:
                    self.log("  Analyzing rate provider vectors...", style="dim")
                    rate_findings = await self._analyze_rate_providers(contract)
                    findings.extend(rate_findings)

                # Read-only reentrancy analysis
                if self.config.check_reentrancy:
                    self.log("  Analyzing read-only reentrancy...", style="dim")
                    reent_findings = await self._analyze_reentrancy(contract)
                    findings.extend(reent_findings)

                # Flash loan analysis
                if self.config.check_flash_loans:
                    self.log("  Analyzing flash loan vectors...", style="dim")
                    flash_findings = await self._analyze_flash_loans(contract)
                    findings.extend(flash_findings)

        self.log(f"Found {len(findings)} Balancer-specific issues", style="bold green")
        return findings

    def _is_balancer_integration(self, source: str) -> bool:
        """Check if contract integrates with Balancer."""
        indicators = [
            "IVault",
            "IBalancer",
            "IPool",
            "IRateProvider",
            "getPoolTokens",
            "joinPool",
            "exitPool",
            "flashLoan",
            "onJoinPool",
            "onExitPool",
            "getRate",
            "BALANCER",
        ]
        return any(ind in source for ind in indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known Balancer patterns."""
        findings = []

        for pattern_name, pattern_info in self.BALANCER_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-BAL-{pattern_name}-{line_num}",
                    title=f"Balancer: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.REENTRANCY_READ_ONLY if "rate" in pattern_name.lower() else VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern:** {pattern_info["description"]}

**Location:** Line {line_num}
**Code:** `{match.group()[:100]}`

**WARNING:** Balancer rate providers are a common source of read-only reentrancy vulnerabilities.
Manual review required to confirm safety.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.7 if "rate" in pattern_name.lower() else 0.6,
                ))

        return findings

    async def _analyze_rate_providers(self, contract) -> list[Finding]:
        """Deep analysis of rate provider usage."""
        prompt = f"""Analyze this Balancer integration for rate provider vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**CRITICAL: Rate Provider Read-Only Reentrancy**

This is the most dangerous Balancer pattern. Check:

1. **getRate() Usage**
   - Where is getRate() called?
   - Is it called during any callback?
   - Can the rate be stale during the call?

2. **Call Path Analysis**
   - Trace all paths that call getRate()
   - Check if any path originates from vault callbacks
   - Check if any path can be reached during join/exit/swap

3. **Value Dependencies**
   - What decisions are made based on rate?
   - Collateral valuation?
   - Share price calculation?
   - Swap amounts?

4. **Historical Context**
   - Sentiment Protocol: $1M lost to this exact pattern
   - Many other protocols affected
   - Balancer recommends VaultReentrancyLib

5. **Mitigation Check**
   - Is VaultReentrancyLib used?
   - Is reentrancy lock in place?
   - Is rate cached before operations?

If getRate() is called anywhere that can be reached during a Balancer callback,
this is likely CRITICAL severity.

Provide specific attack scenario with profit calculation."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "RATE")

    async def _analyze_reentrancy(self, contract) -> list[Finding]:
        """Deep analysis of read-only reentrancy vectors."""
        prompt = f"""Analyze this contract for Balancer read-only reentrancy.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Read-Only Reentrancy Analysis:**

Beyond rate providers, check these patterns:

1. **getPoolTokens() During Callback**
   - Returns stale balances during join/exit
   - Used for price calculations
   - Can be exploited for arbitrage

2. **getBptPrice() / getActualSupply()**
   - BPT price stale during operations
   - Used for collateral valuation
   - Inflation/deflation attacks

3. **View Function Dependencies**
   - ANY view function reading pool state
   - Check if protocol reads during callback
   - Even indirect reads via other contracts

4. **Cross-Protocol Flows**
   - Does this contract call other protocols?
   - Do those protocols read Balancer state?
   - Transitive reentrancy paths?

5. **ETH Callbacks**
   - receive() or fallback() functions
   - What happens during ETH transfer?
   - Can attacker trigger reads?

Map all potential reentrancy paths and assess exploitability."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "REENT")

    async def _analyze_flash_loans(self, contract) -> list[Finding]:
        """Deep analysis of flash loan attack vectors."""
        prompt = f"""Analyze this contract for Balancer flash loan vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Balancer Flash Loan Analysis:**

Remember: Balancer flash loans are FREE (0% fee)!

1. **Flash Loan Amplification**
   - What attacks become profitable with zero-fee flash?
   - Oracle manipulation?
   - Governance attacks?
   - Liquidation triggering?

2. **Flash + Rate Provider**
   - Flash loan to manipulate rate provider input
   - Then exploit protocol reading stale rate
   - Calculate max extractable value

3. **Flash + Join/Exit**
   - Flash loan tokens
   - Join pool during callback
   - Manipulate pool state
   - Exit at profit

4. **Flash Loan Callback Security**
   - Is receiveFlashLoan implemented?
   - Are repayments verified?
   - Can callback be exploited?

5. **Multi-Token Flash**
   - Flash multiple tokens simultaneously
   - Complex manipulation scenarios
   - Cross-pool attacks

Calculate attack profitability given ZERO flash loan fees."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "FLASH")

    def _parse_findings(self, response: str, contract_name: str, prefix: str) -> list[Finding]:
        """Parse findings from response."""
        findings = []
        severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

        for i, block in enumerate(response.split('\n\n')):
            block_lower = block.lower()
            for marker, severity in severity_map.items():
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'attack', 'reentrancy']):
                    vuln_type = VulnerabilityType.REENTRANCY_READ_ONLY if 'reentrancy' in block_lower or 'rate' in block_lower else VulnerabilityType.FLASH_LOAN

                    findings.append(Finding(
                        id=f"{contract_name}-BAL-{prefix}-{i:02d}",
                        title=f"Balancer: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=vuln_type,
                        description=block,
                        contract=contract_name,
                        confidence=0.8,
                        references=["Balancer specialized analysis", "Sentiment Protocol incident"],
                    ))
                    break

        return findings
