"""
Lido Hunter - Specialized vulnerability hunting for Lido stETH/wstETH integrations.

Deep knowledge of:
- stETH rebasing mechanics
- wstETH wrapper design
- Oracle and rate calculations
- Withdrawal queue mechanics
- Staking router
- Integration pitfalls
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
class LidoHunterConfig:
    """Configuration for Lido hunting."""
    ultrathink: bool = True
    thinking_budget: int = 24000
    check_rebasing: bool = True
    check_rate: bool = True
    check_withdrawals: bool = True
    check_oracle: bool = True


class LidoHunter(HunterAgent):
    """
    Specialized hunter for Lido stETH/wstETH integrations.

    Lido Architecture:
    - stETH: Rebasing token representing staked ETH
    - wstETH: Non-rebasing wrapper for stETH
    - Oracle: Reports beacon chain rewards
    - Withdrawal Queue: For unstaking ETH

    Vulnerability Categories:
    1. Rebasing Token Issues - Balance changes between transactions
    2. Rate Manipulation - stETH/ETH rate exploitation
    3. Share Accounting Errors - Using balanceOf vs shares
    4. Oracle Delays - Stale rate during operations
    5. Withdrawal Queue Attacks - Queue manipulation
    6. Integration Incompatibility - Protocols not handling rebasing
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "LidoHunter"
    description = "Deep Lido stETH/wstETH vulnerability analysis"

    # Lido vulnerability patterns
    LIDO_PATTERNS = {
        "steth_balance_caching": {
            "regex": r"stETH\.balanceOf\([^)]+\).*\n.*stETH\.(transfer|approve)",
            "description": "stETH balance cached before operation - rebasing issue",
            "severity": Severity.HIGH,
        },
        "steth_transfer_amount": {
            "regex": r"stETH\.transfer\([^,]+,\s*amount\)",
            "description": "stETH transfer with fixed amount - may transfer wrong shares",
            "severity": Severity.MEDIUM,
        },
        "shares_vs_balance": {
            "regex": r"balanceOf|sharesOf|getSharesByPooledEth|getPooledEthByShares",
            "description": "Balance/shares usage - verify correct function used",
            "severity": Severity.MEDIUM,
        },
        "rate_usage": {
            "regex": r"stEthPerToken|tokensPerStEth|getRate|exchangeRate",
            "description": "Rate calculation - check for manipulation/staleness",
            "severity": Severity.HIGH,
        },
        "withdrawal_request": {
            "regex": r"requestWithdrawals|claimWithdrawals|WithdrawalQueue",
            "description": "Withdrawal queue interaction - check for front-running",
            "severity": Severity.MEDIUM,
        },
    }

    # Lido invariants
    LIDO_INVARIANTS = [
        "sum(shares) * rate = totalPooledEther",
        "wstETH.balanceOf(user) = stETH.sharesOf(wstETH) for user",
        "stETH can rebase positive (rewards) or negative (slashing)",
        "wstETH never rebases - constant shares",
        "withdrawal queue is FIFO",
        "rate can only change on oracle report",
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[LidoHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or LidoHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Lido stETH/wstETH integrations.

**Lido Architecture:**

1. **stETH - Rebasing Token**
   - Balance changes daily based on beacon chain rewards
   - balanceOf(user) = sharesOf(user) * totalPooledEther / totalShares
   - Share count is constant, balance varies with rate
   - Can rebase UP (rewards) or DOWN (slashing)

2. **wstETH - Wrapped stETH**
   - Non-rebasing wrapper for stETH
   - Constant balance, represents underlying stETH shares
   - 1 wstETH = stETH.getPooledEthByShares(1 share)
   - Rate increases over time as staking rewards accrue

3. **Exchange Rate**
   - stETH/ETH rate determined by oracle reports
   - Updated ~daily after beacon chain finalization
   - Small deviations from 1:1 due to market conditions
   - Larger deviations during black swan events

4. **Withdrawal Queue**
   - Request withdrawal: lock stETH, get NFT
   - Wait for processing (days to weeks)
   - Claim ETH when ready
   - FIFO ordering

**CRITICAL Lido Integration Issues:**

1. **Rebasing Balance Problem**
   ```solidity
   // WRONG - balance may change between lines!
   uint256 balance = stETH.balanceOf(user);
   stETH.transfer(recipient, balance);

   // RIGHT - use shares or transferAll
   uint256 shares = stETH.sharesOf(user);
   stETH.transferShares(recipient, shares);
   ```

2. **Transfer Amount Mismatch**
   - stETH.transfer(to, amount) transfers shares worth `amount`
   - But actual transfer may be slightly different due to rounding
   - Use transferShares for precision

3. **Rate Staleness**
   - Rate only updates on oracle report
   - Can be stale for hours
   - Protocols reading rate may use stale values
   - Front-running oracle updates

4. **wstETH vs stETH Confusion**
   - wstETH balance is constant
   - stETH balance changes
   - Using wrong token type causes bugs

5. **Slashing Events**
   - stETH can decrease in value (negative rebase)
   - Protocols must handle this
   - Collateral may become undercollateralized

For each vulnerability:
- Explain Lido-specific mechanics
- Show concrete attack scenario
- Calculate impact
- Provide specific fix using correct Lido functions"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Lido-specific vulnerabilities."""
        self.log("Starting Lido stETH/wstETH analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_lido_integration(contract.source):
                continue

            self.log(f"Analyzing Lido integration: {contract.name}", style="cyan")

            # Pattern detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep analysis
            if self.config.ultrathink:
                if self.config.check_rebasing:
                    self.log("  Analyzing rebasing issues...", style="dim")
                    rebase_findings = await self._analyze_rebasing(contract)
                    findings.extend(rebase_findings)

                if self.config.check_rate:
                    self.log("  Analyzing rate manipulation...", style="dim")
                    rate_findings = await self._analyze_rate(contract)
                    findings.extend(rate_findings)

        self.log(f"Found {len(findings)} Lido-specific issues", style="bold green")
        return findings

    def _is_lido_integration(self, source: str) -> bool:
        """Check if contract integrates with Lido."""
        indicators = [
            "IstETH",
            "IWstETH",
            "ILido",
            "stETH",
            "wstETH",
            "getSharesByPooledEth",
            "getPooledEthByShares",
            "sharesOf",
            "transferShares",
            "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",  # stETH address
            "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",  # wstETH address
        ]
        return any(ind in source for ind in indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known Lido patterns."""
        findings = []

        for pattern_name, pattern_info in self.LIDO_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source, re.MULTILINE | re.DOTALL))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-LIDO-{pattern_name}-{line_num}",
                    title=f"Lido: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.ACCOUNTING_ERROR,
                    description=f"""**Pattern:** {pattern_info["description"]}

**Location:** Line {line_num}
**Code:** `{match.group()[:150]}`

**WARNING:** stETH is a rebasing token. Balances change between transactions.
Use shares-based operations for precise accounting.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.7,
                ))

        return findings

    async def _analyze_rebasing(self, contract) -> list[Finding]:
        """Deep analysis of rebasing token issues."""
        prompt = f"""Analyze this Lido integration for rebasing token vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Rebasing Token Analysis:**

1. **Balance Caching Issues**
   - Is balanceOf() result cached and used later?
   - Can balance change between cache and use?
   - Attack: Sandwich with rebase event

2. **Transfer Amount Precision**
   - Is transfer(amount) used with exact amount?
   - stETH transfer may not transfer exact amount due to share rounding
   - Use transferShares for precision

3. **Accounting Errors**
   - Are balances compared across transactions?
   - Is share-based accounting used?
   - Can rounding errors accumulate?

4. **Slashing Handling**
   - What if stETH rebases DOWN (slashing)?
   - Are collateral ratios maintained?
   - Emergency procedures?

5. **wstETH vs stETH Usage**
   - Is the right token type used?
   - wstETH for storage, stETH for rebasing exposure
   - Confusion between the two?

Provide specific attack scenarios with impact calculation."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "REBASE")

    async def _analyze_rate(self, contract) -> list[Finding]:
        """Deep analysis of rate manipulation."""
        prompt = f"""Analyze this Lido integration for rate-related vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Rate Manipulation Analysis:**

1. **Rate Staleness**
   - How is stETH/ETH rate obtained?
   - Is staleness checked?
   - Can stale rate be exploited?

2. **Oracle Front-Running**
   - Can oracle updates be front-run?
   - What operations depend on rate?
   - Attack: Sandwich oracle update

3. **Rate in Calculations**
   - Is rate used for collateral valuation?
   - Share price calculations?
   - Can manipulation affect these?

4. **Cross-Protocol Rate**
   - Does code read rate from other protocols?
   - DEX prices vs oracle rate?
   - Arbitrage opportunities?

5. **Rate Bounds**
   - Is rate bounded within acceptable range?
   - What if rate deviates significantly?
   - Emergency handling?

Calculate realistic attack profits."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "RATE")

    def _parse_findings(self, response: str, contract_name: str, prefix: str) -> list[Finding]:
        """Parse findings from response."""
        findings = []
        severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

        for i, block in enumerate(response.split('\n\n')):
            block_lower = block.lower()
            for marker, severity in severity_map.items():
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'attack', 'rebase', 'steth']):
                    findings.append(Finding(
                        id=f"{contract_name}-LIDO-{prefix}-{i:02d}",
                        title=f"Lido: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.ACCOUNTING_ERROR,
                        description=block,
                        contract=contract_name,
                        confidence=0.75,
                        references=["Lido specialized analysis"],
                    ))
                    break

        return findings
