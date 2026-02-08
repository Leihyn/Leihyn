"""
GMX Hunter - Specialized vulnerability hunting for GMX V2 perpetuals.

Deep knowledge of:
- Perpetual trading mechanics
- GLP/GM token economics
- Price impact calculations
- Funding rate manipulation
- Keeper bot interactions
- Oracle latency exploitation
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
class GMXHunterConfig:
    """Configuration for GMX hunting."""
    ultrathink: bool = True
    thinking_budget: int = 24000  # Higher for complex perp logic
    check_price_impact: bool = True
    check_funding_rate: bool = True
    check_liquidations: bool = True
    check_keeper_mev: bool = True
    check_oracle_latency: bool = True


class GMXHunter(HunterAgent):
    """
    Specialized hunter for GMX perpetual protocol integrations.

    GMX V2 Architecture:
    - Markets: Long/short trading pairs with configurable parameters
    - GM Tokens: Liquidity provider tokens per market
    - Positions: Leveraged long/short positions
    - Orders: Market, limit, trigger orders via keepers
    - Oracles: Chainlink + signed prices from GMX backend

    Vulnerability Categories:
    1. Price Impact Manipulation - Gaming the price impact formula
    2. Funding Rate Exploitation - Manipulating funding payments
    3. Liquidation Attacks - Triggering unfair liquidations
    4. Oracle Latency - Front-running price updates
    5. Keeper MEV - Extracting value from order execution
    6. GM Token Attacks - LP share manipulation
    7. ADL Manipulation - Auto-deleveraging gaming
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "GMXHunter"
    description = "Deep GMX perpetual protocol vulnerability analysis"

    # GMX-specific vulnerability patterns
    GMX_PATTERNS = {
        "price_impact_gaming": {
            "regex": r"getPriceImpact|priceImpactUsd|applyPriceImpact",
            "description": "Price impact calculation - can be gamed with position sizing",
            "severity": Severity.HIGH,
        },
        "funding_rate_manipulation": {
            "regex": r"getFundingFee|fundingFactor|borrowingFactor",
            "description": "Funding rate usage - check for manipulation vectors",
            "severity": Severity.MEDIUM,
        },
        "unsafe_oracle_usage": {
            "regex": r"getPrice\(|getPrimaryPrice|getSecondaryPrice",
            "description": "Oracle price usage - check for latency exploitation",
            "severity": Severity.HIGH,
        },
        "liquidation_threshold": {
            "regex": r"isLiquidatable|getLiquidationPrice|minCollateralUsd",
            "description": "Liquidation logic - check for manipulation",
            "severity": Severity.HIGH,
        },
        "position_size_limits": {
            "regex": r"maxPositionSize|maxOpenInterest|reserveFactor",
            "description": "Position limits - check for bypass",
            "severity": Severity.MEDIUM,
        },
        "keeper_order_execution": {
            "regex": r"executeOrder|OrderHandler|executeDeposit|executeWithdrawal",
            "description": "Keeper execution - MEV extraction possible",
            "severity": Severity.MEDIUM,
        },
    }

    # GMX invariants that must hold
    GMX_INVARIANTS = [
        "totalLongOpenInterest + totalShortOpenInterest <= maxOpenInterest",
        "position.collateralUsd >= position.sizeUsd * minCollateralFactor",
        "GM.totalSupply * price >= poolValue (within slippage)",
        "funding payments are zero-sum between longs and shorts",
        "liquidation only when position health < threshold",
        "price impact is bounded and predictable",
        "ADL triggers only at extreme imbalance",
        "keeper can only execute valid orders",
    ]

    # Known GMX exploits/issues
    GMX_HISTORICAL_ISSUES = [
        {
            "name": "Price manipulation via large positions",
            "description": "Large positions can move the mark price for liquidations",
            "mitigation": "Check position size vs market liquidity",
        },
        {
            "name": "Oracle front-running",
            "description": "Keepers can see price updates before execution",
            "mitigation": "Check execution price vs oracle price bounds",
        },
        {
            "name": "Funding rate imbalance",
            "description": "Extreme long/short imbalance can be exploited",
            "mitigation": "Check funding rate caps and smoothing",
        },
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[GMXHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or GMXHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an elite perpetual protocol security researcher specializing in GMX.

**GMX V2 Deep Knowledge:**

1. **Market Structure**
   - Each market has long/short tokens and index token
   - GM tokens represent LP shares in specific markets
   - Pool value = long collateral + short collateral + PnL
   - Price impact based on position size vs available liquidity

2. **Position Mechanics**
   - Leverage = sizeUsd / collateralUsd
   - Liquidation when collateral < minCollateralFactor * size
   - Funding rate: longs pay shorts (or vice versa) based on OI imbalance
   - Borrowing fee: paid by all positions to LPs

3. **Oracle System**
   - Primary: Chainlink feeds with heartbeat
   - Secondary: Signed prices from GMX backend
   - Price bounds: Must be within deviation threshold
   - Latency: ~1-2 blocks typical

4. **Order Execution**
   - Orders queued, executed by keepers
   - Execution price = oracle price at execution time
   - Price impact applied based on position size
   - Slippage protection via acceptable price

5. **Known Attack Vectors**
   - Oracle latency arbitrage (front-run price updates)
   - Price impact gaming (split orders to reduce impact)
   - Liquidation hunting (manipulate mark price)
   - Funding rate manipulation (create imbalance)
   - Keeper MEV (reorder executions)
   - GM token share inflation (first depositor)

**Analysis Approach:**
1. Map all price dependencies (where is price used?)
2. Trace value flows (who pays, who receives?)
3. Model adversarial positions (what if attacker controls X?)
4. Check timing assumptions (what if delayed/front-run?)
5. Verify economic constraints (are limits enforced?)

For each vulnerability:
- Explain GMX-specific mechanics involved
- Show exact attack with realistic numbers
- Calculate attacker profit vs cost
- Reference similar perp protocol exploits
- Provide GMX-specific fix"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for GMX-specific vulnerabilities."""
        self.log("Starting GMX perpetual protocol analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_gmx_integration(contract.source):
                continue

            self.log(f"Analyzing GMX integration: {contract.name}", style="cyan")

            # Pattern detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep ultrathink analysis
            if self.config.ultrathink:
                # Price impact analysis
                if self.config.check_price_impact:
                    self.log("  Analyzing price impact mechanics...", style="dim")
                    impact_findings = await self._analyze_price_impact(contract)
                    findings.extend(impact_findings)

                # Funding rate analysis
                if self.config.check_funding_rate:
                    self.log("  Analyzing funding rate mechanics...", style="dim")
                    funding_findings = await self._analyze_funding_rate(contract)
                    findings.extend(funding_findings)

                # Liquidation analysis
                if self.config.check_liquidations:
                    self.log("  Analyzing liquidation mechanics...", style="dim")
                    liq_findings = await self._analyze_liquidations(contract)
                    findings.extend(liq_findings)

                # Oracle latency analysis
                if self.config.check_oracle_latency:
                    self.log("  Analyzing oracle latency vectors...", style="dim")
                    oracle_findings = await self._analyze_oracle_latency(contract)
                    findings.extend(oracle_findings)

                # Keeper MEV analysis
                if self.config.check_keeper_mev:
                    self.log("  Analyzing keeper MEV vectors...", style="dim")
                    keeper_findings = await self._analyze_keeper_mev(contract)
                    findings.extend(keeper_findings)

        self.log(f"Found {len(findings)} GMX-specific issues", style="bold green")
        return findings

    def _is_gmx_integration(self, source: str) -> bool:
        """Check if contract integrates with GMX."""
        indicators = [
            "IGmx",
            "IExchangeRouter",
            "IReader",
            "IMarket",
            "IPosition",
            "GLP",
            "GMX",
            "createOrder",
            "executeOrder",
            "getPosition",
            "getMarket",
        ]
        return any(ind in source for ind in indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known GMX vulnerability patterns."""
        findings = []

        for pattern_name, pattern_info in self.GMX_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-GMX-{pattern_name}-{line_num}",
                    title=f"GMX Pattern: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern Detected:** {pattern_info["description"]}

**Location:** Line {line_num}
**Code:** `{match.group()[:100]}`

This pattern requires careful review for GMX-specific vulnerabilities.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.6,
                ))

        return findings

    async def _analyze_price_impact(self, contract) -> list[Finding]:
        """Deep analysis of price impact mechanics."""
        prompt = f"""Analyze this GMX integration for price impact vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Price Impact Attack Vectors:**

1. **Split Order Attack**
   - Attacker splits large order into many small orders
   - Each small order has minimal price impact
   - Net result: better execution than single large order
   - Q: Does the code allow order splitting? Time restrictions?

2. **Price Impact Timing**
   - Price impact depends on pool state at execution
   - Attacker can manipulate pool state before execution
   - Q: Is price impact calculated at order creation or execution?

3. **Cross-Market Manipulation**
   - Position in market A affects prices in market B
   - Attacker profits from correlation
   - Q: Are cross-market effects considered?

4. **Liquidity Concentration Attack**
   - Attacker provides liquidity, takes positions
   - Earns fees while minimizing own price impact
   - Q: Are there LP position restrictions?

Analyze for each vector. Provide specific attack scenarios with numbers."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "PRICE_IMPACT")

    async def _analyze_funding_rate(self, contract) -> list[Finding]:
        """Deep analysis of funding rate mechanics."""
        prompt = f"""Analyze this GMX integration for funding rate vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Funding Rate Attack Vectors:**

1. **Imbalance Manipulation**
   - Create extreme long/short imbalance
   - Force high funding rate in one direction
   - Profit from funding payments
   - Q: Are there position limits? OI caps?

2. **Funding Rate Arbitrage**
   - Open opposite positions on different venues
   - Collect funding on one, pay on other
   - Net positive if rates differ
   - Q: Is funding rate calculation standard?

3. **Timing Attacks**
   - Open position just before funding payment
   - Close just after receiving payment
   - Q: Is there a minimum holding period?

4. **Flash Loan + Funding**
   - Flash loan to create temporary imbalance
   - Affect funding rate calculation
   - Q: Is funding rate time-weighted?

Analyze for each vector with specific attack scenarios."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "FUNDING")

    async def _analyze_liquidations(self, contract) -> list[Finding]:
        """Deep analysis of liquidation mechanics."""
        prompt = f"""Analyze this GMX integration for liquidation vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Liquidation Attack Vectors:**

1. **Mark Price Manipulation**
   - Manipulate oracle/mark price temporarily
   - Trigger liquidations at unfair prices
   - Profit as liquidator or counter-position
   - Q: How is mark price calculated? Manipulation cost?

2. **Liquidation Front-Running**
   - See pending liquidation in mempool
   - Front-run to become liquidator
   - Or manipulate price to cause liquidation
   - Q: Is liquidation protected from front-running?

3. **Partial Liquidation Gaming**
   - Partial liquidations may leave dust
   - Dust positions can be exploited
   - Q: Is there minimum position size after partial liq?

4. **Liquidation Bonus Extraction**
   - Liquidation bonus may exceed losses
   - Self-liquidation profitable in some cases
   - Q: Is liquidation bonus bounded correctly?

5. **Cascade Liquidations**
   - One liquidation triggers more
   - Price impact of liquidations compounds
   - Q: Are cascade protections in place?

Analyze each vector with specific scenarios."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "LIQUIDATION")

    async def _analyze_oracle_latency(self, contract) -> list[Finding]:
        """Deep analysis of oracle latency exploitation."""
        prompt = f"""Analyze this GMX integration for oracle latency vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Oracle Latency Attack Vectors:**

1. **Front-Running Price Updates**
   - See Chainlink update in mempool
   - Execute order before update hits
   - Profit from stale price
   - Q: Is there price freshness check? Delay mechanism?

2. **Signed Price Manipulation**
   - GMX uses signed prices from backend
   - Backend could be compromised/delayed
   - Q: Are signed prices validated? Expiry?

3. **Cross-Exchange Arbitrage**
   - GMX price lags CEX price
   - Arb between GMX and CEX
   - Q: Is there price band protection?

4. **Oracle Failure Scenarios**
   - What if oracle goes down?
   - What if price is stale?
   - Q: Is there fallback? Staleness check?

5. **Multi-Oracle Inconsistency**
   - Primary vs secondary oracle disagree
   - Which price is used?
   - Q: Is oracle selection manipulable?

Analyze each vector with realistic scenarios."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "ORACLE")

    async def _analyze_keeper_mev(self, contract) -> list[Finding]:
        """Deep analysis of keeper MEV extraction."""
        prompt = f"""Analyze this GMX integration for keeper MEV vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:12000]}
```

**Keeper MEV Attack Vectors:**

1. **Order Reordering**
   - Keeper chooses execution order
   - Can sandwich user orders
   - Q: Is execution order enforced? FIFO?

2. **Execution Timing**
   - Keeper chooses when to execute
   - Can wait for favorable price
   - Q: Is there execution deadline? Penalty?

3. **Selective Execution**
   - Keeper executes only profitable orders
   - User orders stuck in queue
   - Q: Are all orders executed? Incentives?

4. **Keeper Collusion**
   - Multiple keepers coordinate
   - Share MEV profits
   - Q: Is keeper set decentralized?

5. **Keeper Front-Running**
   - Keeper sees order before execution
   - Takes opposite position
   - Q: Is there keeper staking? Slashing?

Analyze each vector with realistic scenarios."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name, "KEEPER")

    def _parse_findings(self, response: str, contract_name: str, prefix: str) -> list[Finding]:
        """Parse findings from analysis response."""
        findings = []
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for i, block in enumerate(response.split('\n\n')):
            block_lower = block.lower()
            for marker, severity in severity_map.items():
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'attack', 'exploit']):
                    findings.append(Finding(
                        id=f"{contract_name}-GMX-{prefix}-{i:02d}",
                        title=f"GMX: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                        description=block,
                        contract=contract_name,
                        confidence=0.75,
                        references=["GMX specialized analysis"],
                    ))
                    break

        return findings
