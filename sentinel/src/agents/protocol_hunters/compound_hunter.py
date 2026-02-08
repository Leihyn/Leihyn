"""
Compound V3 (Comet) Hunter - Specialized vulnerability hunting for Compound V3.

Deep knowledge of:
- Comet single-asset market design
- Collateral absorption mechanics
- Interest rate model
- Liquidation with absorb()
- Supply/borrow caps
- Pause guardian mechanics
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
class CompoundHunterConfig:
    """Configuration for Compound V3 hunting."""
    ultrathink: bool = True
    thinking_budget: int = 24000
    check_collateral: bool = True
    check_liquidation: bool = True
    check_interest_rate: bool = True
    check_governance: bool = True


class CompoundV3Hunter(HunterAgent):
    """
    Specialized hunter for Compound V3 (Comet) integrations.

    Compound V3 Architecture:
    - Single borrowable asset per Comet instance
    - Multiple collateral assets supported
    - Collateral cannot be borrowed, only used as collateral
    - Absorption mechanism for liquidations
    - Reserves accumulate from interest spread

    Vulnerability Categories:
    1. Collateral Factor Manipulation - LTV/LT edge cases
    2. Absorption Attacks - Unfair liquidation conditions
    3. Interest Rate Exploitation - Rate model edge cases
    4. Price Feed Issues - Oracle dependencies
    5. Supply Cap Bypass - Circumventing limits
    6. Governance Attacks - Proposal manipulation
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "CompoundV3Hunter"
    description = "Deep Compound V3 (Comet) vulnerability analysis"

    # Compound V3 vulnerability patterns
    COMPOUND_PATTERNS = {
        "unsafe_borrow_balance": {
            "regex": r"borrowBalanceOf|getBorrowBalance|borrowBalance",
            "description": "Borrow balance read - check for interest accrual timing",
            "severity": Severity.MEDIUM,
        },
        "collateral_factor_reliance": {
            "regex": r"getAssetInfo|collateralFactor|liquidateCollateralFactor",
            "description": "Collateral factor usage - can change via governance",
            "severity": Severity.MEDIUM,
        },
        "supply_cap_check": {
            "regex": r"supplyCap|totalSupply.*cap|isSupplyPaused",
            "description": "Supply cap interaction - check for race conditions",
            "severity": Severity.LOW,
        },
        "absorb_liquidation": {
            "regex": r"absorb\(|isLiquidatable|getAssetInfoByAddress",
            "description": "Absorption/liquidation logic - check for manipulation",
            "severity": Severity.HIGH,
        },
        "base_token_operations": {
            "regex": r"baseToken|supply\(|withdraw\(",
            "description": "Base token operations - check for reentrancy",
            "severity": Severity.MEDIUM,
        },
    }

    # Compound V3 invariants
    COMPOUND_INVARIANTS = [
        "sum(collateral_values) * collateral_factor >= borrow_balance for healthy positions",
        "totalSupply <= supplyCap for each asset",
        "totalBorrow <= totalSupply (utilization <= 100%)",
        "reserves increase monotonically (absent governance action)",
        "absorption only possible when position is liquidatable",
        "base token balance >= total borrows (solvency)",
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[CompoundHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or CompoundHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Compound V3 (Comet) integrations.

**Compound V3 Architecture:**

1. **Single Base Asset Design**
   - Each Comet has ONE borrowable base asset (e.g., USDC)
   - Multiple collateral assets (ETH, WBTC, etc.)
   - Collateral CANNOT be borrowed, only base asset
   - Simpler than V2, but different attack surface

2. **Collateral Mechanics**
   - Each collateral has: priceFeed, borrowCollateralFactor, liquidateCollateralFactor
   - borrowCollateralFactor < liquidateCollateralFactor (buffer zone)
   - Collateral can be seized during absorption

3. **Absorption (Liquidation)**
   - absorb(absorber, accounts[]) called by anyone
   - Protocol takes collateral, covers bad debt
   - No liquidation bonus to caller (absorbed by protocol)
   - Reserves may go negative (bad debt)

4. **Interest Rate Model**
   - Utilization-based: supplyRate and borrowRate
   - Kink model with base rate + slope before/after kink
   - Interest accrues per second via accrue()

5. **Price Feeds**
   - Chainlink oracles with staleness check
   - Price scale normalization
   - Can be updated by governance

**Common Compound V3 Vulnerabilities:**

1. **Collateral Factor Edge Cases**
   - Position exactly at liquidation threshold
   - Governance changes factor while positions exist
   - Multi-collateral positions with mixed factors

2. **Absorption Timing**
   - Front-running absorption calls
   - Self-absorption scenarios
   - Partial absorption effects

3. **Interest Accrual Issues**
   - accrue() not called before operations
   - Interest rate manipulation via large supply/borrow
   - Timestamp manipulation

4. **Price Feed Dependencies**
   - Stale price acceptance
   - Price deviation between accrual and operation
   - Oracle manipulation cost vs profit

5. **Supply Cap Races**
   - Multiple deposits racing to cap
   - Withdrawal and re-deposit to bypass
   - Flash loan + supply attacks

For each vulnerability:
- Explain Compound V3 specific mechanics
- Show attack with realistic numbers
- Calculate profitability
- Provide specific fix"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Compound V3 specific vulnerabilities."""
        self.log("Starting Compound V3 (Comet) analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_compound_integration(contract.source):
                continue

            self.log(f"Analyzing Compound V3 integration: {contract.name}", style="cyan")

            # Pattern detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep ultrathink analysis
            if self.config.ultrathink:
                deep_findings = await self._deep_compound_analysis(contract)
                findings.extend(deep_findings)

        self.log(f"Found {len(findings)} Compound V3 issues", style="bold green")
        return findings

    def _is_compound_integration(self, source: str) -> bool:
        """Check if contract integrates with Compound V3."""
        indicators = [
            "IComet",
            "CometCore",
            "CometExt",
            "absorb",
            "buyCollateral",
            "getAssetInfo",
            "isLiquidatable",
            "borrowBalanceOf",
            "baseToken",
        ]
        return any(ind in source for ind in indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known Compound V3 patterns."""
        findings = []

        for pattern_name, pattern_info in self.COMPOUND_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-COMPV3-{pattern_name}-{line_num}",
                    title=f"Compound V3: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern:** {pattern_info["description"]}

**Location:** Line {line_num}
**Code:** `{match.group()[:100]}`""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.6,
                ))

        return findings

    async def _deep_compound_analysis(self, contract) -> list[Finding]:
        """Deep Compound V3 analysis with ultrathink."""
        prompt = f"""Analyze this Compound V3 (Comet) integration for vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Compound V3 Invariants to Check:**
{chr(10).join(f"- {inv}" for inv in self.COMPOUND_INVARIANTS)}

**Deep Analysis Required:**

1. **Collateral Management**
   - Are collateral factors correctly applied?
   - Edge cases with multiple collateral types?
   - Governance-induced collateral factor changes?

2. **Absorption/Liquidation**
   - Can absorption be front-run profitably?
   - Self-absorption scenarios?
   - Bad debt accumulation risks?

3. **Interest Accrual**
   - Is accrue() called before reads?
   - Interest rate manipulation vectors?
   - Timestamp dependencies?

4. **Oracle Integration**
   - Price feed staleness handling?
   - Price deviation during operations?
   - Oracle manipulation cost analysis?

5. **Supply/Borrow Caps**
   - Cap bypass via flash loans?
   - Race conditions at cap limits?
   - Multi-transaction attacks?

6. **Cross-Protocol Risks**
   - Integration with other DeFi protocols?
   - Reentrancy during callbacks?
   - State inconsistency during operations?

For each finding:
- Severity with justification
- Step-by-step attack path
- Realistic profit calculation
- Specific mitigation

Be thorough. Think adversarially."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name)

    def _parse_findings(self, response: str, contract_name: str) -> list[Finding]:
        """Parse findings from response."""
        findings = []
        severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

        for i, block in enumerate(response.split('\n\n')):
            block_lower = block.lower()
            for marker, severity in severity_map.items():
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'finding', 'attack']):
                    findings.append(Finding(
                        id=f"{contract_name}-COMPV3-DEEP-{i:02d}",
                        title=f"Compound V3: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                        description=block,
                        contract=contract_name,
                        confidence=0.75,
                    ))
                    break

        return findings
