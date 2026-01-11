"""
Aave V3 Hunter - Specialized vulnerability hunting for Aave V3 integrations.

Deep knowledge of:
- Aave V3 Pool, aTokens, debtTokens
- eMode configurations and risks
- Interest rate model edge cases
- Liquidation threshold manipulation
- Flash loan callback patterns
- Supply/borrow cap interactions
- Isolation mode vulnerabilities
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
class AaveHunterConfig:
    """Configuration for Aave V3 hunting."""
    ultrathink: bool = True
    thinking_budget: int = 20000
    check_emode: bool = True
    check_isolation: bool = True
    check_liquidation: bool = True
    check_flash_loan: bool = True
    check_interest_rate: bool = True


class AaveV3Hunter(HunterAgent):
    """
    Specialized hunter for Aave V3 integrations.

    Vulnerability Categories:
    1. eMode Manipulation - LTV/LT changes, asset list changes
    2. Liquidation Issues - Bonus manipulation, partial liquidation edge cases
    3. Flash Loan Callbacks - Reentrancy, state manipulation
    4. Interest Rate Manipulation - Rate model edge cases
    5. Supply/Borrow Caps - Cap bypass, accounting errors
    6. Isolation Mode - Asset restrictions, debt ceiling bypass
    7. Oracle Dependencies - Aave's oracle usage patterns
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "AaveV3Hunter"
    description = "Deep Aave V3 integration vulnerability analysis"

    # Aave V3 specific vulnerability patterns
    AAVE_PATTERNS = {
        "dangerous_emode_reliance": {
            "regex": r"getUserEMode|getEModeCategory|setUserEMode",
            "description": "Relying on eMode state that can change",
            "severity": Severity.MEDIUM,
        },
        "unchecked_health_factor": {
            "regex": r"getUserAccountData|getHealthFactor",
            "description": "Health factor read without considering pending changes",
            "severity": Severity.HIGH,
        },
        "flash_loan_callback_reentrancy": {
            "regex": r"executeOperation.*\{[^}]*\.call",
            "description": "External call in flash loan callback",
            "severity": Severity.HIGH,
        },
        "liquidation_bonus_assumption": {
            "regex": r"getLiquidationBonus|liquidationBonus\s*[=<>]",
            "description": "Hardcoded liquidation bonus assumptions",
            "severity": Severity.MEDIUM,
        },
        "supply_cap_not_checked": {
            "regex": r"supply\(.*\)(?!.*getReserveCaps)",
            "description": "Supply without checking caps",
            "severity": Severity.LOW,
        },
        "variable_rate_assumption": {
            "regex": r"getReserveData.*variableBorrowRate",
            "description": "Assuming stable interest rates",
            "severity": Severity.LOW,
        },
    }

    # Aave V3 invariants that must hold
    AAVE_INVARIANTS = [
        "health_factor >= 1e18 || position is liquidatable",
        "aToken.totalSupply() == pool.totalLiquidity for asset",
        "debtToken.totalSupply() <= pool.totalDebt for asset",
        "user cannot borrow if in isolation mode with non-isolated asset",
        "eMode LTV <= eMode LT <= 100%",
        "liquidation bonus > 100%",
        "supply + borrow <= cap (if cap > 0)",
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[AaveHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or AaveHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Aave V3 integrations.

**Aave V3 Architecture:**
- Pool: Main entry point for supply/borrow/repay/withdraw
- aTokens: Rebasing tokens representing supplied assets
- debtTokens: Represent borrowed positions (variable or stable)
- Oracle: Chainlink-based price feeds
- eMode: Efficiency Mode for correlated assets (higher LTV)
- Isolation Mode: Risk containment for new assets

**Common Aave V3 Integration Bugs:**

1. **Health Factor Miscalculation**
   - Reading health factor before/after state changes
   - Not accounting for pending interest accrual
   - Using wrong price (spot vs Aave oracle)

2. **eMode Edge Cases**
   - User changes eMode while having position
   - LTV/LT assumptions change with eMode category
   - Asset delistng from eMode

3. **Liquidation Issues**
   - Incorrect liquidation bonus calculations
   - Partial liquidation assumptions
   - Self-liquidation scenarios (see Euler)

4. **Flash Loan Callbacks**
   - Reentrancy during executeOperation
   - State inconsistency after flash loan
   - Premium calculations

5. **Supply/Borrow Caps**
   - Cap not checked before operation
   - Race conditions on cap limits
   - Cap changes during operation

6. **Interest Rate Manipulation**
   - Utilization manipulation via flash loan
   - Rate model edge cases at 100% utilization
   - Variable vs stable rate switching

7. **Isolation Mode**
   - Debt ceiling bypass
   - Borrowing non-allowed assets
   - Collateral switching in isolation

For each vulnerability:
1. Explain the Aave-specific context
2. Show exact attack path
3. Reference similar historical exploits
4. Provide Aave-specific fix"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Aave V3 specific vulnerabilities."""
        self.log("Starting Aave V3 specialized analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_aave_integration(contract.source):
                continue

            self.log(f"Analyzing Aave integration: {contract.name}", style="cyan")

            # Pattern-based detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep analysis with ultrathink
            if self.config.ultrathink:
                deep_findings = await self._deep_aave_analysis(contract)
                findings.extend(deep_findings)

        self.log(f"Found {len(findings)} Aave-specific issues", style="bold green")
        return findings

    def _is_aave_integration(self, source: str) -> bool:
        """Check if contract integrates with Aave."""
        aave_indicators = [
            "IPool",
            "IPoolAddressesProvider",
            "aToken",
            "debtToken",
            "DataTypes.ReserveData",
            "@aave",
            "flashLoanSimple",
            "getUserAccountData",
        ]
        return any(ind in source for ind in aave_indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known Aave vulnerability patterns."""
        findings = []

        for pattern_name, pattern_info in self.AAVE_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-AAVE-{pattern_name}-{line_num}",
                    title=f"Aave Pattern: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern Detected:** {pattern_info["description"]}

**Location:** Line {line_num}
**Matched Code:** `{match.group()[:100]}`

This pattern has been associated with vulnerabilities in Aave integrations.
Manual review required to confirm exploitability.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.6,
                ))

        return findings

    async def _deep_aave_analysis(self, contract) -> list[Finding]:
        """Deep Aave-specific analysis with ultrathink."""
        prompt = f"""Analyze this Aave V3 integration for vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Aave V3 Invariants to Check:**
{chr(10).join(f"- {inv}" for inv in self.AAVE_INVARIANTS)}

**Analysis Focus:**

1. **Health Factor Issues**
   - Is health factor read at the right time?
   - Are pending interest accruals considered?
   - Can health factor be manipulated?

2. **eMode Vulnerabilities**
   - What happens if user's eMode changes?
   - Are LTV/LT assumptions correct for all eModes?
   - eMode category edge cases?

3. **Liquidation Risks**
   - Can self-liquidation be profitable?
   - Liquidation bonus edge cases?
   - Partial vs full liquidation assumptions?

4. **Flash Loan Safety**
   - Reentrancy in executeOperation?
   - State consistency after flash?
   - Premium calculations correct?

5. **Cap and Isolation Mode**
   - Are supply/borrow caps checked?
   - Isolation mode debt ceiling?
   - Asset restriction bypass?

For each vulnerability found:
- Severity: Critical/High/Medium/Low
- Root Cause: Specific Aave integration issue
- Attack Path: Step by step with Aave function calls
- Impact: Funds at risk
- Fix: Aave-specific recommendation

Be thorough. Think about edge cases that only appear in Aave context."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        return self._parse_findings(response.content, contract.name)

    def _parse_findings(self, response: str, contract_name: str) -> list[Finding]:
        """Parse findings from analysis response."""
        findings = []

        # Look for severity markers
        severity_markers = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        blocks = response.split('\n\n')

        for i, block in enumerate(blocks):
            block_lower = block.lower()

            for marker, severity in severity_markers.items():
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'finding', 'bug']):
                    findings.append(Finding(
                        id=f"{contract_name}-AAVE-DEEP-{i:02d}",
                        title=f"Aave V3: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                        description=block,
                        contract=contract_name,
                        confidence=0.75,
                        references=["Aave V3 specialized analysis"],
                    ))
                    break

        return findings
