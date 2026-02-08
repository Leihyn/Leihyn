"""
Curve Hunter - Specialized vulnerability hunting for Curve Finance integrations.

Deep knowledge of:
- StableSwap invariant (x^3*y + y^3*x = D)
- CryptoSwap for volatile pairs
- Virtual price manipulation
- veTokenomics and governance
- Gauge and reward systems
- Vyper-specific issues
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
class CurveHunterConfig:
    """Configuration for Curve hunting."""
    ultrathink: bool = True
    thinking_budget: int = 20000
    check_virtual_price: bool = True
    check_reentrancy: bool = True
    check_vyper: bool = True
    check_governance: bool = True


class CurveHunter(HunterAgent):
    """
    Specialized hunter for Curve Finance integrations.

    Vulnerability Categories:
    1. Virtual Price Manipulation - Read-only reentrancy attacks
    2. Vyper Reentrancy - Compiler bugs in reentrancy locks
    3. Amplification Factor - A parameter manipulation
    4. Imbalanced Pools - Exploitation of pool imbalance
    5. veToken Attacks - Governance and voting power
    6. Gauge Manipulation - Reward distribution issues
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "CurveHunter"
    description = "Deep Curve Finance integration vulnerability analysis"

    # Curve vulnerability patterns
    CURVE_PATTERNS = {
        "virtual_price_during_callback": {
            "regex": r"get_virtual_price\(\).*callback|callback.*get_virtual_price",
            "description": "Virtual price read during callback - read-only reentrancy",
            "severity": Severity.CRITICAL,
        },
        "spot_price_usage": {
            "regex": r"get_dy\(|calc_withdraw_one_coin|calc_token_amount",
            "description": "Spot price calculation - may be manipulable",
            "severity": Severity.MEDIUM,
        },
        "unchecked_slippage": {
            "regex": r"(add_liquidity|remove_liquidity|exchange)\([^)]*\)(?!.*min)",
            "description": "Curve operation without slippage protection",
            "severity": Severity.HIGH,
        },
        "raw_call_pattern": {
            "regex": r"raw_call\(|send\(|call\(",
            "description": "Raw call in Vyper - potential reentrancy",
            "severity": Severity.HIGH,
        },
        "amplification_reliance": {
            "regex": r"A\(\)|future_A|initial_A",
            "description": "Relying on amplification factor - can change over time",
            "severity": Severity.LOW,
        },
    }

    # Curve invariants
    CURVE_INVARIANTS = [
        "virtual_price only increases (except during exploit)",
        "D (invariant) is conserved across operations",
        "LP token supply matches pool state",
        "Amplification factor changes gradually",
        "Gauge rewards match boost calculations",
        "veToken balance decreases over time",
    ]

    # Known Vyper versions with reentrancy bugs
    VULNERABLE_VYPER_VERSIONS = ["0.2.15", "0.2.16", "0.3.0"]

    def __init__(
        self,
        state: AuditState,
        config: Optional[CurveHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or CurveHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Curve Finance integrations.

**Curve Architecture:**
- StableSwap: Optimized AMM for pegged assets (stablecoins)
- CryptoSwap: AMM for volatile pairs
- Metapools: Pools paired with base pools (3pool, etc.)
- Gauges: Reward distribution contracts
- veTokenomics: Vote-escrowed CRV for governance

**Critical Curve Vulnerabilities:**

1. **Read-Only Reentrancy (Virtual Price)**
   - THE most dangerous Curve bug
   - During add/remove liquidity, callbacks can occur (ETH send)
   - get_virtual_price() returns stale/wrong value during callback
   - Protocols reading virtual_price can be exploited
   - Led to $70M+ losses across multiple protocols

   Attack: add_liquidity with ETH -> receive() callback -> read virtual_price (wrong!) -> borrow against inflated value

2. **Vyper Reentrancy Lock Bugs**
   - Vyper versions 0.2.15, 0.2.16, 0.3.0 have broken @nonreentrant
   - Locks don't work properly in these versions
   - $73.5M lost in Curve/JPEG'd hack
   - Check compiler version!

3. **Virtual Price Only Goes Up**
   - get_virtual_price() should never decrease
   - If it can decrease = bug
   - Used to track LP value

4. **Pool Imbalance Attacks**
   - Large single-sided deposits/withdrawals
   - Price manipulation via imbalance
   - MEV extraction from rebalancing

5. **Amplification Factor (A)**
   - A determines curve shape
   - Changes over time (ramp)
   - Can affect price calculations
   - Admin can change A

6. **veToken/Gauge Attacks**
   - Flash loan boost manipulation
   - Reward calculation edge cases
   - Voting power during lock/unlock

For Curve audits:
- ALWAYS check for read-only reentrancy when virtual_price is used
- Check Vyper version for reentrancy bugs
- Verify slippage protection
- Consider pool imbalance scenarios"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Curve-specific vulnerabilities."""
        self.log("Starting Curve Finance specialized analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_curve_integration(contract.source):
                continue

            self.log(f"Analyzing Curve integration: {contract.name}", style="cyan")

            # Check for Vyper version vulnerability
            vyper_findings = self._check_vyper_version(contract)
            findings.extend(vyper_findings)

            # Pattern-based detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep analysis
            if self.config.ultrathink:
                deep_findings = await self._deep_curve_analysis(contract)
                findings.extend(deep_findings)

        self.log(f"Found {len(findings)} Curve-specific issues", style="bold green")
        return findings

    def _is_curve_integration(self, source: str) -> bool:
        """Check if contract integrates with Curve."""
        indicators = [
            "ICurve",
            "IStableSwap",
            "get_virtual_price",
            "add_liquidity",
            "remove_liquidity",
            "exchange",
            "calc_withdraw_one_coin",
            "CRV",
            "gauge",
            "veCRV",
        ]
        return any(ind in source for ind in indicators)

    def _check_vyper_version(self, contract) -> list[Finding]:
        """Check for vulnerable Vyper versions."""
        findings = []

        # Check for version pragma
        version_match = re.search(r'#\s*@version\s+(\d+\.\d+\.\d+)', contract.source)
        if version_match:
            version = version_match.group(1)
            if version in self.VULNERABLE_VYPER_VERSIONS:
                findings.append(Finding(
                    id=f"{contract.name}-CURVE-VYPER-VERSION",
                    title=f"CRITICAL: Vulnerable Vyper Version {version}",
                    severity=Severity.CRITICAL,
                    vulnerability_type=VulnerabilityType.REENTRANCY,
                    description=f"""**Vyper Version {version} Has Known Reentrancy Bug**

This contract uses Vyper {version} which has a broken @nonreentrant decorator.
The reentrancy lock does not work correctly in this version.

**Impact:**
- $73.5M lost in Curve/JPEG'd hack (July 2023)
- @nonreentrant decorators provide NO protection

**Affected Versions:** {', '.join(self.VULNERABLE_VYPER_VERSIONS)}

**Immediate Action Required:**
1. Upgrade Vyper compiler to 0.3.1+
2. Redeploy affected contracts
3. Audit all functions with @nonreentrant for reentrancy""",
                    contract=contract.name,
                    confidence=0.99,
                    references=["Curve/JPEG'd hack July 2023"],
                ))

        return findings

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for Curve vulnerability patterns."""
        findings = []

        for pattern_name, pattern_info in self.CURVE_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source, re.IGNORECASE))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-CURVE-{pattern_name}-{line_num}",
                    title=f"Curve: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.REENTRANCY_READ_ONLY if "virtual_price" in pattern_name else VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern Detected:** {pattern_info["description"]}

**Location:** Line {line_num}
**Code:** `{match.group()[:100]}`

This pattern is associated with Curve integration vulnerabilities.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.7,
                ))

        return findings

    async def _deep_curve_analysis(self, contract) -> list[Finding]:
        """Deep Curve-specific analysis with ultrathink."""
        prompt = f"""Analyze this Curve Finance integration for vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Curve Invariants:**
{chr(10).join(f"- {inv}" for inv in self.CURVE_INVARIANTS)}

**Critical Analysis Points:**

1. **Read-Only Reentrancy (MOST IMPORTANT)**
   - Does contract read get_virtual_price()?
   - Is it read during any callback (receive, ERC callback)?
   - Is the price used for calculations (collateral, shares)?
   - Can an attacker trigger add_liquidity with ETH and exploit during callback?

2. **Vyper Reentrancy Bugs**
   - What Vyper version? (0.2.15, 0.2.16, 0.3.0 are VULNERABLE)
   - Are there @nonreentrant decorators that might not work?

3. **Slippage Protection**
   - Are Curve operations protected with min amounts?
   - Can MEV bots sandwich transactions?

4. **Pool State Assumptions**
   - Does code assume balanced pools?
   - What if pool is heavily imbalanced?
   - Are calculations correct at edge cases?

5. **Integration Points**
   - Is virtual_price used to value LP tokens?
   - Are gauge rewards calculated correctly?
   - Is veToken logic handled properly?

For each finding:
- Explain Curve-specific mechanics
- Show exact attack scenario
- Reference similar historical exploits
- Calculate realistic impact

The read-only reentrancy attack is especially important - check thoroughly!"""

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
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'finding', 'reentrancy']):
                    vuln_type = VulnerabilityType.REENTRANCY_READ_ONLY if 'read-only' in block_lower or 'virtual_price' in block_lower else VulnerabilityType.BUSINESS_LOGIC

                    findings.append(Finding(
                        id=f"{contract_name}-CURVE-DEEP-{i:02d}",
                        title=f"Curve: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=vuln_type,
                        description=block,
                        contract=contract_name,
                        confidence=0.8,
                        references=["Curve specialized analysis"],
                    ))
                    break

        return findings
