"""
Uniswap Hunter - Specialized vulnerability hunting for Uniswap V3/V4 integrations.

Deep knowledge of:
- Concentrated liquidity mechanics
- Tick math and precision issues
- Callback reentrancy patterns
- TWAP manipulation bounds
- V4 hook vulnerabilities
- Flash accounting
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
class UniswapHunterConfig:
    """Configuration for Uniswap hunting."""
    ultrathink: bool = True
    thinking_budget: int = 20000
    check_twap: bool = True
    check_callbacks: bool = True
    check_tick_math: bool = True
    check_v4_hooks: bool = True


class UniswapV3Hunter(HunterAgent):
    """
    Specialized hunter for Uniswap V3 integrations.

    Vulnerability Categories:
    1. TWAP Manipulation - Using slot0 without TWAP protection
    2. Callback Reentrancy - swap/mint/flash callbacks
    3. Tick Math Issues - Precision loss, overflow in tick calculations
    4. Liquidity Range Attacks - Concentrated liquidity edge cases
    5. Flash Loan Accounting - Balance checks in flash callbacks
    6. Oracle Manipulation - Short-term price manipulation via large swaps
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "UniswapV3Hunter"
    description = "Deep Uniswap V3 integration vulnerability analysis"

    # Uniswap V3 vulnerability patterns
    UNI_V3_PATTERNS = {
        "slot0_without_twap": {
            "regex": r"slot0\(\)(?!.*observe)",
            "description": "Using slot0 for price without TWAP - easily manipulable",
            "severity": Severity.HIGH,
        },
        "callback_reentrancy": {
            "regex": r"uniswapV3(Swap|Mint|Flash)Callback.*\{[^}]*\.call",
            "description": "External call in Uniswap callback - potential reentrancy",
            "severity": Severity.HIGH,
        },
        "unsafe_tick_math": {
            "regex": r"tickLower|tickUpper|TickMath\.getSqrtRatioAtTick",
            "description": "Tick math operations - check for precision issues",
            "severity": Severity.MEDIUM,
        },
        "hardcoded_fee_tier": {
            "regex": r"fee\s*=\s*(500|3000|10000)|\.fee\(\)",
            "description": "Hardcoded fee tier - may not be optimal or could change",
            "severity": Severity.LOW,
        },
        "missing_deadline": {
            "regex": r"swap\([^)]*\)(?!.*deadline)",
            "description": "Swap without deadline parameter",
            "severity": Severity.MEDIUM,
        },
        "unchecked_sqrt_price": {
            "regex": r"sqrtPriceX96(?!.*require|.*assert)",
            "description": "sqrtPriceX96 used without bounds check",
            "severity": Severity.MEDIUM,
        },
    }

    # Uniswap V3 invariants
    UNI_V3_INVARIANTS = [
        "tick is within valid range [-887272, 887272]",
        "sqrtPriceX96 >= MIN_SQRT_RATIO && sqrtPriceX96 <= MAX_SQRT_RATIO",
        "liquidity is non-negative for all positions",
        "TWAP is harder to manipulate over longer periods",
        "flash loan must be repaid with fee in same transaction",
        "callback must come from expected pool address",
    ]

    def __init__(
        self,
        state: AuditState,
        config: Optional[UniswapHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or UniswapHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Uniswap V3 integrations.

**Uniswap V3 Architecture:**
- Concentrated liquidity in discrete tick ranges
- sqrtPriceX96 representation (Q64.96 fixed point)
- Three fee tiers: 0.05%, 0.30%, 1.00%
- TWAP oracle using observe() and observations array
- Callback pattern for swaps, mints, and flash loans

**Common Uniswap V3 Integration Bugs:**

1. **slot0 Price Manipulation**
   - slot0().sqrtPriceX96 is the CURRENT price
   - Easily manipulated via large swap in same block
   - MUST use observe() for TWAP if price is critical
   - Minimum TWAP window: 30 minutes for safety

2. **Callback Reentrancy**
   - uniswapV3SwapCallback called during swap
   - uniswapV3MintCallback called during mint
   - uniswapV3FlashCallback called during flash
   - State may be inconsistent during callback

3. **Tick Math Precision**
   - Ticks are discrete, prices are continuous
   - TickMath.getSqrtRatioAtTick can overflow/underflow
   - Tick spacing varies by fee tier

4. **Liquidity Range Attacks**
   - JIT (Just-In-Time) liquidity attacks
   - Liquidity concentration manipulation
   - Out-of-range position edge cases

5. **Flash Loan Accounting**
   - Must repay principal + fee in same tx
   - Balance checks must happen at right time
   - Can combine with other protocols for attacks

6. **Price Impact Underestimation**
   - Large swaps have non-linear price impact
   - Multiple tick crossings increase slippage
   - Concentrated liquidity amplifies impact

For each vulnerability:
1. Explain the Uniswap-specific math/mechanics
2. Show manipulation scenario
3. Calculate realistic attack cost/profit
4. Provide Uniswap-specific fix"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Uniswap V3 specific vulnerabilities."""
        self.log("Starting Uniswap V3 specialized analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_uniswap_integration(contract.source):
                continue

            self.log(f"Analyzing Uniswap integration: {contract.name}", style="cyan")

            # Pattern-based detection
            pattern_findings = self._check_patterns(contract)
            findings.extend(pattern_findings)

            # Deep analysis
            if self.config.ultrathink:
                deep_findings = await self._deep_uniswap_analysis(contract)
                findings.extend(deep_findings)

        self.log(f"Found {len(findings)} Uniswap-specific issues", style="bold green")
        return findings

    def _is_uniswap_integration(self, source: str) -> bool:
        """Check if contract integrates with Uniswap V3."""
        indicators = [
            "IUniswapV3",
            "ISwapRouter",
            "INonfungiblePositionManager",
            "sqrtPriceX96",
            "uniswapV3SwapCallback",
            "TickMath",
            "PoolAddress",
        ]
        return any(ind in source for ind in indicators)

    def _check_patterns(self, contract) -> list[Finding]:
        """Check for known Uniswap vulnerability patterns."""
        findings = []

        for pattern_name, pattern_info in self.UNI_V3_PATTERNS.items():
            matches = list(re.finditer(pattern_info["regex"], contract.source))

            for match in matches:
                line_num = contract.source[:match.start()].count('\n') + 1

                findings.append(Finding(
                    id=f"{contract.name}-UNIV3-{pattern_name}-{line_num}",
                    title=f"Uniswap V3: {pattern_name.replace('_', ' ').title()}",
                    severity=pattern_info["severity"],
                    vulnerability_type=VulnerabilityType.ORACLE_MANIPULATION if "slot0" in pattern_name else VulnerabilityType.BUSINESS_LOGIC,
                    description=f"""**Pattern Detected:** {pattern_info["description"]}

**Location:** Line {line_num}
**Matched Code:** `{match.group()[:100]}`

This pattern is associated with Uniswap V3 integration vulnerabilities.""",
                    contract=contract.name,
                    line_numbers=(line_num, line_num + 5),
                    confidence=0.65,
                ))

        return findings

    async def _deep_uniswap_analysis(self, contract) -> list[Finding]:
        """Deep Uniswap-specific analysis with ultrathink."""
        prompt = f"""Analyze this Uniswap V3 integration for vulnerabilities.

**Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**Uniswap V3 Invariants:**
{chr(10).join(f"- {inv}" for inv in self.UNI_V3_INVARIANTS)}

**Analysis Focus:**

1. **Price Oracle Safety**
   - Is slot0 used for pricing? (DANGEROUS)
   - What TWAP window is used? (min 30 min recommended)
   - Can price be manipulated profitably?

2. **Callback Security**
   - Are callbacks properly validated (msg.sender == expected pool)?
   - Any state changes before/during callback?
   - Reentrancy vectors?

3. **Tick Math Safety**
   - Are tick values validated?
   - Precision loss in calculations?
   - Edge cases at min/max ticks?

4. **Flash Loan Usage**
   - Proper repayment verification?
   - State consistency during flash?
   - Can flash + swap combine for attack?

5. **MEV Exposure**
   - Sandwich attack susceptibility?
   - JIT liquidity attack surface?
   - Front-running opportunities?

For each finding:
- Severity with Uniswap context
- Attack scenario with realistic numbers
- Cost/profit analysis
- Specific fix

Think like a MEV searcher looking for profitable attacks."""

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
                if marker in block_lower and any(x in block_lower for x in ['vulnerability', 'issue', 'finding']):
                    findings.append(Finding(
                        id=f"{contract_name}-UNIV3-DEEP-{i:02d}",
                        title=f"Uniswap V3: {block.split(chr(10))[0][:60]}",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.ORACLE_MANIPULATION,
                        description=block,
                        contract=contract_name,
                        confidence=0.75,
                    ))
                    break

        return findings


class UniswapV4Hunter(HunterAgent):
    """
    Specialized hunter for Uniswap V4 hook integrations.

    V4 introduces hooks - custom code that runs during pool operations.
    This creates a massive new attack surface.
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "UniswapV4Hunter"
    description = "Deep Uniswap V4 hook vulnerability analysis"

    # V4 Hook vulnerability patterns
    V4_HOOK_PATTERNS = {
        "hook_reentrancy": {
            "regex": r"(beforeSwap|afterSwap|beforeModifyPosition|afterModifyPosition).*\{[^}]*\.call",
            "description": "External call in hook - reentrancy risk",
            "severity": Severity.HIGH,
        },
        "hook_state_manipulation": {
            "regex": r"(beforeSwap|afterSwap).*\{[^}]*(storage|mapping)",
            "description": "State modification in hook - ordering issues",
            "severity": Severity.MEDIUM,
        },
        "hook_revert_dos": {
            "regex": r"(beforeSwap|afterSwap).*require|revert",
            "description": "Hook can revert - potential DoS",
            "severity": Severity.MEDIUM,
        },
        "hook_return_manipulation": {
            "regex": r"return.*delta|return.*amount",
            "description": "Hook manipulates return values - accounting risk",
            "severity": Severity.HIGH,
        },
    }

    def __init__(
        self,
        state: AuditState,
        config: Optional[UniswapHunterConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or UniswapHunterConfig()

    @property
    def system_prompt(self) -> str:
        return """You are an expert at finding vulnerabilities in Uniswap V4 hooks.

**Uniswap V4 Hook Architecture:**
- Hooks are custom contracts that execute during pool operations
- Hook flags determine which callbacks are enabled
- beforeSwap/afterSwap run during swaps
- beforeModifyPosition/afterModifyPosition run during LP operations
- Hooks can modify deltas (return values)

**V4 Hook Vulnerability Categories:**

1. **Hook Reentrancy**
   - Hook makes external call
   - External contract calls back into pool
   - State is inconsistent during callback

2. **Delta Manipulation**
   - Hook modifies return deltas
   - Accounting becomes inconsistent
   - Value extraction possible

3. **Hook DoS**
   - Hook reverts under certain conditions
   - Pool becomes unusable
   - Griefing attacks

4. **Hook Privilege Escalation**
   - Hook has elevated permissions
   - Can manipulate pool state
   - Access control bypass

5. **Cross-Hook Attacks**
   - Multiple hooks interact
   - Ordering dependencies
   - Conflicting state changes

6. **Flash Accounting Manipulation**
   - V4 uses flash accounting (settle at end)
   - Intermediate states can be exploited
   - Balance invariants during operation

For V4 hook audits:
- Check ALL hook callbacks (before/after for each operation)
- Verify delta calculations
- Look for cross-hook interactions
- Consider MEV implications"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Hunt for Uniswap V4 hook vulnerabilities."""
        self.log("Starting Uniswap V4 hook analysis...", style="bold blue")

        findings = []

        for contract in self.state.contracts:
            if not self._is_v4_hook(contract.source):
                continue

            self.log(f"Analyzing V4 hook: {contract.name}", style="cyan")

            # Pattern detection
            for pattern_name, pattern_info in self.V4_HOOK_PATTERNS.items():
                matches = list(re.finditer(pattern_info["regex"], contract.source, re.DOTALL))
                for match in matches:
                    line_num = contract.source[:match.start()].count('\n') + 1
                    findings.append(Finding(
                        id=f"{contract.name}-V4HOOK-{pattern_name}-{line_num}",
                        title=f"V4 Hook: {pattern_name.replace('_', ' ').title()}",
                        severity=pattern_info["severity"],
                        vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                        description=pattern_info["description"],
                        contract=contract.name,
                        line_numbers=(line_num, line_num + 5),
                        confidence=0.7,
                    ))

            # Deep analysis
            if self.config.ultrathink and self.config.check_v4_hooks:
                deep_findings = await self._deep_hook_analysis(contract)
                findings.extend(deep_findings)

        return findings

    def _is_v4_hook(self, source: str) -> bool:
        """Check if contract is a V4 hook."""
        indicators = [
            "BaseHook",
            "beforeSwap",
            "afterSwap",
            "beforeModifyPosition",
            "IPoolManager",
            "Hooks.Permissions",
            "getHookPermissions",
        ]
        return any(ind in source for ind in indicators)

    async def _deep_hook_analysis(self, contract) -> list[Finding]:
        """Deep V4 hook analysis."""
        prompt = f"""Analyze this Uniswap V4 hook for vulnerabilities.

**Hook Contract: {contract.name}**
```solidity
{contract.source[:15000]}
```

**V4 Hook Security Checklist:**

1. **Reentrancy in Callbacks**
   - Does any hook make external calls?
   - Can PoolManager be called during hook execution?
   - Are state changes atomic?

2. **Delta Manipulation**
   - Do hooks modify delta values?
   - Are calculations correct?
   - Can deltas be exploited?

3. **DoS Vectors**
   - Can hook be made to revert?
   - What conditions cause failure?
   - Can attacker force DoS?

4. **Access Control**
   - Who can trigger hooks?
   - Are there privileged operations?
   - Can permissions be bypassed?

5. **Cross-Hook Interactions**
   - How does this hook interact with others?
   - Ordering dependencies?
   - State conflicts?

6. **MEV Implications**
   - Can hook be front-run?
   - Sandwich attack surface?
   - Value extraction during hook?

Report all vulnerabilities with V4-specific context."""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=self.config.thinking_budget,
            stream=False,
        )

        findings = []
        for i, block in enumerate(response.content.split('\n\n')):
            if any(sev in block.lower() for sev in ['critical', 'high', 'medium']):
                findings.append(Finding(
                    id=f"{contract.name}-V4HOOK-DEEP-{i:02d}",
                    title=f"V4 Hook: {block.split(chr(10))[0][:60]}",
                    severity=Severity.HIGH,
                    vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                    description=block,
                    contract=contract.name,
                    confidence=0.75,
                ))

        return findings
