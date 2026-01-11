"""
Enhanced Ultrathink Prompt Builder - World-class prompts with protocol context.

This module provides:
- Protocol-aware prompt generation
- Historical exploit context injection
- Invariant-based analysis prompts
- Severity calibration guidance
- Attack chain synthesis prompts
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import yaml

from .types import VulnerabilityType


@dataclass
class UltrathinkConfig:
    """Configuration for ultrathink prompts."""
    thinking_budget: int = 20000
    include_historical: bool = True
    include_invariants: bool = True
    include_attack_patterns: bool = True
    severity_guidance: bool = True
    cross_protocol_context: bool = True


class UltrathinkPromptBuilder:
    """
    Build world-class ultrathink prompts with deep protocol context.

    Features:
    - Protocol-specific invariants and patterns
    - Historical exploit references
    - Severity calibration based on contest judging
    - Cross-protocol attack context
    """

    def __init__(self, config: Optional[UltrathinkConfig] = None):
        self.config = config or UltrathinkConfig()
        self._protocol_data = None
        self._load_protocol_data()

    def _load_protocol_data(self) -> None:
        """Load protocol knowledge base."""
        knowledge_path = Path(__file__).parent.parent.parent / "knowledge_base" / "protocols" / "protocol_invariants.yaml"
        if knowledge_path.exists():
            with open(knowledge_path) as f:
                self._protocol_data = yaml.safe_load(f)

    def build_analysis_prompt(
        self,
        code: str,
        contract_name: str,
        detected_protocols: list[str],
        vulnerability_focus: Optional[VulnerabilityType] = None,
    ) -> str:
        """Build comprehensive analysis prompt with protocol context."""

        # Base analysis structure
        prompt_parts = [
            self._build_header(contract_name, detected_protocols),
            self._build_code_section(code),
        ]

        # Add protocol-specific context
        if self.config.include_invariants:
            for protocol in detected_protocols:
                invariants = self._get_protocol_invariants(protocol)
                if invariants:
                    prompt_parts.append(self._build_invariants_section(protocol, invariants))

        # Add attack patterns
        if self.config.include_attack_patterns:
            for protocol in detected_protocols:
                patterns = self._get_attack_patterns(protocol)
                if patterns:
                    prompt_parts.append(self._build_patterns_section(protocol, patterns))

        # Add cross-protocol context
        if self.config.cross_protocol_context and len(detected_protocols) > 1:
            cross_context = self._get_cross_protocol_context(detected_protocols)
            if cross_context:
                prompt_parts.append(self._build_cross_protocol_section(cross_context))

        # Add analysis instructions
        prompt_parts.append(self._build_analysis_instructions(vulnerability_focus))

        # Add severity guidance
        if self.config.severity_guidance:
            prompt_parts.append(self._build_severity_guidance())

        # Add output format
        prompt_parts.append(self._build_output_format())

        return "\n\n".join(prompt_parts)

    def _build_header(self, contract_name: str, protocols: list[str]) -> str:
        """Build prompt header."""
        protocol_str = ", ".join(protocols) if protocols else "Unknown"
        return f"""# Deep Security Analysis: {contract_name}

**Detected Integrations:** {protocol_str}
**Analysis Mode:** Extended Thinking (Ultrathink)
**Goal:** Find exploitable vulnerabilities with working attack paths"""

    def _build_code_section(self, code: str) -> str:
        """Build code section."""
        # Truncate if too long
        max_length = 15000
        if len(code) > max_length:
            code = code[:max_length] + "\n// ... (truncated)"

        return f"""## Source Code

```solidity
{code}
```"""

    def _build_invariants_section(self, protocol: str, invariants: dict) -> str:
        """Build protocol invariants section."""
        lines = [f"## {protocol.upper()} Invariants to Verify"]

        for severity, inv_list in invariants.items():
            if inv_list:
                lines.append(f"\n### {severity.upper()} Priority:")
                for inv in inv_list:
                    lines.append(f"- **{inv['id']}**: {inv['description']}")
                    if 'expression' in inv:
                        lines.append(f"  `{inv['expression']}`")

        return "\n".join(lines)

    def _build_patterns_section(self, protocol: str, patterns: list) -> str:
        """Build attack patterns section."""
        lines = [f"## Known {protocol.upper()} Attack Patterns"]

        for pattern in patterns:
            lines.append(f"\n### {pattern['name']}")
            lines.append(f"**Severity:** {pattern.get('severity', 'Unknown')}")
            lines.append(f"**Description:** {pattern['description']}")
            lines.append(f"**Mitigation:** {pattern.get('mitigation', 'N/A')}")

        return "\n".join(lines)

    def _build_cross_protocol_section(self, context: list) -> str:
        """Build cross-protocol interaction section."""
        lines = ["## CRITICAL: Cross-Protocol Interactions"]

        for item in context:
            lines.append(f"\n### {item['name']}")
            lines.append(f"**Risk Level:** {item['risk'].upper()}")
            lines.append(f"**Description:** {item['description']}")
            lines.append(f"**Mitigation:** {item['mitigation']}")

        return "\n".join(lines)

    def _build_analysis_instructions(self, focus: Optional[VulnerabilityType]) -> str:
        """Build analysis instructions."""
        base_instructions = """## Analysis Instructions

Think deeply about each of these attack vectors:

1. **Value Flows**
   - Where does value enter the contract?
   - Where does it exit?
   - Can an attacker redirect value?

2. **State Transitions**
   - What state changes can occur?
   - Are there invalid state transitions?
   - Can state be manipulated across transactions?

3. **External Dependencies**
   - What external contracts are called?
   - What assumptions are made about them?
   - Can those assumptions be violated?

4. **Economic Incentives**
   - Who profits from each operation?
   - Are there profitable attack paths?
   - What's the cost vs reward for attacks?

5. **Edge Cases**
   - What happens at zero?
   - What happens at max values?
   - First user vs subsequent users?
   - Empty vs full pools?"""

        if focus:
            base_instructions += f"\n\n**FOCUS AREA:** Pay special attention to {focus.value} vulnerabilities."

        return base_instructions

    def _build_severity_guidance(self) -> str:
        """Build severity calibration guidance."""
        return """## Severity Calibration (Contest Standards)

**CRITICAL (Immediate loss of funds):**
- Unconditional loss of user funds
- Complete protocol takeover
- Unbounded value extraction

**HIGH (Conditional loss of funds):**
- Loss of funds with specific preconditions
- Significant value extraction possible
- Core functionality compromise

**MEDIUM (Limited impact):**
- Temporary DoS or griefing
- Limited value extraction
- Non-critical functionality affected

**LOW (Best practices):**
- Gas optimizations
- Code quality issues
- Unlikely edge cases

**Remember:**
- Most findings are initially overrated
- If preconditions are unlikely, downgrade
- If exploit cost > profit, it's likely Medium or Low
- Theoretical issues without PoC are often rejected"""

    def _build_output_format(self) -> str:
        """Build expected output format."""
        return """## Output Format

For each vulnerability found, provide:

```
VULNERABILITY: [Title]
SEVERITY: [Critical/High/Medium/Low]
TYPE: [Vulnerability category]
CONFIDENCE: [0-100%]

ROOT_CAUSE:
[Explain the fundamental issue]

ATTACK_PATH:
1. [Step 1]
2. [Step 2]
...

IMPACT:
[Quantify: $ at risk, % of TVL, affected users]

POC_CONCEPT:
```solidity
// Foundry test concept
```

FIX:
[Specific code changes]

REFERENCES:
[Similar historical exploits if any]
---
```

**Be thorough. Think adversarially. Miss nothing.**"""

    def _get_protocol_invariants(self, protocol: str) -> Optional[dict]:
        """Get invariants for a protocol."""
        if not self._protocol_data:
            return None

        protocol_key = protocol.lower().replace(" ", "_").replace("-", "_")

        # Try exact match
        if protocol_key in self._protocol_data.get("protocols", {}):
            return self._protocol_data["protocols"][protocol_key].get("invariants", {})

        # Try partial match
        for key, data in self._protocol_data.get("protocols", {}).items():
            if protocol_key in key or key in protocol_key:
                return data.get("invariants", {})

        return None

    def _get_attack_patterns(self, protocol: str) -> Optional[list]:
        """Get attack patterns for a protocol."""
        if not self._protocol_data:
            return None

        protocol_key = protocol.lower().replace(" ", "_").replace("-", "_")

        for key, data in self._protocol_data.get("protocols", {}).items():
            if protocol_key in key or key in protocol_key:
                return data.get("attack_patterns", [])

        return None

    def _get_cross_protocol_context(self, protocols: list[str]) -> list:
        """Get cross-protocol danger context."""
        if not self._protocol_data:
            return []

        cross_protocol = self._protocol_data.get("cross_protocol", {})
        dangerous = cross_protocol.get("dangerous_combinations", [])

        # Filter relevant combinations
        relevant = []
        protocols_lower = [p.lower() for p in protocols]

        for combo in dangerous:
            name_lower = combo["name"].lower()
            if any(p in name_lower for p in protocols_lower):
                relevant.append(combo)

        return relevant

    def detect_protocols(self, code: str) -> list[str]:
        """Detect which protocols are integrated in the code."""
        detected = []

        protocol_indicators = {
            "aave": ["IPool", "aToken", "Aave", "AAVE", "getUserAccountData"],
            "uniswap": ["IUniswap", "ISwapRouter", "sqrtPriceX96", "UniswapV3", "UniswapV2"],
            "curve": ["ICurve", "get_virtual_price", "StableSwap", "CRV", "Curve"],
            "balancer": ["IVault", "Balancer", "getPoolTokens", "IRateProvider", "BPT"],
            "compound": ["IComet", "Compound", "CToken", "borrowBalanceOf", "absorb"],
            "gmx": ["IGmx", "GMX", "ExchangeRouter", "createOrder", "GLP"],
            "lido": ["stETH", "wstETH", "ILido", "sharesOf", "getPooledEthByShares"],
            "chainlink": ["AggregatorV3", "latestRoundData", "Chainlink"],
            "maker": ["IMaker", "Vat", "DAI", "MakerDAO"],
        }

        for protocol, indicators in protocol_indicators.items():
            if any(ind in code for ind in indicators):
                detected.append(protocol)

        return detected


# Convenience functions
def build_ultrathink_prompt(
    code: str,
    contract_name: str,
    protocols: Optional[list[str]] = None,
) -> str:
    """Build a world-class ultrathink prompt."""
    builder = UltrathinkPromptBuilder()

    if protocols is None:
        protocols = builder.detect_protocols(code)

    return builder.build_analysis_prompt(code, contract_name, protocols)


def get_thinking_budget(severity: str, complexity: str = "medium") -> int:
    """Get recommended thinking budget based on task."""
    base_budgets = {
        "critical": 32000,
        "high": 24000,
        "medium": 16000,
        "low": 10000,
    }

    complexity_multipliers = {
        "simple": 0.75,
        "medium": 1.0,
        "complex": 1.5,
        "very_complex": 2.0,
    }

    base = base_budgets.get(severity.lower(), 16000)
    multiplier = complexity_multipliers.get(complexity.lower(), 1.0)

    return min(int(base * multiplier), 128000)  # Cap at max
