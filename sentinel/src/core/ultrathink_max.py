"""
Maximum Depth Ultrathink - World-class multi-language analysis.

This module provides the deepest possible analysis prompts for
smart contract security across all supported languages.

Features:
- Historical exploit context
- Protocol-specific invariants
- Attack pattern libraries
- Economic analysis frameworks
- Language-specific pitfalls
- Maximum thinking budgets
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import yaml


class Language(Enum):
    SOLIDITY = "solidity"
    VYPER = "vyper"
    RUST_ANCHOR = "rust_anchor"
    MOVE_APTOS = "move_aptos"
    MOVE_SUI = "move_sui"
    CAIRO = "cairo"
    COSMWASM = "cosmwasm"
    INK = "ink"


@dataclass
class MaxUltrathinkConfig:
    """Maximum depth configuration."""
    thinking_budget: int = 32000  # Maximum thinking tokens
    include_historical_exploits: bool = True
    include_invariants: bool = True
    include_attack_patterns: bool = True
    include_checklists: bool = True
    include_economic_analysis: bool = True
    adversarial_mode: bool = True  # Think like an attacker


class MaxUltrathinkBuilder:
    """
    Build maximum-depth ultrathink prompts for any language.

    This is the most comprehensive analysis system, designed
    for world-class competitive auditing.
    """

    def __init__(self, config: Optional[MaxUltrathinkConfig] = None):
        self.config = config or MaxUltrathinkConfig()
        self._knowledge_base = {}
        self._load_knowledge_bases()

    def _load_knowledge_bases(self):
        """Load all language knowledge bases."""
        kb_path = Path(__file__).parent.parent.parent / "knowledge_base" / "languages"

        for yaml_file in kb_path.glob("*_deep.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                    # Extract language key from filename
                    key = yaml_file.stem.replace("_deep", "")
                    self._knowledge_base[key] = data
            except Exception as e:
                print(f"Warning: Could not load {yaml_file}: {e}")

    def build_max_prompt(
        self,
        code: str,
        language: Language,
        contract_name: str = "Contract",
        focus_areas: Optional[list[str]] = None,
    ) -> str:
        """Build maximum-depth analysis prompt."""

        sections = [
            self._build_header(language, contract_name),
            self._build_code_section(code, language),
        ]

        # Add language-specific deep knowledge
        lang_key = self._get_lang_key(language)
        if lang_key in self._knowledge_base:
            kb = self._knowledge_base[lang_key]

            if self.config.include_historical_exploits:
                sections.append(self._build_exploits_section(kb, language))

            if self.config.include_invariants:
                sections.append(self._build_invariants_section(kb, language))

            if self.config.include_attack_patterns:
                sections.append(self._build_attack_patterns_section(kb, language))

            if self.config.include_checklists:
                sections.append(self._build_checklist_section(kb, language))

        # Add universal sections
        if self.config.include_economic_analysis:
            sections.append(self._build_economic_section(language))

        sections.append(self._build_analysis_instructions(language))

        if self.config.adversarial_mode:
            sections.append(self._build_adversarial_section())

        sections.append(self._build_severity_calibration())
        sections.append(self._build_output_format())

        return "\n\n".join(filter(None, sections))

    def _get_lang_key(self, language: Language) -> str:
        """Map Language enum to knowledge base key."""
        mapping = {
            Language.SOLIDITY: "solidity",
            Language.VYPER: "vyper",
            Language.RUST_ANCHOR: "solana",
            Language.MOVE_APTOS: "move",
            Language.MOVE_SUI: "move",
            Language.CAIRO: "cairo",
            Language.COSMWASM: "cosmwasm",
            Language.INK: "ink",
        }
        return mapping.get(language, "")

    def _build_header(self, language: Language, contract_name: str) -> str:
        """Build comprehensive header."""
        lang_names = {
            Language.SOLIDITY: "Solidity (EVM)",
            Language.VYPER: "Vyper (EVM)",
            Language.RUST_ANCHOR: "Rust/Anchor (Solana)",
            Language.MOVE_APTOS: "Move (Aptos)",
            Language.MOVE_SUI: "Move (Sui)",
            Language.CAIRO: "Cairo (Starknet)",
            Language.COSMWASM: "CosmWasm (Cosmos)",
            Language.INK: "Ink! (Polkadot)",
        }

        return f"""# MAXIMUM DEPTH SECURITY ANALYSIS

**Contract:** {contract_name}
**Language:** {lang_names.get(language, str(language))}
**Analysis Mode:** Ultrathink Maximum Depth
**Thinking Budget:** {self.config.thinking_budget} tokens
**Objective:** Find ALL exploitable vulnerabilities with complete attack paths

---

**CRITICAL INSTRUCTIONS:**
1. Think like a MALICIOUS ATTACKER with unlimited resources
2. Consider flash loans, MEV, and economic attacks
3. Every finding must have a concrete exploitation path
4. No theoretical issues - only REAL vulnerabilities
5. Challenge every assumption the code makes"""

    def _build_code_section(self, code: str, language: Language) -> str:
        """Build code section with syntax highlighting."""
        lang_hints = {
            Language.SOLIDITY: "solidity",
            Language.VYPER: "python",
            Language.RUST_ANCHOR: "rust",
            Language.MOVE_APTOS: "move",
            Language.MOVE_SUI: "move",
            Language.CAIRO: "rust",
            Language.COSMWASM: "rust",
            Language.INK: "rust",
        }

        # Truncate if too long but preserve key parts
        max_len = 18000
        if len(code) > max_len:
            code = code[:max_len] + "\n\n// ... [TRUNCATED - analyze visible code thoroughly]"

        return f"""## Source Code Under Analysis

```{lang_hints.get(language, '')}
{code}
```"""

    def _build_exploits_section(self, kb: dict, language: Language) -> str:
        """Build historical exploits section."""
        # Navigate to the right part of the KB
        exploits = []

        if language == Language.RUST_ANCHOR:
            exploits = kb.get("solana", {}).get("historical_exploits", [])
        elif language in [Language.MOVE_APTOS, Language.MOVE_SUI]:
            lang_key = "aptos" if language == Language.MOVE_APTOS else "sui"
            exploits = kb.get("move", {}).get(lang_key, {}).get("historical_exploits", [])
        elif language == Language.CAIRO:
            exploits = kb.get("cairo", {}).get("historical_exploits", [])
        else:
            exploits = kb.get("historical_exploits", [])

        if not exploits:
            return ""

        lines = ["## Historical Exploits - Learn From The Past"]
        lines.append("")
        lines.append("These real-world exploits inform our analysis:")
        lines.append("")

        for exploit in exploits[:5]:  # Top 5 most relevant
            lines.append(f"### {exploit.get('name', 'Unknown')}")
            if exploit.get('date'):
                lines.append(f"**Date:** {exploit['date']}")
            if exploit.get('loss'):
                lines.append(f"**Loss:** {exploit['loss']}")
            lines.append(f"**Root Cause:** {exploit.get('root_cause', 'Unknown')}")
            lines.append(f"**Lesson:** {exploit.get('lesson', 'N/A')}")
            lines.append("")

        return "\n".join(lines)

    def _build_invariants_section(self, kb: dict, language: Language) -> str:
        """Build invariants section."""
        invariants = {}

        if language == Language.RUST_ANCHOR:
            invariants = kb.get("solana", {}).get("invariants", {})
        elif language in [Language.MOVE_APTOS, Language.MOVE_SUI]:
            lang_key = "aptos" if language == Language.MOVE_APTOS else "sui"
            invariants = kb.get("move", {}).get(lang_key, {}).get("invariants", {})
        elif language == Language.CAIRO:
            invariants = kb.get("cairo", {}).get("invariants", {})
        else:
            invariants = kb.get("invariants", {})

        if not invariants:
            return ""

        lines = ["## Critical Invariants to Verify"]
        lines.append("")
        lines.append("Each invariant violation is a potential vulnerability:")
        lines.append("")

        for severity in ["critical", "high", "medium"]:
            inv_list = invariants.get(severity, [])
            if inv_list:
                lines.append(f"### {severity.upper()} Priority")
                for inv in inv_list:
                    lines.append(f"- **{inv.get('id', '???')}**: {inv.get('name', inv.get('description', ''))}")
                    if inv.get('expression'):
                        lines.append(f"  - `{inv['expression']}`")
                    if inv.get('violation'):
                        lines.append(f"  - ⚠️ Violation: {inv['violation']}")
                lines.append("")

        return "\n".join(lines)

    def _build_attack_patterns_section(self, kb: dict, language: Language) -> str:
        """Build attack patterns section."""
        patterns = {}

        if language == Language.RUST_ANCHOR:
            patterns = kb.get("solana", {}).get("attack_patterns", {})
        elif language in [Language.MOVE_APTOS, Language.MOVE_SUI]:
            lang_key = "aptos" if language == Language.MOVE_APTOS else "sui"
            patterns = kb.get("move", {}).get(lang_key, {}).get("attack_patterns", {})
        elif language == Language.CAIRO:
            patterns = kb.get("cairo", {}).get("attack_patterns", {})
        else:
            patterns = kb.get("attack_patterns", {})

        if not patterns:
            return ""

        lines = ["## Known Attack Patterns"]
        lines.append("")
        lines.append("Look for these specific vulnerability patterns:")
        lines.append("")

        for category, attacks in patterns.items():
            if isinstance(attacks, list):
                lines.append(f"### {category.replace('_', ' ').title()}")
                for attack in attacks:
                    lines.append(f"#### {attack.get('name', 'Unknown')}")
                    lines.append(f"**Severity:** {attack.get('severity', 'Unknown').upper()}")
                    lines.append(f"**Description:** {attack.get('description', '')}")
                    if attack.get('detection_pattern'):
                        lines.append(f"**Detection:** `{attack['detection_pattern']}`")
                    if attack.get('mitigation'):
                        lines.append(f"**Mitigation:** {attack['mitigation']}")
                    lines.append("")

        return "\n".join(lines)

    def _build_checklist_section(self, kb: dict, language: Language) -> str:
        """Build audit checklist section."""
        checklist = []

        if language == Language.RUST_ANCHOR:
            checklist = kb.get("solana", {}).get("audit_checklist", {})
        elif language in [Language.MOVE_APTOS, Language.MOVE_SUI]:
            lang_key = "aptos" if language == Language.MOVE_APTOS else "sui"
            checklist = kb.get("move", {}).get(lang_key, {}).get("audit_checklist", [])
        elif language == Language.CAIRO:
            checklist = kb.get("cairo", {}).get("audit_checklist", {})
        else:
            checklist = kb.get("audit_checklist", [])

        if not checklist:
            return ""

        lines = ["## Audit Checklist"]
        lines.append("")
        lines.append("Verify each item against the code:")
        lines.append("")

        if isinstance(checklist, dict):
            for category, items in checklist.items():
                lines.append(f"### {category.replace('_', ' ').title()}")
                for item in items:
                    severity = item.get('severity', 'medium').upper()
                    lines.append(f"- [{severity}] {item.get('check', item.get('id', ''))}")
                lines.append("")
        elif isinstance(checklist, list):
            for item in checklist:
                severity = item.get('severity', 'medium').upper()
                lines.append(f"- [{severity}] {item.get('check', item.get('id', ''))}")

        return "\n".join(lines)

    def _build_economic_section(self, language: Language) -> str:
        """Build economic analysis framework."""
        return """## Economic Attack Analysis

Consider these economic attack vectors:

### 1. Flash Loan Amplification
- Can borrowed capital amplify any attack?
- What's the maximum borrowable amount?
- Is there profit after fees?

### 2. Price/Oracle Manipulation
- What prices are used?
- How are they obtained?
- Manipulation cost vs potential profit?

### 3. MEV Opportunities
- Can transactions be front-run?
- Sandwich attack possibilities?
- Profitable reordering?

### 4. Value Extraction Paths
- Where does value enter the system?
- Where can it exit?
- Can flows be redirected?

### 5. Incentive Misalignment
- Who benefits from each action?
- Can incentives be exploited?
- Game-theoretic vulnerabilities?"""

    def _build_analysis_instructions(self, language: Language) -> str:
        """Build deep analysis instructions."""
        base = """## Deep Analysis Instructions

For EVERY function/entry point:

### 1. Authorization Analysis
- Who can call this?
- What permissions are required?
- Can authorization be bypassed?

### 2. State Mutation Analysis
- What state changes?
- In what order?
- Reentrancy risk?

### 3. External Interaction Analysis
- What external calls are made?
- To trusted or untrusted targets?
- Can return values be manipulated?

### 4. Arithmetic Analysis
- Overflow/underflow possible?
- Precision loss?
- Rounding direction exploitable?

### 5. Edge Case Analysis
- Zero amounts?
- Maximum values?
- Empty collections?
- First/last user scenarios?"""

        # Add language-specific instructions
        lang_specific = {
            Language.RUST_ANCHOR: """
### Solana-Specific
- Account ownership validated?
- PDAs correctly derived?
- Signer checks complete?
- CPIs properly authorized?""",
            Language.MOVE_APTOS: """
### Aptos-Specific
- Capabilities contained?
- Resources properly acquired?
- Signer validated?
- Hot potato enforced?""",
            Language.MOVE_SUI: """
### Sui-Specific
- Object ownership correct?
- Shared object races?
- PTB attack resistant?
- Dynamic fields secure?""",
            Language.CAIRO: """
### Starknet-Specific
- L1 handler sender validated?
- felt252 vs u256 correct?
- Account abstraction safe?
- Signature replay prevented?""",
        }

        return base + lang_specific.get(language, "")

    def _build_adversarial_section(self) -> str:
        """Build adversarial thinking prompts."""
        return """## ADVERSARIAL MINDSET

Think like a malicious actor with:
- **Unlimited capital** (flash loans are free/cheap)
- **Perfect timing** (MEV bots, block builders)
- **Deep knowledge** (source code, state, pending txs)
- **Multiple accounts** (Sybil attacks)
- **Patience** (multi-block attacks)

Ask yourself:
1. "If I wanted to steal all funds, how would I do it?"
2. "What assumptions does this code make that I can violate?"
3. "What happens in extreme edge cases?"
4. "Can I profit by manipulating any external dependency?"
5. "What would a $100M attack look like?"

**DO NOT STOP** until you've considered every possible attack vector."""

    def _build_severity_calibration(self) -> str:
        """Build severity calibration guidance."""
        return """## Severity Calibration

**CRITICAL (Immediate action required):**
- Direct, unconditional loss of funds
- Complete protocol takeover
- Unbounded value extraction
- No preconditions needed

**HIGH (Serious vulnerability):**
- Loss of funds with specific preconditions
- Significant value at risk
- Core functionality compromise
- Requires some setup but realistic

**MEDIUM (Notable issue):**
- Limited value extraction
- Temporary DoS
- Non-critical functionality affected
- Unlikely but possible

**LOW (Minor/theoretical):**
- Gas optimizations
- Best practice violations
- Extremely unlikely scenarios

**CALIBRATION NOTES:**
- If exploit cost > profit, likely Medium or Low
- If preconditions are very unlikely, downgrade
- Theoretical issues without PoC are often rejected
- When in doubt, provide the attack math"""

    def _build_output_format(self) -> str:
        """Build expected output format."""
        return """## Output Format

For EACH vulnerability found:

```
================================================================================
VULNERABILITY: [Descriptive Title]
================================================================================
SEVERITY: [Critical/High/Medium/Low]
CONFIDENCE: [0-100%]
CATEGORY: [e.g., Access Control, Reentrancy, Economic]

ROOT CAUSE:
[Explain the fundamental flaw - 2-3 sentences max]

VULNERABLE CODE:
[Exact code location and snippet]

ATTACK PATH:
1. Attacker does X
2. This causes Y
3. Resulting in Z (quantified impact)

PROOF OF CONCEPT:
```[language]
// Working exploit code or detailed pseudocode
```

IMPACT QUANTIFICATION:
- Funds at risk: $X or Y% of TVL
- Affected users: [scope]
- Probability: [likelihood assessment]

RECOMMENDED FIX:
```[language]
// Specific code fix
```

REFERENCES:
- [Similar historical exploits if any]
================================================================================
```

**REQUIREMENTS:**
- Every finding MUST have a concrete attack path
- No hand-waving - be specific
- PoC should be implementable
- Quantify impact wherever possible"""


# Convenience function
def build_max_ultrathink(
    code: str,
    language: Language,
    contract_name: str = "Contract",
) -> str:
    """Build maximum-depth ultrathink prompt."""
    builder = MaxUltrathinkBuilder()
    return builder.build_max_prompt(code, language, contract_name)


def get_max_thinking_budget(language: Language) -> int:
    """Get maximum thinking budget for language."""
    # All languages get maximum for deep analysis
    return 32000
