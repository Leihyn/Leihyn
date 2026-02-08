"""
Multi-Language Ultrathink Prompt Builder

Supports:
- Solidity (EVM)
- Rust/Anchor (Solana)
- Move (Aptos/Sui)
- Cairo (Starknet)
- Vyper (EVM)
- Ink! (Polkadot)
- CosmWasm (Cosmos)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Language(Enum):
    SOLIDITY = "solidity"
    RUST_ANCHOR = "rust_anchor"
    RUST_SOLANA = "rust_solana"
    MOVE_APTOS = "move_aptos"
    MOVE_SUI = "move_sui"
    CAIRO = "cairo"
    VYPER = "vyper"
    INK = "ink"
    COSMWASM = "cosmwasm"


@dataclass
class LanguageConfig:
    """Configuration for language-specific analysis."""
    name: str
    file_extensions: list[str]
    thinking_budget: int = 24000
    common_vulns: list[str] = field(default_factory=list)
    unique_patterns: list[str] = field(default_factory=list)


LANGUAGE_CONFIGS = {
    Language.SOLIDITY: LanguageConfig(
        name="Solidity",
        file_extensions=[".sol"],
        common_vulns=[
            "Reentrancy", "Integer overflow", "Access control",
            "Flash loan attacks", "Oracle manipulation", "Front-running"
        ],
        unique_patterns=[
            "delegatecall", "selfdestruct", "tx.origin", "block.timestamp"
        ]
    ),
    Language.RUST_ANCHOR: LanguageConfig(
        name="Rust (Anchor/Solana)",
        file_extensions=[".rs"],
        thinking_budget=28000,
        common_vulns=[
            "Missing signer checks", "Account confusion", "PDA seed collisions",
            "Missing owner checks", "Arithmetic overflow", "Reinitialization",
            "Closing accounts incorrectly", "Type cosplay"
        ],
        unique_patterns=[
            "#[account]", "ctx.accounts", "Pubkey", "invoke_signed",
            "anchor_lang", "AccountInfo", "ProgramError"
        ]
    ),
    Language.MOVE_APTOS: LanguageConfig(
        name="Move (Aptos)",
        file_extensions=[".move"],
        thinking_budget=24000,
        common_vulns=[
            "Missing capability checks", "Resource leaks", "Arithmetic issues",
            "Unauthorized access", "Reentrancy via callbacks", "Flash loan abuse"
        ],
        unique_patterns=[
            "module", "struct", "acquires", "borrow_global", "move_to",
            "signer", "coin::Coin", "aptos_framework"
        ]
    ),
    Language.MOVE_SUI: LanguageConfig(
        name="Move (Sui)",
        file_extensions=[".move"],
        thinking_budget=24000,
        common_vulns=[
            "Object ownership issues", "Shared object race conditions",
            "Missing capability checks", "Arithmetic overflow",
            "Improper object transfer", "Flash loan via PTBs"
        ],
        unique_patterns=[
            "sui::object", "TxContext", "UID", "transfer::public_transfer",
            "dynamic_field", "clock::Clock"
        ]
    ),
    Language.CAIRO: LanguageConfig(
        name="Cairo (Starknet)",
        file_extensions=[".cairo"],
        thinking_budget=26000,
        common_vulns=[
            "Felt overflow/underflow", "Missing access control",
            "Storage collision", "Reentrancy", "Signature malleability",
            "L1-L2 message vulnerabilities"
        ],
        unique_patterns=[
            "@external", "@view", "@storage_var", "felt252",
            "ContractAddress", "starknet::get_caller_address"
        ]
    ),
    Language.VYPER: LanguageConfig(
        name="Vyper",
        file_extensions=[".vy"],
        common_vulns=[
            "Reentrancy (pre-0.3.1)", "Integer bounds", "Access control",
            "Default function issues", "Raw call vulnerabilities"
        ],
        unique_patterns=[
            "@external", "@internal", "@nonreentrant", "HashMap",
            "DynArray", "send()", "raw_call"
        ]
    ),
    Language.COSMWASM: LanguageConfig(
        name="CosmWasm (Rust)",
        file_extensions=[".rs"],
        thinking_budget=26000,
        common_vulns=[
            "Missing sender validation", "Unbounded iterations",
            "Integer overflow", "Reentrancy via submessages",
            "Improper error handling", "State corruption"
        ],
        unique_patterns=[
            "cosmwasm_std", "ExecuteMsg", "QueryMsg", "Deps",
            "MessageInfo", "SubMsg", "WasmMsg"
        ]
    ),
    Language.INK: LanguageConfig(
        name="Ink! (Polkadot)",
        file_extensions=[".rs"],
        thinking_budget=24000,
        common_vulns=[
            "Missing caller checks", "Integer overflow", "Reentrancy",
            "Storage layout issues", "Cross-contract call issues"
        ],
        unique_patterns=[
            "#[ink::contract]", "#[ink(message)]", "#[ink(storage)]",
            "self.env().caller()", "ink_env"
        ]
    ),
}


class MultiLangUltrathinkBuilder:
    """Build ultrathink prompts for any supported language."""

    def __init__(self):
        self.configs = LANGUAGE_CONFIGS

    def detect_language(self, code: str, filename: str = "") -> Language:
        """Detect language from code content and filename."""
        # Check file extension first
        for lang, config in self.configs.items():
            for ext in config.file_extensions:
                if filename.endswith(ext):
                    # Disambiguate Rust-based languages
                    if ext == ".rs":
                        return self._detect_rust_variant(code)
                    # Disambiguate Move variants
                    if ext == ".move":
                        return self._detect_move_variant(code)
                    return lang

        # Content-based detection
        return self._detect_from_content(code)

    def _detect_rust_variant(self, code: str) -> Language:
        """Detect which Rust variant (Anchor, CosmWasm, Ink!)."""
        if "anchor_lang" in code or "#[program]" in code:
            return Language.RUST_ANCHOR
        if "cosmwasm_std" in code or "ExecuteMsg" in code:
            return Language.COSMWASM
        if "#[ink::contract]" in code or "ink_env" in code:
            return Language.INK
        # Default to Anchor as most common
        return Language.RUST_ANCHOR

    def _detect_move_variant(self, code: str) -> Language:
        """Detect Aptos vs Sui Move."""
        if "sui::object" in code or "TxContext" in code:
            return Language.MOVE_SUI
        if "aptos_framework" in code or "aptos_std" in code:
            return Language.MOVE_APTOS
        # Default to Aptos
        return Language.MOVE_APTOS

    def _detect_from_content(self, code: str) -> Language:
        """Detect language from code content."""
        # Solidity
        if "pragma solidity" in code or "contract " in code:
            return Language.SOLIDITY
        # Vyper
        if "@external" in code and "def " in code and "pragma" not in code:
            return Language.VYPER
        # Cairo
        if "#[starknet::contract]" in code or "felt252" in code:
            return Language.CAIRO
        # Move
        if "module " in code and "struct " in code and "fun " in code:
            if "sui::" in code:
                return Language.MOVE_SUI
            return Language.MOVE_APTOS
        # Rust variants
        if "fn " in code and "pub " in code:
            return self._detect_rust_variant(code)

        # Default
        return Language.SOLIDITY

    def build_prompt(
        self,
        code: str,
        language: Optional[Language] = None,
        filename: str = "",
        focus_areas: Optional[list[str]] = None,
    ) -> str:
        """Build ultrathink prompt for given code."""
        if language is None:
            language = self.detect_language(code, filename)

        config = self.configs[language]

        return self._build_language_prompt(code, config, language, focus_areas)

    def _build_language_prompt(
        self,
        code: str,
        config: LanguageConfig,
        language: Language,
        focus_areas: Optional[list[str]] = None,
    ) -> str:
        """Build language-specific prompt."""
        sections = [
            self._header(config, language),
            self._code_section(code, language),
            self._vuln_patterns(config, language),
            self._analysis_instructions(language),
            self._severity_guidance(),
            self._output_format(),
        ]

        if focus_areas:
            sections.insert(3, self._focus_section(focus_areas))

        return "\n\n".join(sections)

    def _header(self, config: LanguageConfig, language: Language) -> str:
        return f"""# Deep Security Analysis: {config.name}

**Language:** {config.name}
**Analysis Mode:** Extended Thinking (Ultrathink)
**Thinking Budget:** {config.thinking_budget} tokens
**Goal:** Find exploitable vulnerabilities with working attack paths"""

    def _code_section(self, code: str, language: Language) -> str:
        lang_hint = {
            Language.SOLIDITY: "solidity",
            Language.RUST_ANCHOR: "rust",
            Language.RUST_SOLANA: "rust",
            Language.MOVE_APTOS: "move",
            Language.MOVE_SUI: "move",
            Language.CAIRO: "cairo",
            Language.VYPER: "python",
            Language.INK: "rust",
            Language.COSMWASM: "rust",
        }.get(language, "")

        # Truncate if too long
        max_len = 15000
        if len(code) > max_len:
            code = code[:max_len] + "\n// ... (truncated)"

        return f"""## Source Code

```{lang_hint}
{code}
```"""

    def _vuln_patterns(self, config: LanguageConfig, language: Language) -> str:
        lines = [f"## {config.name} Vulnerability Patterns"]

        lines.append("\n### Common Vulnerabilities:")
        for vuln in config.common_vulns:
            lines.append(f"- {vuln}")

        lines.append("\n### Unique Patterns to Watch:")
        for pattern in config.unique_patterns:
            lines.append(f"- `{pattern}`")

        # Add language-specific guidance
        extra = self._get_language_specific_guidance(language)
        if extra:
            lines.append(f"\n### {config.name}-Specific Guidance:")
            lines.append(extra)

        return "\n".join(lines)

    def _get_language_specific_guidance(self, language: Language) -> str:
        guidance = {
            Language.RUST_ANCHOR: """
**Solana/Anchor Critical Checks:**
1. Are ALL accounts validated with proper constraints?
2. Is `Signer` required where authorization is needed?
3. Are PDA seeds unique and not controllable by attacker?
4. Is account data properly deserialized and validated?
5. Are CPIs (cross-program invocations) properly signed?
6. Is the program ID checked for all accounts?

**Account Confusion Attack:**
Check if an attacker can pass a different account type than expected.
Anchor's `Account<T>` helps, but manual AccountInfo usage is risky.""",

            Language.MOVE_APTOS: """
**Aptos Move Critical Checks:**
1. Are `signer` parameters validated?
2. Are resources properly acquired with `acquires`?
3. Is `borrow_global_mut` used safely without races?
4. Are coins/tokens handled with proper capability checks?
5. Is arithmetic checked for overflow/underflow?

**Resource Safety:**
Move's ownership model prevents many bugs, but logic errors in
capability checks and access control are still common.""",

            Language.MOVE_SUI: """
**Sui Move Critical Checks:**
1. Are shared objects handled correctly for concurrent access?
2. Is object ownership properly transferred?
3. Are `TxContext` and `Clock` used safely?
4. Are dynamic fields accessed with proper authorization?
5. Is `public_transfer` vs `transfer` used correctly?

**Shared Object Races:**
Sui's shared objects can be accessed concurrently. Check for
race conditions and state inconsistencies.""",

            Language.CAIRO: """
**Cairo/Starknet Critical Checks:**
1. Are felt252 operations checked for overflow?
2. Is `get_caller_address()` used for access control?
3. Are storage variables properly scoped?
4. Is L1<->L2 messaging validated correctly?
5. Are signatures verified with domain separation?

**Felt Overflow:**
felt252 wraps at a prime, not 2^256. This creates different
overflow behavior than EVM integers.""",

            Language.VYPER: """
**Vyper Critical Checks:**
1. Is Vyper version >= 0.3.1? (reentrancy bug in older versions)
2. Are `@nonreentrant` decorators applied correctly?
3. Is `send()` vs `raw_call` used appropriately?
4. Are DynArray bounds checked?
5. Is the default function secured?

**CRITICAL: Vyper 0.2.15-0.3.0 Reentrancy Bug:**
@nonreentrant was BROKEN in these versions. Check compiler version!""",

            Language.COSMWASM: """
**CosmWasm Critical Checks:**
1. Is `info.sender` validated for privileged operations?
2. Are storage operations atomic?
3. Is SubMsg reply handling correct?
4. Are iteration limits enforced?
5. Is error handling complete (no silent failures)?

**Submessage Reentrancy:**
CosmWasm SubMsgs can create reentrancy-like patterns.
Check reply handlers for state consistency.""",

            Language.INK: """
**Ink! Critical Checks:**
1. Is `self.env().caller()` checked for authorization?
2. Are cross-contract calls validated?
3. Is storage layout stable across upgrades?
4. Are arithmetic operations checked?
5. Is the contract upgradeable and properly secured?

**Storage Layout:**
Ink! storage layout can break on upgrade if not careful.
Check for storage compatibility issues.""",
        }
        return guidance.get(language, "")

    def _focus_section(self, focus_areas: list[str]) -> str:
        lines = ["## Focus Areas"]
        for area in focus_areas:
            lines.append(f"- **{area}**")
        return "\n".join(lines)

    def _analysis_instructions(self, language: Language) -> str:
        return """## Analysis Instructions

Think deeply about each attack vector:

1. **Authorization & Access Control**
   - Who can call each function?
   - Are permissions properly enforced?
   - Can authorization be bypassed?

2. **State Management**
   - Can state become inconsistent?
   - Are there race conditions?
   - Is initialization secure?

3. **Value Flows**
   - Where do assets enter/exit?
   - Can value be extracted improperly?
   - Are balances tracked correctly?

4. **External Interactions**
   - What external calls are made?
   - Can callbacks be exploited?
   - Is input validated?

5. **Economic Security**
   - Are there profitable attack paths?
   - Can flash loans amplify attacks?
   - Is oracle/price data trusted safely?"""

    def _severity_guidance(self) -> str:
        return """## Severity Calibration

**CRITICAL:** Unconditional loss of funds, complete takeover
**HIGH:** Conditional loss of funds, significant impact
**MEDIUM:** Limited impact, temporary issues
**LOW:** Best practices, unlikely scenarios

**Cross-Chain Considerations:**
- Solana: Account confusion often High/Critical
- Move: Capability bypasses are Critical
- Cairo: Felt overflow can be Critical
- CosmWasm: Submessage issues often High"""

    def _output_format(self) -> str:
        return """## Output Format

For each vulnerability:

```
VULNERABILITY: [Title]
SEVERITY: [Critical/High/Medium/Low]
LANGUAGE: [Specific language/framework]
CONFIDENCE: [0-100%]

ROOT_CAUSE:
[Fundamental issue]

ATTACK_PATH:
1. [Step 1]
2. [Step 2]
...

IMPACT:
[Quantified impact]

POC_CONCEPT:
[Pseudocode or actual code]

FIX:
[Specific remediation]
---
```

**Think adversarially. Assume attacker has unlimited resources.**"""

    def get_thinking_budget(self, language: Language) -> int:
        """Get recommended thinking budget for language."""
        return self.configs[language].thinking_budget


# Convenience function
def build_multilang_prompt(
    code: str,
    filename: str = "",
    language: Optional[Language] = None,
    focus_areas: Optional[list[str]] = None,
) -> str:
    """Build ultrathink prompt for any supported language."""
    builder = MultiLangUltrathinkBuilder()
    return builder.build_prompt(code, language, filename, focus_areas)
