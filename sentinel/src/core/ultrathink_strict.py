"""
Strict Ultrathink - Zero Tolerance for AI Slop

This module generates prompts that produce:
1. Concrete findings with real exploitation paths
2. Working PoCs that compile and run
3. Quantified impact (not "could potentially...")
4. Specific fixes (not "consider implementing...")

BANNED PHRASES (will be rejected):
- "could potentially"
- "might be vulnerable"
- "consider implementing"
- "it's recommended to"
- "may cause issues"
- "theoretically possible"
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class StrictPromptConfig:
    """Configuration for strict prompts."""
    thinking_budget: int = 32000
    require_poc: bool = True
    require_quantified_impact: bool = True
    require_specific_fix: bool = True
    ban_weak_language: bool = True
    require_attack_math: bool = True


BANNED_PHRASES = [
    "could potentially",
    "might be vulnerable",
    "may cause",
    "consider implementing",
    "it's recommended",
    "should consider",
    "could lead to",
    "potentially vulnerable",
    "may be exploited",
    "theoretically",
    "in theory",
    "possibly",
    "perhaps",
    "seems like",
    "appears to be",
    "// TODO",
    "// Add logic",
    "...",
]

REQUIRED_ELEMENTS = [
    ("VULNERABLE CODE:", "Must include exact vulnerable code snippet"),
    ("ATTACK PATH:", "Must include step-by-step attack"),
    ("IMPACT:", "Must include quantified impact"),
    ("POC:", "Must include working proof of concept"),
    ("FIX:", "Must include specific code fix"),
]


def build_strict_prompt(
    code: str,
    language: str = "solidity",
    contract_name: str = "Contract",
    config: Optional[StrictPromptConfig] = None,
) -> str:
    """Build strict, no-slop ultrathink prompt."""

    config = config or StrictPromptConfig()

    return f'''# STRICT SECURITY ANALYSIS - ZERO TOLERANCE FOR SLOP

**Target:** {contract_name}
**Language:** {language.upper()}
**Mode:** Maximum Depth Analysis
**Thinking Budget:** {config.thinking_budget} tokens

---

## CRITICAL INSTRUCTIONS - READ CAREFULLY

You are a world-class security auditor. Your output will be used directly.
Any vague, uncertain, or placeholder content is UNACCEPTABLE.

### BANNED LANGUAGE (DO NOT USE):
{_format_banned_list()}

### REQUIRED FOR EVERY FINDING:

1. **EXACT VULNERABLE CODE** - File:line and code snippet
2. **CONCRETE ATTACK PATH** - Step-by-step, no hand-waving
3. **QUANTIFIED IMPACT** - Dollar amount or percentage
4. **WORKING POC** - Code that compiles and proves the exploit
5. **SPECIFIC FIX** - Actual corrected code, not suggestions

---

## CODE UNDER ANALYSIS

```{language}
{code}
```

---

## ANALYSIS FRAMEWORK

### Phase 1: Entry Point Enumeration
List EVERY external/public function and what it does.

### Phase 2: Value Flow Analysis
Trace where funds/tokens enter, move, and exit.
Draw the flow diagram mentally.

### Phase 3: Authorization Check
For each state-changing function:
- Who can call it?
- What are the requirements?
- Can they be bypassed?

### Phase 4: Attack Surface Mapping
For each external interaction:
- What can an attacker control?
- What assumptions are made?
- Can those assumptions be violated?

### Phase 5: Economic Analysis
- Flash loan amplification possible?
- MEV extraction paths?
- Price manipulation vectors?

### Phase 6: Edge Case Hunting
- Zero amounts
- Maximum values
- Empty states
- First/last operations

---

## OUTPUT REQUIREMENTS

For EACH vulnerability, provide EXACTLY this format:

```
================================================================================
FINDING: [ID]-[Severity] [Descriptive Title]
================================================================================

SEVERITY: [Critical/High/Medium/Low]
CATEGORY: [Reentrancy/Access Control/Oracle/etc.]
CONFIDENCE: [X]% - [Why this confidence level]

VULNERABLE CODE:
File: [exact file path]
Lines: [start-end]
```[language]
[exact vulnerable code - copy/paste from source]
```

ROOT CAUSE:
[One paragraph MAX. Be precise. No fluff.]

ATTACK PATH:
1. Attacker [specific action]
2. This causes [specific effect]
3. Attacker then [next action]
4. Result: [specific outcome with numbers]

IMPACT QUANTIFICATION:
- Funds at risk: $[X] or [X]% of TVL
- Attack cost: $[Y] (flash loan fees, gas, etc.)
- Net profit: $[X-Y]
- Affected users: [scope]

PROOF OF CONCEPT:
```{language}
// COMPLETE, WORKING POC
// NOT a sketch, NOT pseudocode
// This MUST compile and run

{_get_poc_template(language)}
```

POC OUTPUT (expected):
```
[Exact expected console output proving the exploit]
```

FIX:
```{language}
// EXACT corrected code
// NOT suggestions
// This replaces the vulnerable code
```

WHY THIS FIX WORKS:
[One sentence explaining why this prevents the attack]

================================================================================
```

---

## QUALITY GATES

Before submitting ANY finding, verify:

[ ] Does the vulnerable code actually exist in the source? (Quote exact lines)
[ ] Is the attack path technically feasible? (No impossible steps)
[ ] Is the impact quantified? (No "could potentially" language)
[ ] Does the PoC compile? (No syntax errors, no placeholders)
[ ] Does the PoC prove the exploit? (Has assertions that pass)
[ ] Is the fix specific? (Actual code, not "consider...")

If ANY gate fails, DO NOT include the finding.

---

## SEVERITY CALIBRATION

**CRITICAL** (Report immediately):
- Unconditional loss of funds
- No preconditions required
- Exploitable by anyone
- Example: Unprotected withdrawal function

**HIGH** (Serious vulnerability):
- Loss of funds with preconditions
- Requires specific setup but realistic
- Example: Reentrancy with typical usage pattern

**MEDIUM** (Limited impact):
- Limited funds at risk
- Unlikely preconditions
- Temporary effects
- Example: DoS requiring unusual state

**LOW** (Minor issue):
- No direct fund loss
- Best practice violation
- Theoretical only
- Example: Missing zero-address check

**DO NOT INFLATE SEVERITY** - Judges/reviewers will downgrade
**DO NOT MISS REAL ISSUES** - Better to find all, then calibrate

---

## ANTI-SLOP CHECKLIST

Before finalizing your response, verify:

[ ] Zero instances of banned phrases
[ ] Every finding has all 5 required elements
[ ] All code snippets are real (not invented)
[ ] All numbers are justified (not made up)
[ ] All PoCs would actually work
[ ] All fixes would actually prevent the attack

---

## BEGIN ANALYSIS

Think deeply. Be thorough. Be concrete. No slop.
'''


def _format_banned_list() -> str:
    """Format banned phrases as list."""
    return "\n".join(f'- "{phrase}"' for phrase in BANNED_PHRASES)


def _get_poc_template(language: str) -> str:
    """Get language-specific PoC template structure."""

    templates = {
        "solidity": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    // Real addresses
    address constant TARGET = 0x...;
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
    }

    function test_exploit() public {
        // BEFORE
        uint256 balanceBefore = TARGET.balance;

        // ATTACK
        vm.startPrank(attacker);
        // [Exact exploit code]
        vm.stopPrank();

        // AFTER
        uint256 balanceAfter = TARGET.balance;

        // PROVE EXPLOIT
        assertGt(balanceAfter, balanceBefore, "Attacker profited");
    }
}''',

        "rust": '''use anchor_lang::prelude::*;
use solana_program_test::*;

#[tokio::test]
async fn test_exploit() {
    // Setup
    let program_test = ProgramTest::new(...);
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    // BEFORE
    let balance_before = banks_client.get_balance(target).await.unwrap();

    // ATTACK
    // [Exact exploit code]

    // AFTER
    let balance_after = banks_client.get_balance(target).await.unwrap();

    // PROVE EXPLOIT
    assert!(balance_after < balance_before);
}''',

        "move": '''#[test]
fun test_exploit() {
    // Setup
    let admin = @0x1;
    let attacker = @0x2;

    // BEFORE
    let balance_before = ...;

    // ATTACK
    // [Exact exploit code]

    // AFTER
    let balance_after = ...;

    // PROVE EXPLOIT
    assert!(balance_after > balance_before, 0);
}''',
    }

    return templates.get(language, templates["solidity"])


def validate_finding(finding_text: str) -> tuple[bool, list[str]]:
    """Validate a finding has no slop and meets requirements."""
    errors = []

    # Check banned phrases
    for phrase in BANNED_PHRASES:
        if phrase.lower() in finding_text.lower():
            errors.append(f"BANNED PHRASE: '{phrase}'")

    # Check required elements
    for element, description in REQUIRED_ELEMENTS:
        if element not in finding_text:
            errors.append(f"MISSING: {description}")

    # Check for placeholder patterns
    placeholder_patterns = [
        "// ...",
        "/* ... */",
        "// Add",
        "// TODO",
        "// Implement",
        "[exact",
        "[specific",
        "[your",
    ]
    for pattern in placeholder_patterns:
        if pattern in finding_text:
            errors.append(f"PLACEHOLDER DETECTED: '{pattern}'")

    return len(errors) == 0, errors


class StrictOutputValidator:
    """Validate AI output meets strict requirements."""

    @staticmethod
    def validate(output: str) -> dict:
        """Validate output and return detailed results."""

        results = {
            "valid": True,
            "banned_phrases_found": [],
            "missing_elements": [],
            "placeholder_patterns": [],
            "findings_count": 0,
            "quality_score": 100,
        }

        # Check banned phrases
        for phrase in BANNED_PHRASES:
            if phrase.lower() in output.lower():
                results["banned_phrases_found"].append(phrase)
                results["quality_score"] -= 10

        # Check required elements
        for element, _ in REQUIRED_ELEMENTS:
            if element not in output:
                results["missing_elements"].append(element)
                results["quality_score"] -= 15

        # Count findings
        results["findings_count"] = output.count("================================================================================") // 2

        # Overall validity
        results["valid"] = (
            len(results["banned_phrases_found"]) == 0 and
            len(results["missing_elements"]) == 0 and
            results["quality_score"] >= 70
        )

        return results
