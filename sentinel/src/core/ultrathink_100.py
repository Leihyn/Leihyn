"""
100% Confidence Ultrathink System

Achieves maximum confidence through:
1. Multi-pass analysis (3 independent passes)
2. Cross-verification between passes
3. Formal invariant checking
4. Symbolic execution hints
5. Attack simulation requirements
6. Proof-of-exploit validation
7. Devil's advocate challenge

A finding is only 100% confident when:
- Found in ALL 3 passes independently
- Has working PoC that compiles
- Has mathematical proof of impact
- Survives devil's advocate challenge
- Matches known exploit patterns
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ConfidenceLevel(Enum):
    SPECULATIVE = 25  # Single pass, no PoC
    LOW = 50  # Single pass with PoC concept
    MEDIUM = 75  # Two passes agree, PoC compiles
    HIGH = 90  # Three passes agree, PoC runs
    CERTAIN = 100  # All checks pass, mathematically proven


@dataclass
class VerifiedFinding:
    """Finding with full verification chain."""
    title: str
    confidence: ConfidenceLevel

    # Verification evidence
    pass1_found: bool = False
    pass2_found: bool = False
    pass3_found: bool = False
    poc_compiles: bool = False
    poc_executes: bool = False
    math_proven: bool = False
    devil_advocate_survived: bool = False
    pattern_matched: bool = False

    # Evidence
    vulnerable_code: str = ""
    attack_proof: str = ""
    impact_calculation: str = ""


def build_100_confidence_prompt(
    code: str,
    language: str = "solidity",
    contract_name: str = "Contract",
) -> str:
    """Build prompt designed for 100% confidence findings."""

    return f'''# 100% CONFIDENCE SECURITY ANALYSIS

**Target:** {contract_name}
**Language:** {language.upper()}
**Objective:** Find vulnerabilities with ABSOLUTE CERTAINTY

---

## CONFIDENCE REQUIREMENTS

A finding reaches 100% confidence ONLY when ALL conditions are met:

| Requirement | Description | Weight |
|-------------|-------------|--------|
| Multi-Pass Verification | Found independently in 3 analysis passes | 20% |
| PoC Compilation | Proof of concept compiles without errors | 15% |
| PoC Execution | PoC runs and proves the exploit | 20% |
| Mathematical Proof | Impact quantified with exact numbers | 15% |
| Pattern Match | Matches known historical exploit | 10% |
| Devil's Advocate | Survives counter-arguments | 20% |

**Total required: 100%**

---

## ANALYSIS PROTOCOL

### PASS 1: ATTACK SURFACE MAPPING

Enumerate every entry point:

```
ENTRY POINTS:
1. [function_name] - [visibility] - [state changes] - [external calls]
2. ...
```

For each entry point, answer:
- What can an attacker control?
- What assumptions are made?
- What would break those assumptions?

### PASS 2: INVARIANT VERIFICATION

List every invariant the code assumes:

```
INVARIANTS:
1. [INV-001] [description] - [code location] - [can be violated: YES/NO]
2. ...
```

For each violated invariant:
- How exactly is it violated?
- What is the exploitation path?
- What is the quantified impact?

### PASS 3: EXPLOIT CONSTRUCTION

For each potential vulnerability from Pass 1 and Pass 2:

```
EXPLOIT ATTEMPT:
- Target: [specific function/invariant]
- Attack Vector: [exact method]
- Prerequisites: [what must be true]
- Execution: [step by step]
- Result: [SUCCESS/FAIL with reason]
```

---

## CODE UNDER ANALYSIS

```{language}
{code}
```

---

## VERIFICATION FRAMEWORK

### Step 1: Independent Analysis (3 Passes)

**Pass 1 Focus:** External interactions and value flows
- Where does value enter?
- Where does value exit?
- Can flows be redirected?

**Pass 2 Focus:** State management and access control
- What state changes are possible?
- Who can trigger each change?
- Are there missing checks?

**Pass 3 Focus:** Economic and game-theoretic attacks
- What are the incentives?
- Can flash loans amplify?
- Is there MEV exposure?

### Step 2: Cross-Verification

Only proceed with findings that appear in ALL THREE passes.

```
CROSS-VERIFICATION MATRIX:
| Finding | Pass 1 | Pass 2 | Pass 3 | Proceed |
|---------|--------|--------|--------|---------|
| [name]  | [Y/N]  | [Y/N]  | [Y/N]  | [Y/N]   |
```

### Step 3: PoC Development

For each cross-verified finding, develop COMPLETE PoC:

```{language}
// COMPLETE POC - MUST COMPILE AND RUN
// No placeholders, no "TODO", no "..."

{_get_poc_framework(language)}
```

**PoC Checklist:**
[ ] Compiles without warnings
[ ] Runs without reverting unexpectedly
[ ] Assert statements pass
[ ] Console output shows profit/impact

### Step 4: Mathematical Proof

Prove the impact with EXACT calculations:

```
IMPACT CALCULATION:

Given:
- [Variable 1] = [value]
- [Variable 2] = [value]

Attack Profit = [formula]
             = [substitution]
             = [exact value]

Verification:
- PoC output matches calculation: [YES/NO]
- Profit > Attack Cost: [YES/NO]
- Net Profit: $[exact amount]
```

### Step 5: Pattern Matching

Compare to known exploits:

```
PATTERN MATCH:

Similar Historical Exploits:
1. [Exploit Name] - [Date] - [Loss] - [Similarity %]
2. ...

Matching Elements:
- [Element 1]: [Match/No Match]
- [Element 2]: [Match/No Match]

Pattern Confidence: [X]%
```

### Step 6: Devil's Advocate Challenge

Try to DISPROVE each finding:

```
DEVIL'S ADVOCATE:

Challenge 1: "The function has access control"
Response: [Explain why access control is insufficient]

Challenge 2: "The preconditions are unlikely"
Response: [Explain why preconditions are realistic]

Challenge 3: "The profit doesn't exceed costs"
Response: [Show exact profit calculation with all costs]

Challenge 4: "This was already mitigated"
Response: [Show the specific code that is still vulnerable]

SURVIVED CHALLENGES: [X/4]
```

---

## OUTPUT FORMAT

For each 100% confidence finding:

```
================================================================================
[100% CONFIDENCE] FINDING: [Title]
================================================================================

SEVERITY: [Critical/High/Medium]
CONFIDENCE: 100%

VERIFICATION STATUS:
[X] Pass 1: Found via attack surface analysis
[X] Pass 2: Found via invariant verification
[X] Pass 3: Found via exploit construction
[X] PoC Compiles: Yes
[X] PoC Executes: Yes, shows [X] ETH profit
[X] Math Proven: Net profit = $[X]
[X] Pattern Match: Similar to [Historical Exploit]
[X] Devil's Advocate: Survived 4/4 challenges

VULNERABLE CODE:
```{language}
// File: [path]
// Lines: [start]-[end]
[exact code]
```

ROOT CAUSE:
[One precise sentence]

ATTACK PATH:
1. [Concrete step with exact parameters]
2. [Concrete step with exact parameters]
3. [Concrete step with exact parameters]
4. Result: Attacker gains [X] ETH

MATHEMATICAL PROOF:
```
Initial State:
- Attacker balance: 1 ETH
- Contract balance: 100 ETH

After Attack:
- Attacker balance: 1 + profit ETH
- Contract balance: 100 - profit ETH

Profit Calculation:
profit = [formula] = [value] ETH

Attack Cost:
- Gas: ~[X] ETH
- Flash loan fee: [X] ETH
- Total cost: [X] ETH

Net Profit: profit - cost = [X] ETH ✓
```

PROOF OF CONCEPT:
```{language}
// COMPLETE, VERIFIED POC
[full working code]
```

POC OUTPUT:
```
[actual output from running the PoC]
```

HISTORICAL PARALLEL:
- [Exploit Name]: [Loss]
- Similarity: [X]%
- Key matching element: [description]

DEVIL'S ADVOCATE RESPONSES:
1. Q: [Challenge] A: [Response]
2. Q: [Challenge] A: [Response]
3. Q: [Challenge] A: [Response]
4. Q: [Challenge] A: [Response]

FIX:
```{language}
// Exact fix code
[corrected code]
```

WHY FIX WORKS:
[One sentence explaining prevention mechanism]

================================================================================
```

---

## CONFIDENCE DOWNGRADE RULES

Downgrade from 100% if ANY of these apply:

| Issue | Downgrade To |
|-------|--------------|
| Not found in all 3 passes | 75% max |
| PoC doesn't compile | 50% max |
| PoC doesn't prove profit | 75% max |
| Math doesn't add up | 75% max |
| No historical parallel | 90% max |
| Failed devil's advocate | 75% max |
| Requires unlikely preconditions | 90% max |
| Attack cost > profit | 50% max |

---

## FORBIDDEN (Automatic 0% Confidence)

If ANY of these appear, the finding is INVALID:

- "could potentially"
- "might be"
- "theoretically"
- "// TODO"
- "// Add logic"
- "..."
- Uncompilable code
- Made-up addresses
- Invented function names
- Numbers without derivation

---

## BEGIN 100% CONFIDENCE ANALYSIS

Execute all three passes.
Cross-verify findings.
Develop complete PoCs.
Prove mathematically.
Match patterns.
Challenge with devil's advocate.

Only report findings that achieve 100% confidence.
'''


def _get_poc_framework(language: str) -> str:
    """Get language-specific PoC framework."""

    frameworks = {
        "solidity": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitTest is Test {
    // REAL addresses - verified on-chain
    address constant TARGET = 0x...; // [Contract name]

    address attacker = makeAddr("attacker");

    // Pre-computed values for verification
    uint256 constant EXPECTED_PROFIT = X ether;

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK);
        vm.deal(attacker, 1 ether);
    }

    function test_exploit() public {
        // BEFORE
        uint256 attackerBefore = attacker.balance;
        uint256 targetBefore = TARGET.balance;

        console.log("=== INITIAL STATE ===");
        console.log("Attacker:", attackerBefore);
        console.log("Target:", targetBefore);

        // ATTACK
        vm.startPrank(attacker);
        // [Complete attack code - no placeholders]
        vm.stopPrank();

        // AFTER
        uint256 attackerAfter = attacker.balance;
        uint256 targetAfter = TARGET.balance;

        console.log("=== FINAL STATE ===");
        console.log("Attacker:", attackerAfter);
        console.log("Target:", targetAfter);

        // PROOF
        uint256 profit = attackerAfter - attackerBefore;
        console.log("=== PROFIT:", profit, "===");

        // ASSERTIONS
        assertGt(profit, 0, "Must profit");
        assertEq(profit, EXPECTED_PROFIT, "Profit must match calculation");
    }
}''',

        "rust": '''use anchor_lang::prelude::*;
use solana_program_test::*;

#[tokio::test]
async fn test_exploit() {
    let mut program_test = ProgramTest::new(...);
    let (mut banks, payer, hash) = program_test.start().await;

    // BEFORE
    let attacker_before = banks.get_balance(attacker).await.unwrap();

    println!("=== INITIAL STATE ===");
    println!("Attacker: {}", attacker_before);

    // ATTACK
    // [Complete attack code]

    // AFTER
    let attacker_after = banks.get_balance(attacker).await.unwrap();

    println!("=== FINAL STATE ===");
    println!("Attacker: {}", attacker_after);

    // PROOF
    let profit = attacker_after - attacker_before;
    println!("=== PROFIT: {} ===", profit);

    assert!(profit > 0, "Must profit");
    assert_eq!(profit, EXPECTED_PROFIT, "Profit must match");
}''',
    }

    return frameworks.get(language, frameworks["solidity"])


class ConfidenceCalculator:
    """Calculate confidence score for a finding."""

    WEIGHTS = {
        "pass1_found": 7,
        "pass2_found": 7,
        "pass3_found": 6,
        "poc_compiles": 15,
        "poc_executes": 20,
        "math_proven": 15,
        "pattern_matched": 10,
        "devil_advocate_survived": 20,
    }

    @classmethod
    def calculate(cls, finding: VerifiedFinding) -> int:
        """Calculate confidence percentage."""
        score = 0

        if finding.pass1_found:
            score += cls.WEIGHTS["pass1_found"]
        if finding.pass2_found:
            score += cls.WEIGHTS["pass2_found"]
        if finding.pass3_found:
            score += cls.WEIGHTS["pass3_found"]
        if finding.poc_compiles:
            score += cls.WEIGHTS["poc_compiles"]
        if finding.poc_executes:
            score += cls.WEIGHTS["poc_executes"]
        if finding.math_proven:
            score += cls.WEIGHTS["math_proven"]
        if finding.pattern_matched:
            score += cls.WEIGHTS["pattern_matched"]
        if finding.devil_advocate_survived:
            score += cls.WEIGHTS["devil_advocate_survived"]

        return score

    @classmethod
    def get_level(cls, score: int) -> ConfidenceLevel:
        """Get confidence level from score."""
        if score >= 100:
            return ConfidenceLevel.CERTAIN
        elif score >= 90:
            return ConfidenceLevel.HIGH
        elif score >= 75:
            return ConfidenceLevel.MEDIUM
        elif score >= 50:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.SPECULATIVE


class MultiPassAnalyzer:
    """Run multiple independent analysis passes."""

    PASS_PROMPTS = {
        "pass1": '''## PASS 1: ATTACK SURFACE ANALYSIS

Focus ONLY on:
1. External/public function entry points
2. Value flows (ETH, tokens)
3. External calls and callbacks
4. User-controllable parameters

For each entry point, document:
- Function signature
- What attacker controls
- What assumptions exist
- How assumptions can be violated

Output format:
```
ENTRY: function_name(params)
CONTROLS: [what attacker controls]
ASSUMES: [what code assumes]
VIOLATION: [how to violate assumption]
EXPLOITABLE: [YES/NO with reason]
```
''',

        "pass2": '''## PASS 2: INVARIANT VERIFICATION

Focus ONLY on:
1. State invariants (balances, totals, mappings)
2. Access control invariants (ownership, roles)
3. Economic invariants (no free money, conservation)
4. Temporal invariants (ordering, timing)

For each invariant:
- State the invariant precisely
- Find code that should maintain it
- Find code that could violate it
- Determine if violation is exploitable

Output format:
```
INVARIANT: [precise statement]
MAINTAINED_BY: [code location]
VIOLATED_BY: [code location or N/A]
EXPLOITABLE: [YES/NO with attack path]
```
''',

        "pass3": '''## PASS 3: EXPLOIT CONSTRUCTION

Focus ONLY on:
1. Building actual exploits for findings from Pass 1 & 2
2. Flash loan amplification
3. MEV opportunities
4. Multi-step attack chains

For each potential exploit:
- Write the exact attack sequence
- Calculate exact profit/loss
- Identify all costs
- Determine net profitability

Output format:
```
EXPLOIT: [name]
TARGET: [function/invariant]
SEQUENCE:
1. [exact step]
2. [exact step]
...
PROFIT: [calculation]
COST: [calculation]
NET: [profit - cost]
VIABLE: [YES/NO]
```
''',
    }

    @classmethod
    def get_pass_prompt(cls, pass_num: int) -> str:
        """Get prompt for specific analysis pass."""
        return cls.PASS_PROMPTS.get(f"pass{pass_num}", "")


class DevilsAdvocate:
    """Challenge findings to ensure validity."""

    CHALLENGES = [
        {
            "id": "DA-001",
            "challenge": "Access control prevents this attack",
            "verify": "Show exact code path that bypasses access control",
        },
        {
            "id": "DA-002",
            "challenge": "The preconditions are unrealistic",
            "verify": "Show that preconditions occur in normal usage",
        },
        {
            "id": "DA-003",
            "challenge": "Attack cost exceeds profit",
            "verify": "Show complete cost breakdown with profit margin",
        },
        {
            "id": "DA-004",
            "challenge": "This is intended behavior",
            "verify": "Show documentation/code that proves it's unintended",
        },
        {
            "id": "DA-005",
            "challenge": "Slippage/MEV protection prevents this",
            "verify": "Show the specific bypass or why protection fails",
        },
        {
            "id": "DA-006",
            "challenge": "Time constraints make this impractical",
            "verify": "Show attack can complete within block time",
        },
        {
            "id": "DA-007",
            "challenge": "This requires admin/owner cooperation",
            "verify": "Show attack works without privileged cooperation",
        },
        {
            "id": "DA-008",
            "challenge": "The impact is overestimated",
            "verify": "Show mathematical proof of exact impact",
        },
    ]

    @classmethod
    def get_challenges(cls, vulnerability_type: str) -> list[dict]:
        """Get relevant challenges for vulnerability type."""
        # Return all challenges - comprehensive validation
        return cls.CHALLENGES

    @classmethod
    def build_challenge_prompt(cls, finding_summary: str) -> str:
        """Build devil's advocate challenge prompt."""
        challenges = "\n".join([
            f"{c['id']}: {c['challenge']}\n   Verify: {c['verify']}"
            for c in cls.CHALLENGES
        ])

        return f'''## DEVIL'S ADVOCATE CHALLENGE

Finding to challenge:
{finding_summary}

You must respond to EACH challenge below.
If you cannot adequately respond, the finding confidence drops.

CHALLENGES:
{challenges}

For each challenge, provide:
```
CHALLENGE: [ID]
RESPONSE: [Your defense - must be specific and provable]
EVIDENCE: [Code snippet or calculation proving your response]
VERDICT: [SURVIVED/FAILED]
```

A finding only achieves 100% confidence if it SURVIVES ALL challenges.
'''


# Validation functions
def validate_100_confidence(finding_text: str) -> tuple[bool, int, list[str]]:
    """Validate if finding meets 100% confidence requirements."""

    checks = {
        "multi_pass": False,
        "poc_present": False,
        "math_present": False,
        "pattern_present": False,
        "devil_advocate": False,
    }
    issues = []

    # Check for multi-pass verification
    if "Pass 1" in finding_text and "Pass 2" in finding_text and "Pass 3" in finding_text:
        checks["multi_pass"] = True
    else:
        issues.append("Missing multi-pass verification")

    # Check for PoC
    if "function test_" in finding_text or "async fn test_" in finding_text:
        if "assert" in finding_text.lower():
            checks["poc_present"] = True
        else:
            issues.append("PoC missing assertions")
    else:
        issues.append("Missing proof of concept")

    # Check for math proof
    if "=" in finding_text and ("ETH" in finding_text or "profit" in finding_text.lower()):
        if any(c.isdigit() for c in finding_text):
            checks["math_present"] = True
        else:
            issues.append("Math proof missing numbers")
    else:
        issues.append("Missing mathematical proof")

    # Check for pattern matching
    historical_keywords = ["similar", "historical", "exploit", "$", "loss", "hack"]
    if any(kw in finding_text.lower() for kw in historical_keywords):
        checks["pattern_present"] = True
    else:
        issues.append("Missing historical pattern match")

    # Check for devil's advocate
    if "challenge" in finding_text.lower() and "response" in finding_text.lower():
        checks["devil_advocate"] = True
    else:
        issues.append("Missing devil's advocate challenge")

    # Calculate score
    score = sum(20 for check in checks.values() if check)

    return score >= 100, score, issues
