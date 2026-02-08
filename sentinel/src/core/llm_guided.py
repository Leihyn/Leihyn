"""
LLM-Guided Deep Analysis - Finding Novel Vulnerabilities

Patterns find KNOWN bugs.
Symbolic execution PROVES bugs.
LLM reasoning finds NOVEL bugs.

This module uses LLM capabilities for:
1. Business logic vulnerability detection
2. Protocol-specific attack reasoning
3. Cross-contract interaction analysis
4. Novel vulnerability hypothesis generation
5. Exploit chain construction

The key insight: Security bugs are often in the GAP between
what the code does and what it SHOULD do. LLMs can reason
about intent, not just syntax.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AnalysisDepth(Enum):
    QUICK = "quick"          # 5 min, surface level
    STANDARD = "standard"    # 15 min, thorough
    DEEP = "deep"           # 30 min, competition-grade
    MAXIMUM = "maximum"      # 1 hour, leave no stone unturned


class VulnerabilityHypothesis(Enum):
    """Types of vulnerabilities LLM should hunt for."""
    BUSINESS_LOGIC = "business_logic"
    ECONOMIC = "economic"
    ACCESS_CONTROL = "access_control"
    STATE_MANIPULATION = "state_manipulation"
    ORACLE_DEPENDENCY = "oracle_dependency"
    CROSS_CONTRACT = "cross_contract"
    TIMING = "timing"
    GOVERNANCE = "governance"
    UPGRADEABILITY = "upgradeability"


@dataclass
class NovelFinding:
    """A novel vulnerability found through LLM reasoning."""
    hypothesis: VulnerabilityHypothesis
    title: str
    severity: str
    reasoning_chain: list[str]  # Step-by-step reasoning
    attack_scenario: str
    preconditions: list[str]
    profit_mechanism: str
    affected_code: list[str]
    confidence: float
    novelty_score: float  # How novel is this vs known patterns


@dataclass
class ReasoningChain:
    """A chain of reasoning about potential vulnerabilities."""
    hypothesis: str
    evidence_for: list[str]
    evidence_against: list[str]
    conclusion: str
    confidence: float


class LLMGuidedAnalyzer:
    """
    Use LLM reasoning to find vulnerabilities that patterns miss.

    Strategy:
    1. Understand what the code is TRYING to do
    2. Identify assumptions the code makes
    3. Find ways to violate those assumptions
    4. Construct concrete attack scenarios
    5. Validate with symbolic execution
    """

    def __init__(self, depth: AnalysisDepth = AnalysisDepth.STANDARD):
        self.depth = depth
        self.thinking_budget = self._get_thinking_budget()

    def _get_thinking_budget(self) -> int:
        """Get thinking token budget based on depth."""
        budgets = {
            AnalysisDepth.QUICK: 8000,
            AnalysisDepth.STANDARD: 16000,
            AnalysisDepth.DEEP: 24000,
            AnalysisDepth.MAXIMUM: 32000,
        }
        return budgets.get(self.depth, 16000)

    def build_analysis_prompt(
        self,
        code: str,
        protocol_type: str,
        known_issues: list[str],
    ) -> str:
        """
        Build the ultimate LLM analysis prompt.

        This prompt guides the LLM to think like an attacker,
        not just a pattern matcher.
        """

        return f'''# ADVERSARIAL SECURITY ANALYSIS

You are a world-class smart contract security researcher.
Your goal: Find bugs that WIN competitions.
Your approach: Think like an ATTACKER, not an auditor.

## PROTOCOL CONTEXT
Type: {protocol_type}
Known Issues Found: {len(known_issues)} (you must find MORE)

## YOUR MISSION
Find vulnerabilities that:
1. Pattern matchers MISS
2. Are CONCRETELY exploitable
3. Have REAL financial impact
4. You can PROVE with a PoC

## ANALYSIS FRAMEWORK

### PHASE 1: UNDERSTAND INTENT (not just code)
Ask yourself:
- What is this code TRYING to achieve?
- What ASSUMPTIONS does it make?
- What would break those assumptions?

### PHASE 2: ATTACK SURFACE MAPPING
For each external/public function:
- What state can it modify?
- What external calls does it make?
- What tokens/value does it handle?
- Who can call it and when?

### PHASE 3: HYPOTHESIS GENERATION
Generate attack hypotheses:

**Business Logic Attacks:**
- Can I do things in an unexpected ORDER?
- Can I call functions with UNEXPECTED VALUES?
- Can I exploit EDGE CASES (0, max, negative)?

**Economic Attacks:**
- Can I extract value without providing equivalent value?
- Can I manipulate prices/rates to my advantage?
- Can I grief other users profitably?

**State Attacks:**
- Can I put the contract in an INVALID STATE?
- Can I make state changes REVERT selectively?
- Can I front-run state changes?

**Access Control Attacks:**
- Can I become an admin/owner?
- Can I bypass permission checks?
- Can I act on behalf of others?

**Cross-Contract Attacks:**
- Can I exploit callback reentrancy?
- Can I manipulate dependencies?
- Can I compose attacks across protocols?

### PHASE 4: ATTACK CONSTRUCTION
For each viable hypothesis:
1. Define PRECONDITIONS (what must be true)
2. Specify EXACT attack steps
3. Calculate PROFIT vs COST
4. Identify BLOCKERS (what could stop this)

### PHASE 5: VALIDATION REQUIREMENTS
For each finding, you MUST provide:
- Specific line numbers
- Concrete attack values
- Expected vs actual behavior
- Profit calculation

## KNOWN ISSUES (Don't repeat these)
{chr(10).join(f"- {issue}" for issue in known_issues) if known_issues else "None found yet"}

## CODE TO ANALYZE
```
{code}
```

## OUTPUT FORMAT

For each vulnerability found:

### [SEVERITY]-[NUMBER]: [Title]

**Hypothesis:** [Which attack type]

**Reasoning Chain:**
1. [First observation]
2. [Therefore...]
3. [Which means...]
4. [Leading to exploit...]

**Attack Scenario:**
```
1. Attacker does X with value Y
2. This causes state change Z
3. Attacker then calls W
4. Result: Attacker profits P
```

**Proof of Concept:**
```solidity
// Concrete, runnable PoC code
```

**Root Cause:** [Single sentence]

**Impact:** [Specific financial impact]

**Confidence:** [HIGH/MEDIUM/LOW] - [Why]

---

BEGIN ADVERSARIAL ANALYSIS:
'''

    def build_cross_contract_prompt(
        self,
        contracts: dict[str, str],
        interactions: list[dict],
    ) -> str:
        """Build prompt for cross-contract vulnerability analysis."""

        contract_list = "\n".join(
            f"### {name}\n```\n{code[:2000]}...\n```"
            for name, code in contracts.items()
        )

        return f'''# CROSS-CONTRACT VULNERABILITY ANALYSIS

## ATTACK SURFACE
Multiple contracts interact. Your goal: find vulnerabilities
that exist ONLY because of their interactions.

## CONTRACTS
{contract_list}

## KNOWN INTERACTIONS
{interactions}

## ANALYSIS FOCUS

### Reentrancy Across Contracts
- Contract A calls B, B calls back to A
- State inconsistency windows
- Cross-protocol reentrancy

### Flash Loan Amplification
- What can be borrowed?
- What can be manipulated during loan?
- What profit can be extracted?

### Oracle Manipulation
- What prices are used?
- Can they be manipulated?
- What depends on those prices?

### Composability Attacks
- How do protocols compose?
- What assumptions does each make?
- Can those assumptions be broken?

## OUTPUT
For each cross-contract vulnerability:
1. Attack flow across contracts
2. Required capital/flash loans
3. Profit calculation
4. Concrete PoC
'''

    def build_invariant_discovery_prompt(self, code: str) -> str:
        """Build prompt to discover implicit invariants in code."""

        return f'''# INVARIANT DISCOVERY

Your task: Find the IMPLICIT INVARIANTS in this code.
Then find ways to VIOLATE them.

## WHAT ARE INVARIANTS?
Properties that MUST always be true:
- Conservation: tokens_in == tokens_out
- Ordering: withdrawal <= deposit
- Bounds: price > 0 && price < MAX
- Relationships: collateral >= debt * ratio

## CODE
```
{code}
```

## ANALYSIS STEPS

### Step 1: List ALL state variables
For each:
- What values are valid?
- What transitions are allowed?
- Who can modify it?

### Step 2: Find IMPLICIT invariants
Things the code ASSUMES but doesn't CHECK:
- "This will never be zero"
- "This will never overflow"
- "These will always be in sync"
- "Only admin will call this"

### Step 3: Violate each invariant
For each implicit invariant:
- HOW can it be violated?
- WHAT would happen if violated?
- IS the violation profitable?

## OUTPUT FORMAT

### Invariant: [Name]
**Implicit assumption:** [What the code assumes]
**Violation method:** [How to break it]
**Consequence:** [What happens when broken]
**Exploitable:** [YES/NO + reasoning]
**PoC:** [Code to violate it]
'''

    def build_novel_attack_prompt(
        self,
        code: str,
        protocol_type: str,
        historical_attacks: list[dict],
    ) -> str:
        """Build prompt to discover novel attack patterns."""

        attacks_str = "\n".join(
            f"- {a['name']}: {a['description']}"
            for a in historical_attacks[:10]
        )

        return f'''# NOVEL ATTACK DISCOVERY

## OBJECTIVE
Find an attack that:
1. Has NOT been seen before
2. Exploits THIS specific code
3. Is CONCRETELY profitable

## HISTORICAL ATTACKS (Don't repeat these)
{attacks_str}

## CODE
```
{code}
```

## PROTOCOL TYPE
{protocol_type}

## NOVEL ATTACK GENERATION

### Think Differently
- What would a SMART attacker try?
- What would an INSIDER know to exploit?
- What would COMPOSABILITY enable?
- What would TIMING enable?

### Unexplored Vectors
- Edge cases in math
- State machine transitions
- Permission boundaries
- External dependencies
- Upgrade mechanisms
- Governance attacks

### Attack Innovation
Combine known attack primitives:
- Flash loan + oracle manipulation + ...
- Reentrancy + governance + ...
- Front-running + state manipulation + ...

## OUTPUT
Novel attack with:
- Why it's different from known attacks
- Complete attack sequence
- Profit calculation
- Concrete PoC
'''


class AdversarialReasoning:
    """
    Adversarial reasoning patterns for vulnerability discovery.

    These are the mental models attackers use.
    """

    REASONING_PATTERNS = {
        "assumption_violation": {
            "description": "Find implicit assumptions and violate them",
            "questions": [
                "What does this code assume about inputs?",
                "What does it assume about state?",
                "What does it assume about callers?",
                "What does it assume about external contracts?",
            ],
        },

        "state_machine_abuse": {
            "description": "Find invalid state transitions",
            "questions": [
                "What states can this contract be in?",
                "What transitions are allowed?",
                "Can I force an invalid transition?",
                "Can I skip required transitions?",
            ],
        },

        "economic_extraction": {
            "description": "Find paths to extract value",
            "questions": [
                "Where does value enter the system?",
                "Where does value exit the system?",
                "Can I extract more than I put in?",
                "Can I manipulate exchange rates?",
            ],
        },

        "access_control_bypass": {
            "description": "Find ways to gain unauthorized access",
            "questions": [
                "Who should be able to call this?",
                "Is that actually enforced?",
                "Can I become that role?",
                "Can I act on behalf of that role?",
            ],
        },

        "timing_exploitation": {
            "description": "Exploit timing dependencies",
            "questions": [
                "What order are things expected to happen?",
                "Can I change that order?",
                "What if I do things simultaneously?",
                "What if I front-run or back-run?",
            ],
        },

        "composability_attacks": {
            "description": "Exploit protocol interactions",
            "questions": [
                "What external protocols does this use?",
                "What assumptions does it make about them?",
                "Can I manipulate those protocols first?",
                "Can I use flash loans to amplify?",
            ],
        },
    }

    @classmethod
    def generate_questions(cls, pattern_name: str) -> list[str]:
        """Get adversarial questions for a reasoning pattern."""
        pattern = cls.REASONING_PATTERNS.get(pattern_name, {})
        return pattern.get("questions", [])

    @classmethod
    def all_patterns(cls) -> list[str]:
        """Get all reasoning pattern names."""
        return list(cls.REASONING_PATTERNS.keys())


class ProtocolSpecificReasoning:
    """
    Protocol-specific attack reasoning.

    Different protocol types have different attack surfaces.
    """

    PROTOCOL_ATTACKS = {
        "amm": {
            "primary_attacks": [
                "Price manipulation via flash loan",
                "Sandwich attacks on swaps",
                "First depositor attack",
                "LP token share inflation",
                "Imbalanced pool exploitation",
            ],
            "invariants": [
                "xy = k (for constant product)",
                "LP tokens backed by reserves",
                "Swap execution matches quote",
            ],
            "key_questions": [
                "Can I manipulate reserves before/during my action?",
                "Can I front-run large swaps?",
                "Can I inflate/deflate LP token value?",
            ],
        },

        "lending": {
            "primary_attacks": [
                "Oracle manipulation for undercollateralized borrow",
                "Flash loan + oracle attack",
                "Interest rate manipulation",
                "Bad debt generation",
                "Liquidation manipulation",
            ],
            "invariants": [
                "Collateral value >= debt value * ratio",
                "Interest accrual is correct",
                "Liquidations are profitable",
            ],
            "key_questions": [
                "Can I manipulate collateral price?",
                "Can I borrow more than I should?",
                "Can I avoid liquidation unfairly?",
                "Can I liquidate when I shouldn't?",
            ],
        },

        "vault": {
            "primary_attacks": [
                "Share inflation attack",
                "Donation attack",
                "Withdrawal queue manipulation",
                "Strategy manipulation",
                "Fee extraction attack",
            ],
            "invariants": [
                "Shares represent proportional ownership",
                "Deposits increase assets",
                "Withdrawals decrease assets",
            ],
            "key_questions": [
                "Can I manipulate share price?",
                "Can I extract more than my share?",
                "Can I grief other depositors?",
            ],
        },

        "bridge": {
            "primary_attacks": [
                "Message spoofing",
                "Replay attacks",
                "Validator collusion",
                "Proof forgery",
                "Sequencer manipulation",
            ],
            "invariants": [
                "Tokens locked == tokens minted",
                "Messages verified before execution",
                "No double-spending across chains",
            ],
            "key_questions": [
                "Can I forge a message?",
                "Can I replay a message?",
                "Can I manipulate validators/sequencer?",
            ],
        },

        "governance": {
            "primary_attacks": [
                "Flash loan governance attack",
                "Proposal griefing",
                "Timelock bypass",
                "Voting manipulation",
                "Treasury drain",
            ],
            "invariants": [
                "Votes require locked tokens",
                "Proposals follow timelock",
                "Execution matches proposal",
            ],
            "key_questions": [
                "Can I get voting power temporarily?",
                "Can I bypass timelock?",
                "Can I execute unauthorized changes?",
            ],
        },
    }

    @classmethod
    def get_attacks(cls, protocol_type: str) -> list[str]:
        """Get primary attacks for protocol type."""
        return cls.PROTOCOL_ATTACKS.get(protocol_type, {}).get("primary_attacks", [])

    @classmethod
    def get_invariants(cls, protocol_type: str) -> list[str]:
        """Get key invariants for protocol type."""
        return cls.PROTOCOL_ATTACKS.get(protocol_type, {}).get("invariants", [])

    @classmethod
    def get_questions(cls, protocol_type: str) -> list[str]:
        """Get key questions for protocol type."""
        return cls.PROTOCOL_ATTACKS.get(protocol_type, {}).get("key_questions", [])


def build_ultimate_prompt(
    code: str,
    language: str = "solidity",
    protocol_type: str = "generic",
    known_issues: list[str] = None,
    depth: AnalysisDepth = AnalysisDepth.DEEP,
) -> str:
    """
    Build the ultimate LLM analysis prompt.

    This is SENTINEL's secret weapon - a prompt that makes
    LLMs think like elite security researchers.

    Args:
        code: Source code to analyze
        language: Programming language
        protocol_type: Type of protocol
        known_issues: Already found issues (don't repeat)
        depth: Analysis depth

    Returns:
        Complete analysis prompt
    """
    analyzer = LLMGuidedAnalyzer(depth)
    return analyzer.build_analysis_prompt(
        code,
        protocol_type,
        known_issues or [],
    )
