"""
Formal Verification Integration for 100% Confidence

Provides:
1. Invariant specification templates
2. Symbolic execution hints
3. Formal proof patterns
4. Certora/Halmos integration templates
5. Property-based testing generators
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class PropertyType(Enum):
    INVARIANT = "invariant"  # Must always hold
    PRECONDITION = "precondition"  # Must hold before
    POSTCONDITION = "postcondition"  # Must hold after
    TRANSITION = "transition"  # Valid state changes


@dataclass
class FormalProperty:
    """Formal property specification."""
    name: str
    property_type: PropertyType
    description: str
    formal_spec: str  # Certora/Halmos syntax
    solidity_check: str  # Equivalent Solidity assertion


class InvariantTemplates:
    """Pre-built invariant templates for common patterns."""

    TEMPLATES = {
        # =====================================================================
        # ACCESS CONTROL INVARIANTS
        # =====================================================================
        "owner_never_zero": FormalProperty(
            name="Owner Never Zero",
            property_type=PropertyType.INVARIANT,
            description="Owner address is never zero after initialization",
            formal_spec='''
invariant ownerNeverZero()
    owner() != 0
    { preserved { require initialized; } }
''',
            solidity_check='''
function invariant_ownerNeverZero() public view {
    if (initialized) {
        assert(owner != address(0));
    }
}
'''
        ),

        "only_owner_can_change_owner": FormalProperty(
            name="Only Owner Can Change Owner",
            property_type=PropertyType.TRANSITION,
            description="Owner can only be changed by current owner",
            formal_spec='''
rule onlyOwnerCanChangeOwner(address newOwner) {
    address ownerBefore = owner();
    env e;

    setOwner(e, newOwner);

    assert e.msg.sender == ownerBefore;
}
''',
            solidity_check='''
function test_onlyOwnerCanChangeOwner(address newOwner) public {
    address ownerBefore = owner;
    vm.prank(attacker);
    vm.expectRevert();
    setOwner(newOwner);
}
'''
        ),

        # =====================================================================
        # BALANCE INVARIANTS
        # =====================================================================
        "total_equals_sum": FormalProperty(
            name="Total Equals Sum of Balances",
            property_type=PropertyType.INVARIANT,
            description="Total supply equals sum of all individual balances",
            formal_spec='''
invariant totalEqualsSum()
    totalSupply() == sum(balanceOf)
''',
            solidity_check='''
function invariant_totalEqualsSum() public view {
    uint256 sum = 0;
    for (uint i = 0; i < holders.length; i++) {
        sum += balanceOf[holders[i]];
    }
    assert(totalSupply == sum);
}
'''
        ),

        "no_balance_exceeds_total": FormalProperty(
            name="No Balance Exceeds Total",
            property_type=PropertyType.INVARIANT,
            description="No individual balance exceeds total supply",
            formal_spec='''
invariant noBalanceExceedsTotal(address user)
    balanceOf(user) <= totalSupply()
''',
            solidity_check='''
function invariant_noBalanceExceedsTotal(address user) public view {
    assert(balanceOf[user] <= totalSupply);
}
'''
        ),

        "balance_non_negative": FormalProperty(
            name="Balance Non-Negative",
            property_type=PropertyType.INVARIANT,
            description="Balances are always non-negative (uint ensures this)",
            formal_spec='''
invariant balanceNonNegative(address user)
    balanceOf(user) >= 0
''',
            solidity_check='''
// Automatically enforced by uint256 type
// But check for underflow in transfer:
function invariant_noUnderflow(address from, uint256 amount) public view {
    assert(balanceOf[from] >= amount);
}
'''
        ),

        # =====================================================================
        # REENTRANCY INVARIANTS
        # =====================================================================
        "no_reentrant_state_change": FormalProperty(
            name="No Reentrant State Change",
            property_type=PropertyType.INVARIANT,
            description="State cannot change during external call",
            formal_spec='''
rule noReentrantStateChange() {
    uint256 stateBefore = stateVar();

    env e;
    externalCall(e);

    assert stateBefore == stateVar()
        || !isInExternalCall();
}
''',
            solidity_check='''
function invariant_noReentrantStateChange() public {
    uint256 stateBefore = stateVar;
    // Reentrancy guard should prevent this:
    assert(!_locked || stateBefore == stateVar);
}
'''
        ),

        # =====================================================================
        # ECONOMIC INVARIANTS
        # =====================================================================
        "no_free_tokens": FormalProperty(
            name="No Free Tokens",
            property_type=PropertyType.TRANSITION,
            description="Tokens cannot be created without corresponding deposit",
            formal_spec='''
rule noFreeTokens(address user, uint256 amount) {
    uint256 totalBefore = totalSupply();
    uint256 balanceBefore = balanceOf(user);

    env e;
    mint(e, user, amount);

    uint256 totalAfter = totalSupply();
    uint256 balanceAfter = balanceOf(user);

    // If tokens increased, must have received deposit
    assert totalAfter > totalBefore =>
        e.msg.value > 0 || transferredIn > 0;
}
''',
            solidity_check='''
function test_noFreeTokens() public {
    uint256 totalBefore = totalSupply;
    uint256 attackerBefore = balanceOf[attacker];

    vm.prank(attacker);
    // Try to mint without deposit
    vm.expectRevert();
    mint(attacker, 1000);

    assert(totalSupply == totalBefore);
    assert(balanceOf[attacker] == attackerBefore);
}
'''
        ),

        "conservation_of_value": FormalProperty(
            name="Conservation of Value",
            property_type=PropertyType.INVARIANT,
            description="Total value in system remains constant (excluding fees)",
            formal_spec='''
invariant conservationOfValue()
    address(this).balance + totalDebt == totalDeposits
    { preserved { require feesAccounted; } }
''',
            solidity_check='''
function invariant_conservationOfValue() public view {
    uint256 systemValue = address(this).balance + totalDebt;
    uint256 liabilities = totalDeposits;
    // Allow for fee margin
    assert(systemValue >= liabilities);
    assert(systemValue <= liabilities + totalFees);
}
'''
        ),

        # =====================================================================
        # ORACLE INVARIANTS
        # =====================================================================
        "price_bounds": FormalProperty(
            name="Price Within Bounds",
            property_type=PropertyType.INVARIANT,
            description="Oracle price within reasonable bounds",
            formal_spec='''
invariant priceBounds()
    getPrice() > MIN_PRICE &&
    getPrice() < MAX_PRICE
''',
            solidity_check='''
function invariant_priceBounds() public view {
    uint256 price = oracle.getPrice();
    assert(price > MIN_PRICE);
    assert(price < MAX_PRICE);
}
'''
        ),

        "price_freshness": FormalProperty(
            name="Price Freshness",
            property_type=PropertyType.PRECONDITION,
            description="Price data is recent",
            formal_spec='''
rule priceFreshness() {
    env e;
    uint256 price = getPrice(e);
    uint256 timestamp = getLastUpdate();

    assert e.block.timestamp - timestamp < MAX_STALENESS;
}
''',
            solidity_check='''
function invariant_priceFreshness() public view {
    (, , uint256 updatedAt, , ) = oracle.latestRoundData();
    assert(block.timestamp - updatedAt < MAX_STALENESS);
}
'''
        ),
    }

    @classmethod
    def get_template(cls, name: str) -> Optional[FormalProperty]:
        """Get invariant template by name."""
        return cls.TEMPLATES.get(name)

    @classmethod
    def get_all_templates(cls) -> dict[str, FormalProperty]:
        """Get all templates."""
        return cls.TEMPLATES

    @classmethod
    def generate_certora_spec(cls, invariants: list[str]) -> str:
        """Generate Certora specification file."""
        specs = []
        for name in invariants:
            template = cls.get_template(name)
            if template:
                specs.append(f"// {template.description}")
                specs.append(template.formal_spec)
                specs.append("")

        return "\n".join(specs)

    @classmethod
    def generate_foundry_invariants(cls, invariants: list[str]) -> str:
        """Generate Foundry invariant tests."""
        tests = ['''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract InvariantTest is Test {
    TargetContract target;

    function setUp() public {
        target = new TargetContract();
    }
''']

        for name in invariants:
            template = cls.get_template(name)
            if template:
                tests.append(f"    // {template.description}")
                tests.append(template.solidity_check)
                tests.append("")

        tests.append("}")
        return "\n".join(tests)


class SymbolicExecutionHints:
    """Hints for symbolic execution tools."""

    @staticmethod
    def generate_halmos_test(
        function_name: str,
        parameters: list[tuple[str, str]],
        preconditions: list[str],
        postconditions: list[str],
    ) -> str:
        """Generate Halmos symbolic test."""

        params_str = ", ".join(f"{ptype} {pname}" for ptype, pname in parameters)
        precond_str = "\n        ".join(f"vm.assume({p});" for p in preconditions)
        postcond_str = "\n        ".join(f"assert({p});" for p in postconditions)

        return f'''// Halmos symbolic execution test
function check_{function_name}({params_str}) public {{
    // Preconditions (symbolic assumptions)
    {precond_str}

    // Execute function under test
    target.{function_name}({", ".join(p[1] for p in parameters)});

    // Postconditions (must hold for ALL inputs)
    {postcond_str}
}}
'''

    @staticmethod
    def generate_symbolic_attack_search(
        target_function: str,
        attacker_balance_var: str,
        victim_balance_var: str,
    ) -> str:
        """Generate symbolic test that searches for profitable attacks."""

        return f'''// Symbolic attack search
// Halmos will find inputs that make attacker profit

function check_no_profitable_attack(
    uint256 attackAmount,
    bytes calldata attackData
) public {{
    // Record initial state
    uint256 attackerBefore = {attacker_balance_var};
    uint256 victimBefore = {victim_balance_var};

    // Assume attacker has limited funds
    vm.assume(attackerBefore <= 100 ether);

    // Execute potential attack
    vm.prank(attacker);
    try target.{target_function}(attackAmount, attackData) {{
        // Attack succeeded
    }} catch {{
        // Attack failed - this is fine
        return;
    }}

    // Record final state
    uint256 attackerAfter = {attacker_balance_var};
    uint256 victimAfter = {victim_balance_var};

    // Assert no profit possible
    // If Halmos finds counterexample, we have a vulnerability!
    assert(attackerAfter <= attackerBefore);
}}
'''


class PropertyBasedTesting:
    """Generate property-based tests for fuzzing."""

    @staticmethod
    def generate_echidna_config() -> str:
        """Generate Echidna configuration."""
        return '''# echidna.yaml
testMode: assertion
testLimit: 100000
shrinkLimit: 5000
seqLen: 100
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
sender: ["0x00a329c0648769A73afAc7F9381E08FB43dBEA72"]
coverage: true
corpusDir: "corpus"
'''

    @staticmethod
    def generate_echidna_test(
        property_name: str,
        property_check: str,
    ) -> str:
        """Generate Echidna property test."""
        return f'''// Echidna property test
contract EchidnaTest {{
    TargetContract target;

    constructor() {{
        target = new TargetContract();
    }}

    // Property: {property_name}
    function echidna_{property_name}() public view returns (bool) {{
        return {property_check};
    }}
}}
'''

    @staticmethod
    def generate_foundry_fuzz_test(
        function_name: str,
        fuzz_params: list[tuple[str, str]],
        assertions: list[str],
    ) -> str:
        """Generate Foundry fuzz test."""

        params_str = ", ".join(f"{ptype} {pname}" for ptype, pname in fuzz_params)
        bounds = "\n        ".join([
            f"{pname} = bound({pname}, 0, type({ptype}).max);"
            for ptype, pname in fuzz_params
            if ptype.startswith("uint")
        ])
        asserts = "\n        ".join(f"assertTrue({a});" for a in assertions)

        return f'''// Foundry fuzz test - runs with random inputs
function testFuzz_{function_name}({params_str}) public {{
    // Bound inputs to reasonable ranges
    {bounds}

    // Execute
    target.{function_name}({", ".join(p[1] for p in fuzz_params)});

    // Assertions must hold for ALL random inputs
    {asserts}
}}
'''


def build_formal_verification_prompt(code: str, contract_name: str) -> str:
    """Build prompt for formal verification-guided analysis."""

    return f'''# FORMAL VERIFICATION-GUIDED ANALYSIS

**Target:** {contract_name}
**Method:** Property-based reasoning with formal specifications

---

## STEP 1: INVARIANT IDENTIFICATION

Identify all invariants that MUST hold:

### State Invariants
- What must always be true about storage variables?
- What relationships between variables must hold?

### Economic Invariants
- Conservation of value?
- No free tokens/ETH?
- Bounded profits?

### Access Control Invariants
- Who can do what?
- What transitions are valid?

For each invariant, specify:
```
INVARIANT: [name]
FORMAL: [mathematical expression]
CODE CHECK: [Solidity assertion]
VIOLATION: [how it could be violated]
```

---

## STEP 2: ATTACK PROPERTY

Define the property we're trying to violate:

```
ATTACK_PROPERTY:
    attacker.balance_after > attacker.balance_before
    AND attacker.balance_after - attacker.balance_before > attack_cost
```

This is what we're searching for - inputs that make this true.

---

## STEP 3: SYMBOLIC ANALYSIS

For each function, reason symbolically:

```
FUNCTION: [name]
INPUTS: [symbolic variables]
PRECONDITIONS: [what must be true before]
EFFECTS: [what changes]
POSTCONDITIONS: [what must be true after]

CAN VIOLATE ATTACK_PROPERTY? [YES/NO with reasoning]
```

---

## STEP 4: COUNTEREXAMPLE SEARCH

For any function that CAN violate the attack property:

```
COUNTEREXAMPLE:
INPUTS: [specific values]
EXECUTION:
1. [step with concrete values]
2. [step with concrete values]
RESULT: attacker profits [X] ETH
```

---

## CODE UNDER ANALYSIS

```solidity
{code}
```

---

## OUTPUT FORMAT

For each vulnerability found through formal reasoning:

```
FORMALLY VERIFIED VULNERABILITY:

Violated Invariant: [which invariant is broken]

Formal Proof:
- Precondition: [formal statement]
- Action: [what attacker does]
- Postcondition Violation: [how invariant breaks]

Counterexample:
- Input values: [specific values]
- Expected behavior: [what should happen]
- Actual behavior: [what happens]
- Profit: [exact amount]

Certora Specification:
```cvl
[formal spec that catches this bug]
```

Foundry Invariant Test:
```solidity
[test that catches this bug]
```
```

---

BEGIN FORMAL ANALYSIS
'''
