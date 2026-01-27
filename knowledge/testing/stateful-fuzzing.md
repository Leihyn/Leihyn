# Stateful Fuzzing for Smart Contracts

> Advanced fuzzing techniques using Recon Magic methodology for achieving high standardized line coverage.

---

## Overview

Stateful fuzzing (also called invariant testing) explores all possible state combinations of a smart contract system by making sequences of function calls. Unlike property-based testing that tests individual functions, stateful fuzzing tests the entire system's behavior over time.

**Key Insight**: Traditional line coverage includes view/pure functions that don't contribute to state exploration. **Standardized line coverage** focuses only on state-changing functions, providing a more accurate metric for fuzzer efficacy.

---

## Why Standardized Line Coverage?

Traditional coverage reports include:
- View functions (read-only, can't alter state)
- Pure functions (no state access)
- Internal utilities

These inflate coverage numbers without reflecting actual state exploration.

**Standardized coverage** counts only:
- External/public state-changing functions
- Functions in the call trace of target functions
- Library functions that modify state

```
Traditional Coverage: 85% (includes view/pure)
Standardized Coverage: 62% (actual state exploration)
```

The 62% is the real number that matters for finding bugs.

---

## Core Concepts

### 1. Functions of Interest

Functions that can alter contract state and are externally callable:

```solidity
// INCLUDED in standardized coverage
function deposit(uint256 amount) external {        // State-changing
    balances[msg.sender] += amount;
}

function withdraw(uint256 amount) external {       // State-changing
    balances[msg.sender] -= amount;
}

// EXCLUDED from standardized coverage
function balanceOf(address user) external view returns (uint256) {  // View
    return balances[user];
}

function calculateFee(uint256 amount) public pure returns (uint256) {  // Pure
    return amount * 3 / 1000;
}
```

### 2. Clamped Handlers

Handlers with restricted input ranges to reach deeper states faster.

**Without clamping**: Fuzzer tries random uint256 values, mostly invalid
**With clamping**: Fuzzer uses values that make sense (e.g., user's balance)

```solidity
// UNCLAMPED - Full search space, slow coverage
function handler_deposit(uint256 amount) external {
    target.deposit(amount);  // amount can be anything 0 to 2^256
}

// CLAMPED - Reduced search space, fast coverage
function handler_deposit_clamped(uint256 amount) external {
    // Clamp to user's actual token balance
    amount = _bound(amount, 1, token.balanceOf(currentActor));
    target.deposit(amount);
}
```

#### Clamping Strategies

| Strategy | Use When | Example |
|----------|----------|---------|
| **Static** | Values from test setup | `amount = _bound(amount, 1, INITIAL_BALANCE)` |
| **Dynamic** | Values from system state | `amount = _bound(amount, 1, pool.totalDeposits())` |
| **Actor-based** | Values specific to caller | `amount = _bound(amount, 1, balances[currentActor])` |
| **Bounded** | Reasonable ranges | `fee = _bound(fee, 1, MAX_FEE)` |

### 3. Shortcut Functions

Multi-step sequences that reach deep states faster:

```solidity
// Individual calls might take millions of iterations to reach this state
// Shortcut reaches it immediately

function shortcut_depositAndBorrow(
    uint256 depositAmount,
    uint256 borrowAmount
) external {
    // Step 1: Deposit collateral
    depositAmount = _bound(depositAmount, 1e18, token.balanceOf(currentActor));
    this.handler_deposit(depositAmount);

    // Step 2: Borrow against collateral
    uint256 maxBorrow = _getMaxBorrowAmount(currentActor);
    borrowAmount = _bound(borrowAmount, 1, maxBorrow);
    this.handler_borrow(borrowAmount);
}
```

#### Common Shortcut Patterns

| Pattern | Handlers Combined | DeFi Example |
|---------|-------------------|--------------|
| Collateralization | deposit + borrow | Aave, Compound |
| Token Allowance | approve + transferFrom | ERC20 |
| Staking Lifecycle | stake + wait + claim | Lido, Curve gauges |
| AMM Liquidity | addLiquidity + swap | Uniswap, Balancer |
| Position Management | open + modify + close | GMX, Synthetix |

---

## Chimera Framework

The [Chimera framework](https://github.com/Recon-Fuzz/chimera) provides structure for writing stateful fuzzing tests compatible with Echidna and Medusa.

### Project Structure

```
test/
  fuzzing/
    Setup.sol              # Deploy contracts, initialize state
    Properties.sol         # Invariants to check
    TargetFunctions.sol    # Handlers (unclamped, clamped, shortcuts)
    CryticTester.sol       # Medusa entry point
    CryticAsserts.sol      # Echidna entry point
echidna.yaml               # Echidna config
medusa.json                # Medusa config
```

### Minimal Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseTargetFunctions} from "@chimera/BaseTargetFunctions.sol";
import {Properties} from "./Properties.sol";
import {vm} from "@chimera/Hevm.sol";

contract TargetFunctions is BaseTargetFunctions, Properties {

    // Actor management
    address[] internal actors;
    address internal currentActor;

    modifier useActor(uint256 actorSeed) {
        currentActor = actors[_bound(actorSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }

    // UNCLAMPED HANDLERS (full search space)

    function handler_deposit(uint256 amount) external {
        vault.deposit(amount);
    }

    function handler_withdraw(uint256 amount) external {
        vault.withdraw(amount);
    }

    // CLAMPED HANDLERS (reduced search space)

    function handler_deposit_clamped(uint256 amount) external {
        amount = _bound(amount, 1, token.balanceOf(currentActor));
        this.handler_deposit(amount);
    }

    function handler_withdraw_clamped(uint256 amount) external {
        amount = _bound(amount, 1, vault.balanceOf(currentActor));
        this.handler_withdraw(amount);
    }

    // SHORTCUT FUNCTIONS

    function shortcut_depositAndWithdraw(
        uint256 depositAmt,
        uint256 withdrawAmt
    ) external {
        depositAmt = _bound(depositAmt, 1e18, token.balanceOf(currentActor));
        this.handler_deposit(depositAmt);

        vm.warp(block.timestamp + 1 days);

        withdrawAmt = _bound(withdrawAmt, 1, vault.balanceOf(currentActor));
        this.handler_withdraw(withdrawAmt);
    }
}
```

---

## Tools

### Echidna

Property-based fuzzer from Trail of Bits.

```yaml
# echidna.yaml
testMode: assertion
corpusDir: corpus
testLimit: 1000000
workers: 4
```

```bash
echidna . --contract CryticAsserts --config echidna.yaml
```

### Medusa

Go-based fuzzer with parallel execution.

```json
{
  "fuzzing": {
    "workers": 10,
    "timeout": 0,
    "testLimit": 0,
    "corpusDirectory": "corpus"
  }
}
```

```bash
medusa fuzz --config medusa.json
```

### Foundry Invariant Testing

Built-in to Forge, simpler setup but less powerful.

```solidity
contract InvariantTest is Test {
    function setUp() public {
        // Deploy and configure
        targetContract(address(vault));
    }

    function invariant_totalSupplyEqualsDeposits() public {
        assertEq(
            vault.totalSupply(),
            token.balanceOf(address(vault))
        );
    }
}
```

```bash
forge test --match-contract InvariantTest
```

---

## Workflow: Achieving High Coverage

### Step 1: Identify Functions of Interest

```bash
# Using Sentinel
sentinel coverage analyze ./src/Vault.sol --contract Vault
```

Output:
```
Functions of Interest (8):
  - deposit(uint256)
  - withdraw(uint256)
  - borrow(uint256)
  - repay(uint256)
  - liquidate(address)
  - setFee(uint256)
  - pause()
  - unpause()

Excluded (4):
  - balanceOf(address) [view]
  - totalSupply() [view]
  - calculateInterest(uint256) [pure]
  - owner() [view]

Standardized Coverage Target: 8 functions
```

### Step 2: Create Unclamped Handlers

One handler per function of interest:

```solidity
function handler_deposit(uint256 amount) external {
    vault.deposit(amount);
}
// ... repeat for all 8 functions
```

### Step 3: Run Initial Fuzzing

```bash
echidna . --contract CryticAsserts --config echidna.yaml --test-limit 100000
```

Check coverage report - identify uncovered lines.

### Step 4: Add Clamped Handlers

For each function with low coverage, add clamped version:

```solidity
function handler_borrow_clamped(uint256 amount) external {
    uint256 maxBorrow = vault.getMaxBorrow(currentActor);
    amount = _bound(amount, 1, maxBorrow);
    this.handler_borrow(amount);
}
```

### Step 5: Add Shortcuts

Identify multi-step patterns that are hard to reach:

```solidity
// Reaching liquidation requires: deposit, borrow, price drop, liquidate
function shortcut_createLiquidation(uint256 collateral, uint256 debt) external {
    // 1. Setup victim position
    address victim = _getRandomActor();
    _setCurrentActor(victim);
    collateral = _bound(collateral, 1e18, token.balanceOf(victim));
    this.handler_deposit(collateral);
    debt = _bound(debt, collateral / 2, vault.getMaxBorrow(victim));
    this.handler_borrow(debt);

    // 2. Crash price
    oracle.setPrice(oracle.getPrice() / 2);

    // 3. Liquidate
    address liquidator = _getRandomActor();
    _setCurrentActor(liquidator);
    this.handler_liquidate(victim);
}
```

### Step 6: Iterate Until High Coverage

Target: >90% standardized line coverage

```
Run 1: 45% coverage
+ Add clamped handlers
Run 2: 67% coverage
+ Add shortcuts
Run 3: 85% coverage
+ Fix edge cases
Run 4: 94% coverage
```

---

## Best Practices

### Do

- Keep unclamped handlers alongside clamped ones (full search space)
- Use dynamic clamping over static when possible
- Create shortcuts for multi-tx exploit paths
- Commit fuzzer changes at each step (reproducibility)
- Run long campaigns (hours to days)

### Don't

- Clamp too aggressively (miss edge cases)
- Forget view/pure in coverage calculations
- Skip unclamped handlers entirely
- Use placeholder values in handlers
- Ignore coverage gaps in complex paths

---

## Resources

### Tools
- [Echidna](https://github.com/crytic/echidna) - Trail of Bits fuzzer
- [Medusa](https://github.com/crytic/medusa) - Go-based fuzzer
- [Chimera](https://github.com/Recon-Fuzz/chimera) - Fuzzing framework
- [Foundry](https://book.getfoundry.sh/forge/invariant-testing) - Invariant testing

### Learning
- [Recon Book](https://getrecon.xyz/book) - Comprehensive fuzzing guide
- [Recon Magic Blog](https://getrecon.xyz/blog/recon-magic) - Standardized coverage methodology
- [Foundry Invariant Testing](https://book.getfoundry.sh/forge/invariant-testing)

### Public Campaigns
- [Recon Public Campaigns](https://github.com/Recon-Fuzz/public-campaigns) - Real examples
- [Chimera Template](https://github.com/Recon-Fuzz/chimera-template) - Starter template

---

## Benchmarks (Recon Magic)

| Codebase | Unclamped Coverage | Clamped Coverage | Improvement |
|----------|-------------------|------------------|-------------|
| Liquity V2 Governance | 52% | 89% | +37% |
| AAVE V4 | 48% | 91% | +43% |
| Superform Periphery | 55% | 94% | +39% |
| Nerite | 61% | 87% | +26% |

**Time to implement clamped suite:**
- Manual: 3-5 days
- With Recon Magic: 2-3 hours (38x faster)

---

## Integration with Sentinel

Sentinel can automatically generate fuzzing suites:

```python
from sentinel.src.core.sentinel import Sentinel

sentinel = Sentinel()

# Analyze standardized coverage
coverage = sentinel.get_standardized_coverage(code, "Vault")
print(f"Functions of interest: {coverage['functions_of_interest']}")
print(f"Excluded: {coverage['excluded_functions']}")

# Generate Chimera suite
suite = sentinel.get_fuzzing_suite(code, "Vault")
# Write to test/fuzzing/Vault.TargetFunctions.sol
```

---

*Last updated: January 2026*
*Based on Recon Magic methodology*
