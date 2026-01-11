# Smart Contract Security Audit Checklist

## Pre-Audit Preparation

- [ ] Codebase is frozen (no changes during audit)
- [ ] All dependencies are locked to specific versions
- [ ] Documentation is up to date
- [ ] Test suite runs successfully
- [ ] Code coverage report available
- [ ] Known issues documented

---

## 1. Access Control

- [ ] All privileged functions have proper access modifiers
- [ ] Owner/Admin can't rug (check for dangerous functions)
- [ ] Multi-sig or timelock on critical operations
- [ ] Role-based access properly implemented
- [ ] No hardcoded addresses that can't be updated
- [ ] `onlyOwner` functions can't be front-run maliciously

### Questions to Ask:
- Who can call this function?
- What's the worst case if this key is compromised?
- Is there a way to recover from admin key loss?

---

## 2. Reentrancy

- [ ] External calls follow CEI pattern (Checks-Effects-Interactions)
- [ ] ReentrancyGuard used where appropriate
- [ ] No state changes after external calls
- [ ] Cross-function reentrancy considered
- [ ] Read-only reentrancy in view functions checked

### High-Risk Patterns:
```solidity
// DANGEROUS: State change after external call
function withdraw() external {
    (bool success,) = msg.sender.call{value: balance}("");
    balance = 0;  // Should be BEFORE the call
}
```

---

## 3. Integer Arithmetic

- [ ] Solidity 0.8.x or SafeMath used
- [ ] Unchecked blocks are safe from overflow/underflow
- [ ] Division by zero prevented
- [ ] Precision loss in division considered
- [ ] Multiplication before division to prevent precision loss

### Check:
```solidity
// BAD: Precision loss
uint256 result = (a / b) * c;

// GOOD: Multiply first
uint256 result = (a * c) / b;
```

---

## 4. Oracle & Price Manipulation

- [ ] TWAP used instead of spot prices where appropriate
- [ ] Chainlink oracle has staleness check
- [ ] Oracle decimals handled correctly
- [ ] Flash loan price manipulation considered
- [ ] Fallback oracle available
- [ ] Circuit breakers for extreme price movements

### Chainlink Check:
```solidity
(, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
require(price > 0, "Invalid price");
require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "Stale price");
```

---

## 5. Token Handling

- [ ] SafeERC20 used for transfers
- [ ] Fee-on-transfer tokens handled
- [ ] Rebasing tokens handled (or explicitly not supported)
- [ ] ERC777 hooks considered (reentrancy via callbacks)
- [ ] Return values checked (USDT doesn't return bool)
- [ ] Approval race condition handled (approve to 0 first)
- [ ] Token decimals not assumed to be 18

### Common Issues:
```solidity
// USDT requires approval to 0 first
IERC20(usdt).approve(spender, 0);
IERC20(usdt).approve(spender, amount);
```

---

## 6. Signature Verification

- [ ] Replay protection (nonce or deadline)
- [ ] Cross-chain replay protection (chain ID in hash)
- [ ] Signature malleability handled (use OpenZeppelin ECDSA)
- [ ] EIP-712 used for structured data
- [ ] `ecrecover` returns address(0) on failure - check it!
- [ ] Permit signatures can't be reused

### Must Include in Hash:
- Nonce
- Chain ID
- Contract address
- Expiration deadline

---

## 7. Denial of Service

- [ ] No unbounded loops
- [ ] No unbounded arrays that grow forever
- [ ] External calls can fail without blocking contract
- [ ] Pull over push for payments
- [ ] Gas limits on loops considered

### Pattern:
```solidity
// BAD: Push to many addresses
for (uint i = 0; i < users.length; i++) {
    users[i].transfer(amount);  // One failure breaks all
}

// GOOD: Pull pattern
mapping(address => uint256) public owed;
function withdraw() external {
    uint256 amount = owed[msg.sender];
    owed[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

---

## 8. Flash Loan Attacks

- [ ] Governance voting protected from flash loans
- [ ] Price calculations not manipulable in single tx
- [ ] Collateral ratios use time-weighted values
- [ ] Liquidity-based calculations resistant to manipulation

---

## 9. Proxy & Upgrades

- [ ] Implementation initialized (can't be taken over)
- [ ] Storage layout compatible between versions
- [ ] No storage collisions
- [ ] Initializer can only be called once
- [ ] `_disableInitializers()` in implementation constructor
- [ ] Upgrade path tested thoroughly

### Storage Collision Check:
- Compare storage layout of old vs new implementation
- New variables MUST be added at the end
- Never remove or reorder existing variables

---

## 10. Input Validation

- [ ] Zero address checks on initialization
- [ ] Array length checks (empty arrays, mismatched lengths)
- [ ] Bounds checking on percentages (< 100%, etc.)
- [ ] Minimum/maximum value checks
- [ ] Deadline checks for time-sensitive operations

---

## 11. Event Logging

- [ ] All state changes emit events
- [ ] Events indexed appropriately
- [ ] No sensitive data in events (can be scraped)
- [ ] Parameter order makes sense for filtering

---

## 12. Gas Optimization (Security-Related)

- [ ] No gas griefing vectors
- [ ] Gas limits on external calls where appropriate
- [ ] Loops have reasonable bounds
- [ ] Storage packing doesn't create vulnerabilities

---

## 13. External Calls

- [ ] Return values checked
- [ ] Low-level calls have proper error handling
- [ ] `delegatecall` targets are trusted
- [ ] Untrusted contracts treated as malicious
- [ ] Callback hooks can't be exploited

---

## 14. Randomness

- [ ] No on-chain randomness (block.timestamp, blockhash)
- [ ] Chainlink VRF or commit-reveal used
- [ ] VRF callback can't be manipulated

---

## 15. MEV Considerations

- [ ] Sandwich attack vectors identified
- [ ] Slippage protection implemented
- [ ] Deadline parameters on swaps
- [ ] Private mempool / Flashbots considered for sensitive txs

---

## Finding Severity Guide

### Critical
- Direct theft of user funds
- Permanent freezing of funds
- Protocol insolvency

### High
- Theft requiring specific conditions
- Temporary freezing of funds
- Governance manipulation

### Medium
- Griefing attacks (no profit motive)
- Incorrect state that can be fixed
- Limited impact vulnerabilities

### Low
- Best practice violations
- Informational issues
- Gas optimizations

### Gas
- Pure gas optimization suggestions

---

## Post-Audit

- [ ] All findings addressed or acknowledged
- [ ] Re-audit of critical fixes
- [ ] Monitoring and alerting set up
- [ ] Incident response plan documented
- [ ] Bug bounty program launched
