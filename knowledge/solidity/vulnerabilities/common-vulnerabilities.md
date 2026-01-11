# Common Smart Contract Vulnerabilities

## Critical Severity

### 1. Reentrancy
**Description:** Attacker re-enters a function before state updates complete.

**Vulnerable Code:**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // External call BEFORE state update
    require(success);
    balances[msg.sender] -= amount;  // State updated AFTER external call
}
```

**Fix:** Use CEI pattern or ReentrancyGuard
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State update FIRST
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

---

### 2. Access Control Missing
**Description:** Critical functions lack proper authorization.

**Vulnerable Code:**
```solidity
function mint(address to, uint256 amount) external {
    _mint(to, amount);  // Anyone can mint!
}
```

**Fix:**
```solidity
function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}
```

---

### 3. Oracle Manipulation
**Description:** Price oracles can be manipulated in a single transaction.

**Vulnerable Code:**
```solidity
function getPrice() public view returns (uint256) {
    return reserve1 / reserve0;  // Spot price - easily manipulated
}
```

**Fix:** Use TWAP or Chainlink
```solidity
function getPrice() public view returns (uint256) {
    return chainlinkOracle.latestAnswer();  // External oracle
}
```

---

## High Severity

### 4. Integer Overflow/Underflow
**Description:** Arithmetic operations wrap around (pre-0.8.0).

**Note:** Solidity 0.8.0+ has built-in overflow checks. Use `unchecked` carefully.

```solidity
// Dangerous in unchecked blocks
unchecked {
    uint256 result = a - b;  // Can underflow if b > a
}
```

---

### 5. Signature Replay
**Description:** Same signature can be used multiple times.

**Vulnerable Code:**
```solidity
function executeWithSig(address to, uint256 amount, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    require(recoverSigner(hash, sig) == owner);
    // No nonce check - signature can be replayed!
}
```

**Fix:**
```solidity
mapping(bytes32 => bool) public usedSignatures;

function executeWithSig(address to, uint256 amount, uint256 nonce, bytes memory sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this), block.chainid));
    require(!usedSignatures[hash], "Already used");
    require(recoverSigner(hash, sig) == owner);
    usedSignatures[hash] = true;
    // Execute...
}
```

---

### 6. Flash Loan Attacks
**Description:** Attacker uses borrowed funds to manipulate protocol state.

**Common Targets:**
- Governance voting with token balance snapshots
- Collateral price manipulation
- Liquidity pool ratio manipulation

**Mitigations:**
- Use time-weighted values (TWAP)
- Require token lock-up before voting
- Use Chainlink oracles

---

## Medium Severity

### 7. Frontrunning
**Description:** Attacker sees pending transaction and submits theirs first.

**Common Cases:**
- DEX trades (sandwich attacks)
- NFT minting (mint sniping)
- Liquidations

**Mitigations:**
- Commit-reveal schemes
- Flashbots/private mempools
- Slippage protection

---

### 8. Denial of Service (DoS)
**Description:** Attacker prevents legitimate users from using the contract.

**Vulnerable Code:**
```solidity
function refundAll() external {
    for (uint256 i = 0; i < users.length; i++) {
        payable(users[i]).transfer(refunds[users[i]]);  // One failure breaks all
    }
}
```

**Fix:** Use pull payments
```solidity
function claimRefund() external {
    uint256 amount = refunds[msg.sender];
    refunds[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

---

### 9. Uninitialized Storage/Proxy
**Description:** Implementation contract not initialized, attacker takes control.

**Fix:** Always call initializer, use `_disableInitializers()` in constructor.

```solidity
constructor() {
    _disableInitializers();
}

function initialize(address admin) external initializer {
    __Ownable_init(admin);
}
```

---

### 10. Precision Loss
**Description:** Division before multiplication loses precision.

**Vulnerable Code:**
```solidity
uint256 result = (a / b) * c;  // Precision lost in division
```

**Fix:**
```solidity
uint256 result = (a * c) / b;  // Multiply first
```

---

## Low Severity

### 11. Missing Zero Address Checks
```solidity
function setAdmin(address newAdmin) external onlyOwner {
    require(newAdmin != address(0), "Zero address");
    admin = newAdmin;
}
```

### 12. Floating Pragma
```solidity
// Bad
pragma solidity ^0.8.0;

// Good
pragma solidity 0.8.20;
```

### 13. Missing Event Emissions
```solidity
function setFee(uint256 newFee) external onlyOwner {
    uint256 oldFee = fee;
    fee = newFee;
    emit FeeUpdated(oldFee, newFee);  // Always emit events for state changes
}
```

---

## Quick Reference Checklist

- [ ] Reentrancy guards on external calls
- [ ] Access control on sensitive functions
- [ ] Input validation (zero address, bounds)
- [ ] Integer overflow in unchecked blocks
- [ ] Oracle manipulation resistance
- [ ] Signature replay protection
- [ ] Flash loan attack vectors
- [ ] Frontrunning considerations
- [ ] DoS resistance (no unbounded loops)
- [ ] Proper initialization
- [ ] Precision in calculations
- [ ] Event emissions
