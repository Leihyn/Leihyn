# Solidity Gas Optimization Tricks

## Storage Optimizations

### 1. Pack Storage Variables
```solidity
// Bad: 3 storage slots (96 bytes)
uint256 a;    // slot 0
uint128 b;    // slot 1
uint128 c;    // slot 2

// Good: 2 storage slots (64 bytes)
uint256 a;    // slot 0
uint128 b;    // slot 1 (first half)
uint128 c;    // slot 1 (second half)
```

### 2. Use Smaller Types When Possible
```solidity
// For timestamps (good until year 2106)
uint32 timestamp;  // Instead of uint256

// For percentages (0-10000 = 0-100.00%)
uint16 basisPoints;  // Instead of uint256

// For small counters
uint8 count;  // If max is 255
```

### 3. Use Constants and Immutables
```solidity
// Costs 0 gas to read (inlined at compile time)
uint256 public constant FEE = 100;

// Costs ~100 gas to read (stored in bytecode)
uint256 public immutable deployTime;

// Costs ~2100 gas cold, ~100 gas warm (stored in storage)
uint256 public fee;
```

### 4. Cache Storage in Memory
```solidity
// Bad: Multiple storage reads (~2100 gas each cold)
function bad() external {
    for (uint i = 0; i < array.length; i++) {  // storage read each iteration
        total += array[i];
    }
}

// Good: Cache in memory
function good() external {
    uint256[] memory _array = array;  // One storage read
    uint256 len = _array.length;
    for (uint i = 0; i < len; i++) {
        total += _array[i];
    }
}
```

---

## Calldata Optimizations

### 5. Use calldata for External Function Arrays
```solidity
// Bad: Copies to memory (~60 gas per element)
function bad(uint256[] memory data) external { }

// Good: Reads directly from calldata (~3 gas per element)
function good(uint256[] calldata data) external { }
```

### 6. Use bytes32 Instead of string
```solidity
// Expensive: Dynamic type
string public name = "MyToken";

// Cheap: Fixed size
bytes32 public constant NAME = "MyToken";
```

---

## Logic Optimizations

### 7. Short-Circuit Conditions
```solidity
// Put cheaper/more likely to fail conditions first
require(amount > 0 && balanceOf[msg.sender] >= amount);
//       ↑ cheap       ↑ storage read (expensive)
```

### 8. Use Unchecked for Safe Math
```solidity
// When you know overflow is impossible
function increment(uint256 i) internal pure returns (uint256) {
    unchecked {
        return i + 1;  // Saves ~100 gas
    }
}

// Common pattern for loops
for (uint256 i; i < length;) {
    // ...
    unchecked { ++i; }
}
```

### 9. ++i is Cheaper than i++
```solidity
// Bad
for (uint i = 0; i < 10; i++) { }

// Good
for (uint i; i < 10; ++i) { }

// Best
for (uint i; i < 10;) {
    // ...
    unchecked { ++i; }
}
```

### 10. Use != 0 Instead of > 0
```solidity
// For unsigned integers
require(amount != 0);  // Slightly cheaper than > 0
```

---

## ERC20 Optimizations

### 11. Use Solmate/Solady Instead of OpenZeppelin
```solidity
// OpenZeppelin ERC20 transfer: ~51,000 gas
// Solmate ERC20 transfer: ~42,000 gas
// Solady ERC20 transfer: ~40,000 gas
```

### 12. Batch Operations
```solidity
// Bad: Multiple transfers
function badAirdrop(address[] calldata to, uint256 amount) external {
    for (uint i; i < to.length;) {
        transfer(to[i], amount);
        unchecked { ++i; }
    }
}

// Good: Single state update where possible
function goodAirdrop(address[] calldata to, uint256 amount) external {
    uint256 totalAmount = amount * to.length;
    balanceOf[msg.sender] -= totalAmount;

    for (uint i; i < to.length;) {
        balanceOf[to[i]] += amount;
        emit Transfer(msg.sender, to[i], amount);
        unchecked { ++i; }
    }
}
```

---

## Advanced Tricks

### 13. Transient Storage (EIP-1153)
```solidity
// Solidity 0.8.24+
// Only persists for the transaction, much cheaper
assembly {
    tstore(0, value)  // Store
    let v := tload(0) // Load
}
```

### 14. Use Assembly for Simple Operations
```solidity
// Checking if address is contract
function isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly {
        size := extcodesize(account)
    }
    return size > 0;
}
```

### 15. Custom Errors Instead of Strings
```solidity
// Bad: ~100+ gas per character
require(success, "Transfer failed");

// Good: ~24 gas
error TransferFailed();
if (!success) revert TransferFailed();
```

### 16. Use Mappings Instead of Arrays for Lookups
```solidity
// Bad: O(n) lookup
address[] public whitelist;

// Good: O(1) lookup
mapping(address => bool) public isWhitelisted;
```

---

## Gas Cost Reference

| Operation | Gas Cost |
|-----------|----------|
| SSTORE (0 → non-zero) | 22,100 |
| SSTORE (non-zero → non-zero) | 5,000 |
| SSTORE (non-zero → 0) | 5,000 + 4,800 refund |
| SLOAD (cold) | 2,100 |
| SLOAD (warm) | 100 |
| CALL (cold) | 2,600 |
| CALL (warm) | 100 |
| Memory expansion | 3 per word + quadratic |
| Calldata | 4 per zero byte, 16 per non-zero |
| LOG | 375 + 375 per topic + 8 per byte |
