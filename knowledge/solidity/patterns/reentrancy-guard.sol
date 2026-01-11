// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyGuard Pattern
 * @notice Prevents reentrant calls to a function
 * @dev Use the `nonReentrant` modifier on functions that make external calls
 */

// Pattern 1: OpenZeppelin Style
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

// Pattern 2: Transient Storage (EIP-1153) - More gas efficient (Solidity 0.8.24+)
abstract contract ReentrancyGuardTransient {
    bytes32 private constant _REENTRANCY_SLOT = keccak256("reentrancy.guard");

    modifier nonReentrant() {
        assembly {
            if tload(_REENTRANCY_SLOT) { revert(0, 0) }
            tstore(_REENTRANCY_SLOT, 1)
        }
        _;
        assembly {
            tstore(_REENTRANCY_SLOT, 0)
        }
    }
}

// Pattern 3: Checks-Effects-Interactions (CEI)
// No modifier needed - just follow the pattern:
contract CEIPattern {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        // 1. CHECKS - Validate inputs and state
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 2. EFFECTS - Update state BEFORE external calls
        balances[msg.sender] -= amount;

        // 3. INTERACTIONS - External calls LAST
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

/*
 * WHEN TO USE:
 * - Functions that make external calls (call, transfer, send)
 * - Functions that call untrusted contracts
 * - Callback functions (ERC721 onERC721Received, etc.)
 *
 * GAS COSTS:
 * - OpenZeppelin style: ~2600 gas (cold) / ~200 gas (warm)
 * - Transient storage: ~200 gas (always)
 * - CEI pattern: 0 gas overhead
 */
