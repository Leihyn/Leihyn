// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title BaseExploitTest
 * @notice Base contract for all exploit PoCs with common utilities
 */
abstract contract BaseExploitTest is Test {
    // Common addresses
    address constant ATTACKER = address(0xBAD);
    address constant VICTIM = address(0xDEAD);
    address constant PROTOCOL = address(0xC0DE);

    // Common tokens (mainnet)
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI = 0x6B175474E89094C44Da98b954EeseDcDAD11091;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // Flash loan providers
    address constant AAVE_V3_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant UNISWAP_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

    // Profit tracking
    uint256 internal initialAttackerBalance;
    uint256 internal finalAttackerBalance;

    modifier asAttacker() {
        vm.startPrank(ATTACKER);
        _;
        vm.stopPrank();
    }

    modifier asVictim() {
        vm.startPrank(VICTIM);
        _;
        vm.stopPrank();
    }

    modifier trackProfit() {
        initialAttackerBalance = ATTACKER.balance;
        _;
        finalAttackerBalance = ATTACKER.balance;
        _logProfit();
    }

    function _logProfit() internal view {
        if (finalAttackerBalance > initialAttackerBalance) {
            console.log("=== EXPLOIT SUCCESSFUL ===");
            console.log("Profit (ETH):", (finalAttackerBalance - initialAttackerBalance) / 1e18);
        } else {
            console.log("=== EXPLOIT FAILED ===");
        }
    }

    function _logProfit(address token, uint256 before, uint256 after_) internal view {
        if (after_ > before) {
            console.log("=== EXPLOIT SUCCESSFUL ===");
            console.log("Token:", token);
            console.log("Profit:", after_ - before);
        }
    }

    // Common setup helpers
    function _dealToken(address token, address to, uint256 amount) internal {
        deal(token, to, amount);
    }

    function _dealETH(address to, uint256 amount) internal {
        deal(to, amount);
    }

    function _label(address addr, string memory name) internal {
        vm.label(addr, name);
    }

    // Balance helpers
    function _balanceOf(address token, address account) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", account)
        );
        require(success, "balanceOf failed");
        return abi.decode(data, (uint256));
    }

    // Timestamp manipulation
    function _skipTime(uint256 seconds_) internal {
        skip(seconds_);
    }

    function _setTimestamp(uint256 timestamp) internal {
        vm.warp(timestamp);
    }

    // Block manipulation
    function _skipBlocks(uint256 blocks) internal {
        vm.roll(block.number + blocks);
    }
}
