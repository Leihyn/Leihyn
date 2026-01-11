// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../foundry/base_test.sol";

// Aave V3 interfaces
interface IPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;

    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// Uniswap V3 interfaces
interface IUniswapV3Pool {
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external;
}

// Balancer interface
interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

/**
 * @title FlashLoanPoC
 * @notice Template for flash loan attack PoCs using Aave V3
 *
 * USAGE:
 * 1. Fork mainnet: vm.createSelectFork("mainnet", BLOCK_NUMBER);
 * 2. Implement _executeAttack() with exploit logic
 * 3. Run: forge test --match-test test_flashLoanAttack -vvvv --fork-url $RPC
 */
abstract contract FlashLoanPoC is BaseExploitTest, IFlashLoanSimpleReceiver {
    IPool constant AAVE_POOL = IPool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    // Attack parameters
    address internal flashToken;
    uint256 internal flashAmount;

    function setUp() public virtual {
        // Fork mainnet
        // vm.createSelectFork("mainnet", 18_500_000);

        // Default flash loan token
        flashToken = WETH;
        flashAmount = 10_000 ether;

        vm.label(address(AAVE_POOL), "AaveV3Pool");
    }

    /// @notice Main exploit entry point
    function test_flashLoanAttack() public asAttacker {
        uint256 tokenBefore = _balanceOf(flashToken, ATTACKER);
        console.log("=== Starting Flash Loan Attack ===");
        console.log("Borrowing:", flashAmount / 1e18, "tokens");

        // Request flash loan
        AAVE_POOL.flashLoanSimple(
            address(this),
            flashToken,
            flashAmount,
            "", // params
            0   // referral code
        );

        uint256 tokenAfter = _balanceOf(flashToken, ATTACKER);
        _logProfit(flashToken, tokenBefore, tokenAfter);
    }

    /// @notice Aave flash loan callback - implement attack here
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        require(msg.sender == address(AAVE_POOL), "Invalid caller");
        require(initiator == address(this), "Invalid initiator");

        console.log("Flash loan received:", amount / 1e18);
        console.log("Premium to pay:", premium / 1e18);

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeAttack(asset, amount);

        // Approve repayment
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(AAVE_POOL), amountOwed);

        console.log("Repaying:", amountOwed / 1e18);
        return true;
    }

    /// @notice Override this with actual attack logic
    function _executeAttack(address asset, uint256 amount) internal virtual;
}

/**
 * @title UniswapFlashPoC
 * @notice Template for flash loan attack using Uniswap V3
 */
abstract contract UniswapFlashPoC is BaseExploitTest, IUniswapV3FlashCallback {
    IUniswapV3Pool internal flashPool;

    function test_uniswapFlashAttack() public asAttacker {
        console.log("=== Starting Uniswap Flash Attack ===");

        // Get amounts to flash
        (uint256 amount0, uint256 amount1) = _getFlashAmounts();

        flashPool.flash(
            address(this),
            amount0,
            amount1,
            "" // data
        );
    }

    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external override {
        require(msg.sender == address(flashPool), "Invalid caller");

        console.log("Uniswap flash received");
        console.log("Fee0:", fee0);
        console.log("Fee1:", fee1);

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeUniswapAttack();

        // Repay flash loan + fees
        _repayFlashLoan(fee0, fee1);
    }

    function _getFlashAmounts() internal virtual returns (uint256 amount0, uint256 amount1);
    function _executeUniswapAttack() internal virtual;
    function _repayFlashLoan(uint256 fee0, uint256 fee1) internal virtual;
}

/**
 * @title BalancerFlashPoC
 * @notice Template for flash loan attack using Balancer
 */
abstract contract BalancerFlashPoC is BaseExploitTest, IFlashLoanRecipient {
    IBalancerVault constant BALANCER_VAULT = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function test_balancerFlashAttack() public asAttacker {
        console.log("=== Starting Balancer Flash Attack ===");

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);

        (tokens[0], amounts[0]) = _getFlashParams();

        BALANCER_VAULT.flashLoan(
            address(this),
            tokens,
            amounts,
            "" // userData
        );
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external override {
        require(msg.sender == address(BALANCER_VAULT), "Invalid caller");

        console.log("Balancer flash received");

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeBalancerAttack(tokens, amounts);

        // Repay (Balancer has 0 fees!)
        for (uint i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).transfer(address(BALANCER_VAULT), amounts[i] + feeAmounts[i]);
        }
    }

    function _getFlashParams() internal virtual returns (address token, uint256 amount);
    function _executeBalancerAttack(address[] memory tokens, uint256[] memory amounts) internal virtual;
}

// Minimal ERC20 interface
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
