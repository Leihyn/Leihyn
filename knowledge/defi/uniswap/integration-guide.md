# The Complete Guide to Uniswap Integration: From V3 Concentrated Liquidity to V4 Hooks

Uniswap has fundamentally shaped how we think about on-chain liquidity. With V3's concentrated liquidity and V4's hook architecture, the protocol offers unprecedented flexibility for DeFi builders. This guide walks through practical integration patterns for both versions, from basic swaps to building custom hooks.

---

## Understanding the Evolution

**Uniswap V2** gave us the constant product formula (`x * y = k`) - simple, elegant, but capital inefficient. Liquidity was spread uniformly across all prices from 0 to infinity.

**Uniswap V3** introduced concentrated liquidity, allowing LPs to allocate capital within specific price ranges. This increased capital efficiency by up to 4000x for stablecoin pairs, but at the cost of complexity.

**Uniswap V4** takes a different approach - instead of adding features directly, it provides hooks: customization points that let developers extend pool behavior. Want dynamic fees? Build a hook. Custom oracles? Hook. On-chain limit orders? Also a hook.

---

## Part 1: Uniswap V3 Integration

### Core Architecture

V3's architecture centers around a few key contracts:

```
┌─────────────────┐     ┌──────────────────┐
│  SwapRouter     │────>│  Pool            │
└─────────────────┘     │  - Concentrated  │
                        │    Liquidity     │
┌─────────────────┐     │  - Tick System   │
│  NFTPositionMgr │────>│  - Fee Tiers     │
└─────────────────┘     └──────────────────┘
                               │
                               v
                        ┌──────────────────┐
                        │  Factory         │
                        │  - Pool Creation │
                        │  - Fee Config    │
                        └──────────────────┘
```

- **Factory**: Deploys and tracks pools
- **Pool**: Holds liquidity, executes swaps
- **SwapRouter**: Routes trades across pools
- **NonfungiblePositionManager**: Manages LP positions as NFTs

### The Tick System

V3 divides the price space into discrete "ticks". Each tick represents a 0.01% price movement. Liquidity only exists between tick boundaries chosen by LPs.

```solidity
// Price to tick conversion
// tick = log(sqrt(price)) / log(sqrt(1.0001))
// For price = $2000 (ETH/USDC), tick ≈ 74959

// Tick spacing depends on fee tier:
// 0.01% fee = 1 tick spacing (stablecoins)
// 0.05% fee = 10 tick spacing
// 0.30% fee = 60 tick spacing
// 1.00% fee = 200 tick spacing
```

### Executing Swaps

The most common integration pattern - swapping tokens through Uniswap:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UniswapV3Swapper {
    ISwapRouter public immutable swapRouter;

    // Fee tiers available
    uint24 public constant FEE_LOWEST = 100;    // 0.01%
    uint24 public constant FEE_LOW = 500;       // 0.05%
    uint24 public constant FEE_MEDIUM = 3000;   // 0.30%
    uint24 public constant FEE_HIGH = 10000;    // 1.00%

    constructor(address _swapRouter) {
        swapRouter = ISwapRouter(_swapRouter);
    }

    /// @notice Swap exact input amount for maximum output
    function swapExactInput(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountIn,
        uint256 amountOutMinimum
    ) external returns (uint256 amountOut) {
        // Transfer tokens from user
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(address(swapRouter), amountIn);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: fee,
                recipient: msg.sender,
                deadline: block.timestamp + 15 minutes,
                amountIn: amountIn,
                amountOutMinimum: amountOutMinimum,  // Slippage protection
                sqrtPriceLimitX96: 0  // No price limit
            });

        amountOut = swapRouter.exactInputSingle(params);
    }

    /// @notice Swap minimum input for exact output amount
    function swapExactOutput(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountOut,
        uint256 amountInMaximum
    ) external returns (uint256 amountIn) {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountInMaximum);
        IERC20(tokenIn).approve(address(swapRouter), amountInMaximum);

        ISwapRouter.ExactOutputSingleParams memory params = ISwapRouter
            .ExactOutputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: fee,
                recipient: msg.sender,
                deadline: block.timestamp + 15 minutes,
                amountOut: amountOut,
                amountInMaximum: amountInMaximum,
                sqrtPriceLimitX96: 0
            });

        amountIn = swapRouter.exactOutputSingle(params);

        // Refund excess tokens
        uint256 excess = amountInMaximum - amountIn;
        if (excess > 0) {
            IERC20(tokenIn).transfer(msg.sender, excess);
        }
    }
}
```

### Multi-Hop Swaps

When direct pools don't exist or offer poor rates, route through intermediate tokens:

```solidity
/// @notice Execute multi-hop swap (e.g., USDC -> WETH -> ARB)
function swapMultiHop(
    bytes memory path,      // Encoded path: tokenA, fee, tokenB, fee, tokenC
    uint256 amountIn,
    uint256 amountOutMinimum
) external returns (uint256 amountOut) {
    IERC20 tokenIn = IERC20(toAddress(path, 0));
    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenIn.approve(address(swapRouter), amountIn);

    ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams({
        path: path,
        recipient: msg.sender,
        deadline: block.timestamp + 15 minutes,
        amountIn: amountIn,
        amountOutMinimum: amountOutMinimum
    });

    amountOut = swapRouter.exactInput(params);
}

// Path encoding helper
function encodePath(
    address tokenA,
    uint24 fee1,
    address tokenB,
    uint24 fee2,
    address tokenC
) public pure returns (bytes memory) {
    return abi.encodePacked(tokenA, fee1, tokenB, fee2, tokenC);
}
```

### Providing Liquidity

V3 positions are NFTs, managed through the NonfungiblePositionManager:

```solidity
import {INonfungiblePositionManager} from "@uniswap/v3-periphery/contracts/interfaces/INonfungiblePositionManager.sol";

contract V3LiquidityProvider {
    INonfungiblePositionManager public immutable positionManager;

    /// @notice Create a new liquidity position
    function mintPosition(
        address token0,
        address token1,
        uint24 fee,
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0Desired,
        uint256 amount1Desired
    ) external returns (
        uint256 tokenId,
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1
    ) {
        // Transfer tokens
        IERC20(token0).transferFrom(msg.sender, address(this), amount0Desired);
        IERC20(token1).transferFrom(msg.sender, address(this), amount1Desired);

        // Approve position manager
        IERC20(token0).approve(address(positionManager), amount0Desired);
        IERC20(token1).approve(address(positionManager), amount1Desired);

        INonfungiblePositionManager.MintParams memory params =
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: fee,
                tickLower: tickLower,
                tickUpper: tickUpper,
                amount0Desired: amount0Desired,
                amount1Desired: amount1Desired,
                amount0Min: 0,  // Set appropriate slippage in production
                amount1Min: 0,
                recipient: msg.sender,
                deadline: block.timestamp + 15 minutes
            });

        (tokenId, liquidity, amount0, amount1) = positionManager.mint(params);

        // Refund unused tokens
        _refundExcess(token0, amount0Desired - amount0);
        _refundExcess(token1, amount1Desired - amount1);
    }

    /// @notice Calculate tick range for a percentage around current price
    function calculateTickRange(
        address pool,
        uint256 percentageWidth  // e.g., 500 = 5%
    ) external view returns (int24 tickLower, int24 tickUpper) {
        (, int24 currentTick,,,,,) = IUniswapV3Pool(pool).slot0();
        int24 tickSpacing = IUniswapV3Pool(pool).tickSpacing();

        int24 tickDelta = int24(int256(percentageWidth) * 100); // Approximate

        tickLower = ((currentTick - tickDelta) / tickSpacing) * tickSpacing;
        tickUpper = ((currentTick + tickDelta) / tickSpacing) * tickSpacing;
    }
}
```

### Reading Pool State

```solidity
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

    function liquidity() external view returns (uint128);
    function tickSpacing() external view returns (int24);
    function fee() external view returns (uint24);
}

contract V3PoolReader {
    /// @notice Get current price from sqrtPriceX96
    function getPrice(address pool) external view returns (uint256 price) {
        (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();

        // price = (sqrtPriceX96 / 2^96)^2
        // For token0/token1 price with decimal adjustment
        price = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) * 1e18 >> 192;
    }

    /// @notice Get TWAP price for manipulation resistance
    function getTWAP(address pool, uint32 secondsAgo) external view returns (int24 avgTick) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = secondsAgo;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);

        avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(secondsAgo)));
    }
}
```

### V3 Key Addresses

```solidity
// Ethereum Mainnet
address constant V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
address constant V3_SWAP_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
address constant V3_SWAP_ROUTER_02 = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;
address constant V3_POSITION_MANAGER = 0xC36442b4a4522E871399CD717aBDD847Ab11FE88;
address constant V3_QUOTER = 0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6;
address constant V3_QUOTER_V2 = 0x61fFE014bA17989E743c5F6cB21bF9697530B21e;

// Base
address constant BASE_V3_FACTORY = 0x33128a8fC17869897dcE68Ed026d694621f6FDfD;
address constant BASE_V3_SWAP_ROUTER = 0x2626664c2603336E57B271c5C0b26F421741e481;

// Arbitrum
address constant ARB_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
address constant ARB_V3_SWAP_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
```

---

## Part 2: Uniswap V4 Integration

V4 represents a paradigm shift. Instead of many pool contracts, there's a single **PoolManager** (singleton) that manages all pools. The real innovation is **hooks** - contracts that can inject custom logic at key points in a pool's lifecycle.

### V4 Architecture

```
                    ┌─────────────────────────────────────┐
                    │           PoolManager               │
                    │  (Singleton - manages ALL pools)    │
                    │                                     │
                    │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐   │
                    │  │Pool1│ │Pool2│ │Pool3│ │Pool4│   │
                    │  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘   │
                    └─────┼──────┼──────┼──────┼────────┘
                          │      │      │      │
                          v      v      v      v
                       ┌─────────────────────────────┐
                       │         Hooks               │
                       │  beforeSwap / afterSwap     │
                       │  beforeAddLiquidity / after │
                       │  beforeRemoveLiquidity      │
                       │  beforeDonate / afterDonate │
                       │  beforeInitialize / after   │
                       └─────────────────────────────┘
```

### Hook Lifecycle

Hooks can intercept operations at these points:

| Hook | When Called | Common Use Cases |
|------|-------------|------------------|
| `beforeInitialize` | Pool creation | Validation, setup |
| `afterInitialize` | After pool created | Oracle initialization |
| `beforeAddLiquidity` | LP deposits | KYC checks, limits |
| `afterAddLiquidity` | After deposit | Reward tracking |
| `beforeRemoveLiquidity` | LP withdrawals | Lockup enforcement |
| `afterRemoveLiquidity` | After withdrawal | Fee distribution |
| `beforeSwap` | Before each swap | Dynamic fees, access control |
| `afterSwap` | After each swap | Analytics, rebates |
| `beforeDonate` | Before donation | Validation |
| `afterDonate` | After donation | Reward distribution |

### Building Your First Hook

Hooks must be deployed to addresses where specific bits are set, indicating which hooks are enabled. This is enforced at the protocol level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/BaseHook.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";

contract VolumeTrackingHook is BaseHook {
    using PoolIdLibrary for PoolKey;

    // Track volume per pool
    mapping(PoolId => uint256) public poolVolume;

    // Track volume per user
    mapping(PoolId => mapping(address => uint256)) public userVolume;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    /// @notice Declare which hooks this contract implements
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,        // We only need afterSwap
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /// @notice Called after every swap - track volume
    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external override returns (bytes4, int128) {
        PoolId poolId = key.toId();

        // Calculate absolute swap amount
        uint256 swapAmount = params.amountSpecified < 0
            ? uint256(-params.amountSpecified)
            : uint256(params.amountSpecified);

        // Update tracking
        poolVolume[poolId] += swapAmount;
        userVolume[poolId][sender] += swapAmount;

        return (BaseHook.afterSwap.selector, 0);
    }
}
```

### Dynamic Fee Hook

One of the most powerful V4 patterns - adjusting fees based on market conditions:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/BaseHook.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";

/// @title Dynamic Fee Hook
/// @notice Adjusts swap fees based on volatility and volume
contract DynamicFeeHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using LPFeeLibrary for uint24;

    // Fee bounds (in hundredths of a bip, so 3000 = 0.30%)
    uint24 public constant MIN_FEE = 500;      // 0.05%
    uint24 public constant MAX_FEE = 10000;    // 1.00%
    uint24 public constant BASE_FEE = 3000;    // 0.30%

    // Volatility tracking
    mapping(PoolId => uint256) public lastPrice;
    mapping(PoolId => uint256) public volatilityAccumulator;
    mapping(PoolId => uint256) public lastUpdateBlock;

    // Volume tracking for fee calculation
    mapping(PoolId => uint256) public recentVolume;
    uint256 public constant VOLUME_THRESHOLD_HIGH = 1000 ether;
    uint256 public constant VOLUME_THRESHOLD_LOW = 100 ether;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: true,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,       // Need to set dynamic fee
            afterSwap: true,        // Update volatility tracking
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function afterInitialize(
        address,
        PoolKey calldata key,
        uint160 sqrtPriceX96,
        int24,
        bytes calldata
    ) external override returns (bytes4) {
        PoolId poolId = key.toId();
        lastPrice[poolId] = sqrtPriceX96;
        lastUpdateBlock[poolId] = block.number;
        return BaseHook.afterInitialize.selector;
    }

    function beforeSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        bytes calldata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        PoolId poolId = key.toId();

        // Calculate dynamic fee based on conditions
        uint24 dynamicFee = calculateDynamicFee(poolId);

        // Return fee with override flag
        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            dynamicFee | LPFeeLibrary.OVERRIDE_FEE_FLAG
        );
    }

    function afterSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta,
        bytes calldata
    ) external override returns (bytes4, int128) {
        PoolId poolId = key.toId();

        // Update volume tracking
        uint256 swapAmount = params.amountSpecified < 0
            ? uint256(-params.amountSpecified)
            : uint256(params.amountSpecified);

        // Decay old volume and add new
        if (block.number > lastUpdateBlock[poolId]) {
            uint256 blocksPassed = block.number - lastUpdateBlock[poolId];
            recentVolume[poolId] = recentVolume[poolId] / (1 + blocksPassed / 100);
        }
        recentVolume[poolId] += swapAmount;

        // Update price for volatility calculation
        (uint160 sqrtPriceX96,,,) = poolManager.getSlot0(poolId);

        if (lastPrice[poolId] > 0) {
            uint256 priceChange = sqrtPriceX96 > lastPrice[poolId]
                ? sqrtPriceX96 - lastPrice[poolId]
                : lastPrice[poolId] - sqrtPriceX96;

            // EMA of volatility
            volatilityAccumulator[poolId] =
                (volatilityAccumulator[poolId] * 95 + priceChange * 5) / 100;
        }

        lastPrice[poolId] = sqrtPriceX96;
        lastUpdateBlock[poolId] = block.number;

        return (BaseHook.afterSwap.selector, 0);
    }

    function calculateDynamicFee(PoolId poolId) internal view returns (uint24) {
        uint256 vol = volatilityAccumulator[poolId];
        uint256 volume = recentVolume[poolId];

        uint24 fee = BASE_FEE;

        // Increase fee during high volatility
        if (vol > 1e15) {
            fee += 2000;  // +0.20%
        } else if (vol > 1e14) {
            fee += 1000;  // +0.10%
        }

        // Decrease fee during high volume (attract more trades)
        if (volume > VOLUME_THRESHOLD_HIGH) {
            fee = fee > 1000 ? fee - 1000 : MIN_FEE;
        }
        // Increase fee during low volume (protect LPs)
        else if (volume < VOLUME_THRESHOLD_LOW) {
            fee += 500;
        }

        // Clamp to bounds
        if (fee < MIN_FEE) fee = MIN_FEE;
        if (fee > MAX_FEE) fee = MAX_FEE;

        return fee;
    }
}
```

### Hook Address Mining

V4 hooks must be deployed to specific addresses where bits indicate enabled hooks. Use CREATE2 with a salt to mine the correct address:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Hooks} from "v4-core/libraries/Hooks.sol";

contract HookMiner {
    /// @notice Find a salt that produces a hook address with correct flags
    function findSalt(
        address deployer,
        bytes32 initCodeHash,
        uint160 flags,
        uint256 startSalt
    ) external pure returns (bytes32 salt, address hookAddress) {
        for (uint256 i = startSalt; i < startSalt + 10000; i++) {
            salt = bytes32(i);
            hookAddress = computeAddress(deployer, salt, initCodeHash);

            if (uint160(hookAddress) & Hooks.ALL_HOOK_MASK == flags) {
                return (salt, hookAddress);
            }
        }
        revert("No valid salt found");
    }

    function computeAddress(
        address deployer,
        bytes32 salt,
        bytes32 initCodeHash
    ) public pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash)
                    )
                )
            )
        );
    }
}
```

### Swapping on V4

V4 uses a callback pattern for swaps:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {IUnlockCallback} from "v4-core/interfaces/callback/IUnlockCallback.sol";

contract V4Swapper is IUnlockCallback {
    using CurrencyLibrary for Currency;

    IPoolManager public immutable poolManager;

    struct SwapCallbackData {
        PoolKey key;
        IPoolManager.SwapParams params;
        address sender;
    }

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    function swap(
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params
    ) external returns (BalanceDelta delta) {
        // Unlock triggers the callback where we execute the swap
        delta = abi.decode(
            poolManager.unlock(abi.encode(SwapCallbackData(key, params, msg.sender))),
            (BalanceDelta)
        );
    }

    function unlockCallback(bytes calldata data) external override returns (bytes memory) {
        require(msg.sender == address(poolManager), "Not pool manager");

        SwapCallbackData memory swapData = abi.decode(data, (SwapCallbackData));

        // Execute the swap
        BalanceDelta delta = poolManager.swap(swapData.key, swapData.params, "");

        // Settle balances
        // If delta is negative, we owe tokens to the pool
        // If delta is positive, pool owes us tokens

        int128 delta0 = delta.amount0();
        int128 delta1 = delta.amount1();

        if (delta0 < 0) {
            // We owe token0 to pool
            swapData.key.currency0.transfer(address(poolManager), uint128(-delta0));
            poolManager.settle(swapData.key.currency0);
        } else if (delta0 > 0) {
            // Pool owes us token0
            poolManager.take(swapData.key.currency0, swapData.sender, uint128(delta0));
        }

        if (delta1 < 0) {
            swapData.key.currency1.transfer(address(poolManager), uint128(-delta1));
            poolManager.settle(swapData.key.currency1);
        } else if (delta1 > 0) {
            poolManager.take(swapData.key.currency1, swapData.sender, uint128(delta1));
        }

        return abi.encode(delta);
    }
}
```

### V4 Key Addresses

```solidity
// V4 is still being deployed - these are testnet/sepolia addresses
// Check official docs for latest mainnet addresses

// Base Sepolia
address constant BASE_SEPOLIA_POOL_MANAGER = 0x7Da1D65F8B249183667cdE74C5CBD46dD38AA829;

// Sepolia
address constant SEPOLIA_POOL_MANAGER = 0xE8E23e97Fa135823143d6b9Cba9c699040D51F70;
```

---

## Part 3: Security Considerations

### Price Oracle Manipulation

Never use spot prices for critical operations:

```solidity
// DANGEROUS: Spot price can be manipulated in a single transaction
function getSpotPrice(address pool) external view returns (uint256) {
    (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();
    return uint256(sqrtPriceX96) * uint256(sqrtPriceX96) >> 192;
}

// SAFE: Use TWAP for manipulation resistance
function getTWAPPrice(address pool, uint32 twapInterval) external view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapInterval)));

    // Convert tick to price
    return getTickPrice(avgTick);
}
```

### Slippage Protection

Always implement slippage checks:

```solidity
function swap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut  // Critical: caller-specified minimum
) external {
    // ... swap logic ...

    require(amountOut >= minAmountOut, "Slippage exceeded");
}
```

### Deadline Protection

Prevent stale transactions from executing:

```solidity
modifier checkDeadline(uint256 deadline) {
    require(block.timestamp <= deadline, "Transaction too old");
    _;
}
```

### Hook Security (V4)

When building hooks, consider:

1. **Reentrancy**: Hooks are called mid-operation; use reentrancy guards
2. **Access Control**: Validate that `msg.sender` is the PoolManager
3. **Gas Limits**: Hooks add gas overhead; keep logic efficient
4. **State Consistency**: Don't assume state between hooks

```solidity
contract SecureHook is BaseHook {
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function afterSwap(...) external override noReentrant returns (...) {
        require(msg.sender == address(poolManager), "Only pool manager");
        // ... logic ...
    }
}
```

---

## Part 4: Testing Patterns

### Foundry Fork Testing

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";

contract UniswapIntegrationTest is Test {
    ISwapRouter router = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WHALE = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;

    function setUp() public {
        vm.createSelectFork("mainnet", 18000000);
    }

    function testSwapETHforUSDC() public {
        uint256 amountIn = 1 ether;

        vm.deal(address(this), amountIn);

        // Wrap ETH
        (bool success,) = WETH.call{value: amountIn}("");
        require(success);

        IERC20(WETH).approve(address(router), amountIn);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: WETH,
                tokenOut: USDC,
                fee: 3000,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            });

        uint256 amountOut = router.exactInputSingle(params);

        assertGt(amountOut, 0, "Should receive USDC");
        console.log("Received USDC:", amountOut);
    }
}
```

### V4 Hook Testing

```solidity
import {PoolManager} from "v4-core/PoolManager.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";

contract HookTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;

    MyHook hook;
    PoolKey poolKey;

    function setUp() public {
        // Deploy V4 infrastructure
        deployFreshManagerAndRouters();

        // Deploy hook to correct address
        address hookAddress = address(
            uint160(Hooks.AFTER_SWAP_FLAG)
        );
        deployCodeTo("MyHook.sol", abi.encode(manager), hookAddress);
        hook = MyHook(hookAddress);

        // Initialize pool
        (poolKey,) = initPool(
            currency0,
            currency1,
            hook,
            3000,
            SQRT_RATIO_1_1,
            ZERO_BYTES
        );
    }

    function testHookCalledOnSwap() public {
        // ... perform swap ...
        // ... assert hook state changed ...
    }
}
```

---

## Conclusion

Uniswap's evolution from V2's simplicity through V3's capital efficiency to V4's programmability reflects DeFi's maturation. V3 remains the workhorse for production integrations - battle-tested with deep liquidity. V4 opens new design spaces that were previously impossible or required separate contracts.

For protocol integrators, the choice depends on your needs:
- **Simple swaps**: V3 SwapRouter with proper slippage protection
- **Custom AMM logic**: V4 hooks
- **Maximum liquidity**: V3 on mainnet (for now)
- **Innovation**: V4 on newer chains

The key to successful Uniswap integration is understanding the tradeoffs: concentrated liquidity demands active management, hooks add gas overhead but enable customization, and all integrations must account for MEV and price manipulation.

---

## Resources

- [Uniswap V3 Docs](https://docs.uniswap.org/protocol/V3/introduction)
- [Uniswap V4 Docs](https://docs.uniswap.org/contracts/v4/overview)
- [V4 Core Repository](https://github.com/Uniswap/v4-core)
- [V4 Periphery Repository](https://github.com/Uniswap/v4-periphery)
- [Awesome Uniswap Hooks](https://github.com/ora-io/awesome-uniswap-hooks)
- [Hook Examples](https://github.com/Uniswap/v4-periphery/tree/main/contracts/hooks/examples)

---

*Written for developers integrating Uniswap into production DeFi applications. Last updated: December 2025*
