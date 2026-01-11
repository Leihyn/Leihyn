# GMX Integration Guide

## Overview

GMX is a decentralized perpetual exchange. Key components:
- **GLP**: Liquidity provider token (basket of assets)
- **GMX**: Governance/utility token
- **Vault**: Holds assets, processes trades
- **Router**: Entry point for trades

## Architecture

```
User → Router → PositionRouter → Vault
                      ↓
               Keeper (executes)
```

## Core Concepts

### Leverage Trading
- Up to 50x leverage
- No price impact on entry (oracle-based)
- Funding rates based on utilization
- Liquidation at maintenance margin

### GLP (Liquidity)
- Multi-asset index (ETH, BTC, stables)
- LPs earn 70% of platform fees
- Minting/burning based on target weights

## Opening Positions

### Increase Position (Long/Short)

```solidity
interface IPositionRouter {
    function createIncreasePosition(
        address[] memory _path,           // Collateral path
        address _indexToken,              // Token to long/short
        uint256 _amountIn,                // Collateral amount
        uint256 _minOut,                  // Min collateral after swap
        uint256 _sizeDelta,               // Position size in USD (30 decimals)
        bool _isLong,                     // Long or short
        uint256 _acceptablePrice,         // Max/min price for long/short
        uint256 _executionFee,            // Fee for keeper
        bytes32 _referralCode,            // Referral code
        address _callbackTarget           // Callback contract
    ) external payable returns (bytes32);
}

contract GMXTrader {
    IPositionRouter public router;
    address public WETH;

    function openLongETH(uint256 sizeDelta, uint256 acceptablePrice) external payable {
        address[] memory path = new address[](1);
        path[0] = WETH;

        uint256 executionFee = router.minExecutionFee();

        router.createIncreasePosition{value: msg.value}(
            path,
            WETH,                          // Long ETH
            msg.value - executionFee,      // Collateral
            0,                             // No swap needed
            sizeDelta,                     // Size in USD * 1e30
            true,                          // isLong
            acceptablePrice,               // Max entry price
            executionFee,
            bytes32(0),
            address(0)
        );
    }
}
```

### Decrease Position (Close/Reduce)

```solidity
interface IPositionRouter {
    function createDecreasePosition(
        address[] memory _path,
        address _indexToken,
        uint256 _collateralDelta,    // Collateral to withdraw
        uint256 _sizeDelta,          // Size to decrease
        bool _isLong,
        address _receiver,
        uint256 _acceptablePrice,    // Min/max price
        uint256 _minOut,
        uint256 _executionFee,
        bool _withdrawETH,
        address _callbackTarget
    ) external payable returns (bytes32);
}
```

## Reading Position Data

```solidity
interface IVault {
    function getPosition(
        address _account,
        address _collateralToken,
        address _indexToken,
        bool _isLong
    ) external view returns (
        uint256 size,           // Position size in USD (30 decimals)
        uint256 collateral,     // Collateral in USD
        uint256 averagePrice,   // Entry price (30 decimals)
        uint256 entryFundingRate,
        uint256 reserveAmount,
        int256 realisedPnl,
        uint256 lastIncreasedTime
    );

    function getPositionDelta(
        address _account,
        address _collateralToken,
        address _indexToken,
        bool _isLong
    ) external view returns (bool hasProfit, uint256 delta);
}

contract PositionReader {
    IVault public vault;

    function getPositionInfo(address account, address indexToken, bool isLong)
        external view returns (
            uint256 size,
            uint256 collateral,
            uint256 leverage,
            int256 pnl,
            uint256 liquidationPrice
        )
    {
        (size, collateral, , , , , ) = vault.getPosition(
            account,
            isLong ? indexToken : USDC,  // Collateral token
            indexToken,
            isLong
        );

        leverage = size * 1e4 / collateral; // 4 decimals

        (bool hasProfit, uint256 delta) = vault.getPositionDelta(
            account,
            isLong ? indexToken : USDC,
            indexToken,
            isLong
        );

        pnl = hasProfit ? int256(delta) : -int256(delta);

        // Simplified liquidation price calculation
        // Real calculation is more complex
    }
}
```

## GLP Operations

### Mint GLP

```solidity
interface IGlpManager {
    function addLiquidity(
        address _token,
        uint256 _amount,
        uint256 _minUsdg,
        uint256 _minGlp
    ) external returns (uint256);

    function addLiquidityETH(
        uint256 _minUsdg,
        uint256 _minGlp
    ) external payable returns (uint256);

    function removeLiquidity(
        address _tokenOut,
        uint256 _glpAmount,
        uint256 _minOut,
        address _receiver
    ) external returns (uint256);
}

interface IRewardRouter {
    function mintAndStakeGlp(
        address _token,
        uint256 _amount,
        uint256 _minUsdg,
        uint256 _minGlp
    ) external returns (uint256);

    function mintAndStakeGlpETH(
        uint256 _minUsdg,
        uint256 _minGlp
    ) external payable returns (uint256);

    function unstakeAndRedeemGlp(
        address _tokenOut,
        uint256 _glpAmount,
        uint256 _minOut,
        address _receiver
    ) external returns (uint256);
}
```

### Claim Rewards

```solidity
interface IRewardRouter {
    function claimFees() external;
    function claimEsGmx() external;
    function compound() external; // Stake rewards

    function handleRewards(
        bool _shouldClaimGmx,
        bool _shouldStakeGmx,
        bool _shouldClaimEsGmx,
        bool _shouldStakeEsGmx,
        bool _shouldStakeMultiplierPoints,
        bool _shouldClaimWeth,
        bool _shouldConvertWethToEth
    ) external;
}
```

## Price Feeds

```solidity
interface IVaultPriceFeed {
    function getPrice(
        address _token,
        bool _maximise,
        bool _includeAmmPrice,
        bool _useSwapPricing
    ) external view returns (uint256);

    function getPrimaryPrice(
        address _token,
        bool _maximise
    ) external view returns (uint256);
}

// Prices are in 30 decimals
// $50,000 = 50000 * 1e30
```

## Key Addresses (Arbitrum)

```solidity
// Core
address constant VAULT = 0x489ee077994B6658eAfA855C308275EAd8097C4A;
address constant ROUTER = 0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064;
address constant POSITION_ROUTER = 0xb87a436B93fFE9D75c5cFA7bAcFff96430b09868;
address constant ORDER_BOOK = 0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB;

// Tokens
address constant GLP = 0x4277f8F2c384827B5273592FF7CeBd9f2C1ac258;
address constant GMX = 0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a;
address constant ES_GMX = 0xf42Ae1D54fd613C9bb14810b0588FaAa09a426cA;

// Rewards
address constant REWARD_ROUTER = 0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1;
address constant GLP_MANAGER = 0x321F653eED006AD1C29D174e17d96351BDe22649;

// Price Feed
address constant VAULT_PRICE_FEED = 0x2d68011bcA022ed0E474264145F46CC4de96a002;
```

## Fees

| Fee Type | Amount |
|----------|--------|
| Open/Close Position | 0.1% of size |
| Swap | 0.2-0.8% (dynamic) |
| Borrow (per hour) | Variable |
| Execution | ~0.0003 ETH |

## Keeper Execution

Positions are executed by keepers after a delay:

```solidity
// Check if position request exists
function pendingPositions(bytes32 key) external view returns (bool);

// Keepers call these:
function executeIncreasePosition(bytes32 _key, address payable _executionFeeReceiver) external;
function executeDecreasePosition(bytes32 _key, address payable _executionFeeReceiver) external;
```

## Security Considerations

1. **Execution Delay**: Positions aren't instant, price can move
2. **Liquidation**: Monitor health factor
3. **Oracle Risk**: GMX uses custom oracle with Chainlink backup
4. **GLP Risk**: IL from trader PnL (traders win = GLP loses)
5. **Cooldown**: 15 min cooldown on GLP after minting
