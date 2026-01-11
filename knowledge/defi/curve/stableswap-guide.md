# Curve Finance Integration Guide

## Overview

Curve is an AMM optimized for stablecoins and pegged assets using the StableSwap invariant.

## Key Concepts

### StableSwap Invariant
```
A * n^n * sum(x_i) + D = A * D * n^n + D^(n+1) / (n^n * prod(x_i))
```
Where:
- `A` = Amplification coefficient (higher = more like constant sum)
- `n` = Number of tokens
- `D` = Total deposits (invariant)
- `x_i` = Balance of token i

### Pool Types

| Type | Use Case | Example |
|------|----------|---------|
| Plain Pool | Same-peg stables | 3pool (DAI/USDC/USDT) |
| Lending Pool | Yield-bearing | aave pool |
| Metapool | Pair against base pool | FRAX/3CRV |
| Crypto Pool (V2) | Volatile pairs | tricrypto |

## Core Integration

### Get Pool Info

```solidity
interface ICurvePool {
    function A() external view returns (uint256);
    function get_virtual_price() external view returns (uint256);
    function balances(uint256 i) external view returns (uint256);
    function coins(uint256 i) external view returns (address);
    function fee() external view returns (uint256); // 1e10 = 100%
}
```

### Swap Tokens

```solidity
interface ICurvePool {
    // For plain pools
    function exchange(
        int128 i,      // Input token index
        int128 j,      // Output token index
        uint256 dx,    // Input amount
        uint256 min_dy // Minimum output (slippage protection)
    ) external returns (uint256);

    // For pools with ETH
    function exchange(
        int128 i,
        int128 j,
        uint256 dx,
        uint256 min_dy
    ) external payable returns (uint256);
}

contract CurveSwapper {
    ICurvePool public constant POOL_3CRV = ICurvePool(0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7);

    // Swap DAI (index 0) to USDC (index 1)
    function swapDAItoUSDC(uint256 amount, uint256 minOut) external {
        IERC20(DAI).transferFrom(msg.sender, address(this), amount);
        IERC20(DAI).approve(address(POOL_3CRV), amount);

        uint256 received = POOL_3CRV.exchange(0, 1, amount, minOut);
        IERC20(USDC).transfer(msg.sender, received);
    }
}
```

### Add Liquidity

```solidity
interface ICurvePool {
    function add_liquidity(
        uint256[3] calldata amounts,  // Array size = num tokens
        uint256 min_mint_amount
    ) external returns (uint256);

    function remove_liquidity(
        uint256 _amount,
        uint256[3] calldata min_amounts
    ) external returns (uint256[3] memory);

    function remove_liquidity_one_coin(
        uint256 _token_amount,
        int128 i,
        uint256 min_amount
    ) external returns (uint256);
}
```

### Calculate Expected Output

```solidity
interface ICurvePool {
    function get_dy(
        int128 i,
        int128 j,
        uint256 dx
    ) external view returns (uint256);

    function calc_token_amount(
        uint256[3] calldata amounts,
        bool deposit
    ) external view returns (uint256);

    function calc_withdraw_one_coin(
        uint256 _token_amount,
        int128 i
    ) external view returns (uint256);
}
```

## Gauge & Rewards (veTokenomics)

### Staking LP Tokens

```solidity
interface ICurveGauge {
    function deposit(uint256 _value) external;
    function withdraw(uint256 _value) external;
    function claim_rewards() external;
    function claimable_reward(address _user, address _token) external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

contract CurveStaker {
    IERC20 public lpToken;
    ICurveGauge public gauge;

    function stake(uint256 amount) external {
        lpToken.transferFrom(msg.sender, address(this), amount);
        lpToken.approve(address(gauge), amount);
        gauge.deposit(amount);
    }

    function unstake(uint256 amount) external {
        gauge.withdraw(amount);
        lpToken.transfer(msg.sender, amount);
    }

    function claimRewards() external {
        gauge.claim_rewards();
        // Transfer rewards to user
    }
}
```

### Vote-Escrowed CRV (veCRV)

```solidity
interface IVotingEscrow {
    function create_lock(uint256 _value, uint256 _unlock_time) external;
    function increase_amount(uint256 _value) external;
    function increase_unlock_time(uint256 _unlock_time) external;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}
```

## Key Addresses (Ethereum Mainnet)

```solidity
// Pools
address constant POOL_3CRV = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;
address constant POOL_STETH = 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022;
address constant POOL_FRAX = 0xd632f22692FaC7611d2AA1C0D552930D43CAEd3B;
address constant POOL_TRICRYPTO = 0xD51a44d3FaE010294C616388b506AcdA1bfAAE46;

// LP Tokens
address constant LP_3CRV = 0x6c3F90f043a72FA612cbac8115EE7e52BDe6E490;

// Governance
address constant CRV = 0xD533a949740bb3306d119CC777fa900bA034cd52;
address constant VECRV = 0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2;

// Router
address constant CURVE_ROUTER = 0x99a58482BD75cbab83b27EC03CA68fF489b5788f;
```

## Router (Multi-Pool Swaps)

```solidity
interface ICurveRouter {
    function exchange(
        address[9] calldata _route,
        uint256[3][4] calldata _swap_params,
        uint256 _amount,
        uint256 _expected
    ) external payable returns (uint256);

    function get_exchange_amount(
        address[9] calldata _route,
        uint256[3][4] calldata _swap_params,
        uint256 _amount
    ) external view returns (uint256);
}
```

## CryptoSwap (V2) - Volatile Pairs

```solidity
interface ICryptoSwap {
    function exchange(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 min_dy
    ) external payable returns (uint256);

    function get_dy(uint256 i, uint256 j, uint256 dx) external view returns (uint256);

    function price_oracle() external view returns (uint256);
    function price_scale() external view returns (uint256);
}
```

## Security Considerations

1. **Virtual Price Manipulation**: Don't use `get_virtual_price()` for pricing in same tx
2. **Read-Only Reentrancy**: Some pools have reentrancy in view functions
3. **Slippage**: Always use `min_dy` / `min_mint_amount`
4. **Token Indices**: Different pools have different orderings
5. **Fee Calculation**: Fee is in 1e10 basis (1e8 = 1%)

## Common Patterns

### Get Best Rate Across Pools

```solidity
function getBestRate(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) external view returns (address bestPool, uint256 bestAmount) {
    address[] memory pools = getPoolsForPair(tokenIn, tokenOut);

    for (uint256 i = 0; i < pools.length; i++) {
        try ICurvePool(pools[i]).get_dy(
            getTokenIndex(pools[i], tokenIn),
            getTokenIndex(pools[i], tokenOut),
            amountIn
        ) returns (uint256 amount) {
            if (amount > bestAmount) {
                bestAmount = amount;
                bestPool = pools[i];
            }
        } catch {}
    }
}
```
