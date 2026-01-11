# Aave V3 Integration Guide

## Overview

Aave V3 is a decentralized lending protocol. Key contracts:
- **Pool**: Main entry point for deposits, borrows, repayments
- **PoolAddressesProvider**: Registry for protocol addresses
- **AToken**: Interest-bearing token received on deposit
- **VariableDebtToken**: Token representing variable rate debt

## Core Integration Patterns

### 1. Supply (Deposit) Assets

```solidity
import {IPool} from "@aave/v3-core/contracts/interfaces/IPool.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AaveSupplier {
    IPool public immutable pool;

    constructor(address _pool) {
        pool = IPool(_pool);
    }

    function supply(address asset, uint256 amount) external {
        // 1. Transfer tokens from user
        IERC20(asset).transferFrom(msg.sender, address(this), amount);

        // 2. Approve pool to spend
        IERC20(asset).approve(address(pool), amount);

        // 3. Supply to Aave (user receives aTokens)
        pool.supply(
            asset,           // asset address
            amount,          // amount to supply
            msg.sender,      // onBehalfOf - who receives aTokens
            0                // referralCode
        );
    }
}
```

### 2. Borrow Assets

```solidity
function borrow(address asset, uint256 amount) external {
    // Interest rate modes: 1 = Stable, 2 = Variable
    uint256 interestRateMode = 2; // Variable rate

    pool.borrow(
        asset,
        amount,
        interestRateMode,
        0,              // referralCode
        msg.sender      // onBehalfOf
    );
}
```

### 3. Repay Debt

```solidity
function repay(address asset, uint256 amount) external {
    IERC20(asset).transferFrom(msg.sender, address(this), amount);
    IERC20(asset).approve(address(pool), amount);

    pool.repay(
        asset,
        amount,         // use type(uint256).max to repay all
        2,              // interestRateMode
        msg.sender      // onBehalfOf
    );
}
```

### 4. Withdraw Assets

```solidity
function withdraw(address asset, uint256 amount) external {
    // User must have approved this contract to spend their aTokens
    pool.withdraw(
        asset,
        amount,         // use type(uint256).max to withdraw all
        msg.sender      // to
    );
}
```

## Flash Loans

### Simple Flash Loan

```solidity
import {IPoolAddressesProvider} from "@aave/v3-core/contracts/interfaces/IPoolAddressesProvider.sol";
import {FlashLoanSimpleReceiverBase} from "@aave/v3-core/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";

contract SimpleFlashLoan is FlashLoanSimpleReceiverBase {
    constructor(IPoolAddressesProvider provider)
        FlashLoanSimpleReceiverBase(provider) {}

    function executeFlashLoan(address asset, uint256 amount) external {
        POOL.flashLoanSimple(
            address(this),  // receiverAddress
            asset,
            amount,
            "",             // params
            0               // referralCode
        );
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // Your arbitrage/liquidation logic here

        // Approve repayment
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(POOL), amountOwed);

        return true;
    }
}
```

### Multi-Asset Flash Loan

```solidity
function executeMultiFlashLoan(
    address[] memory assets,
    uint256[] memory amounts
) external {
    uint256[] memory modes = new uint256[](assets.length);
    // modes: 0 = no debt, 1 = stable, 2 = variable

    POOL.flashLoan(
        address(this),
        assets,
        amounts,
        modes,
        address(this),  // onBehalfOf
        "",             // params
        0               // referralCode
    );
}
```

## Health Factor & Liquidations

### Check User Health

```solidity
function getUserHealth(address user) external view returns (
    uint256 totalCollateralBase,
    uint256 totalDebtBase,
    uint256 availableBorrowsBase,
    uint256 currentLiquidationThreshold,
    uint256 ltv,
    uint256 healthFactor
) {
    return pool.getUserAccountData(user);
}

// Health Factor < 1e18 means position can be liquidated
```

### Perform Liquidation

```solidity
function liquidate(
    address collateralAsset,
    address debtAsset,
    address user,
    uint256 debtToCover
) external {
    IERC20(debtAsset).transferFrom(msg.sender, address(this), debtToCover);
    IERC20(debtAsset).approve(address(pool), debtToCover);

    pool.liquidationCall(
        collateralAsset,
        debtAsset,
        user,
        debtToCover,    // use type(uint256).max for max
        false           // receiveAToken: false = receive underlying
    );
}
```

## Key Addresses (Mainnet)

```solidity
// Ethereum Mainnet
address constant POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
address constant POOL_ADDRESSES_PROVIDER = 0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e;

// Base
address constant POOL_BASE = 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5;

// Arbitrum
address constant POOL_ARBITRUM = 0x794a61358D6845594F94dc1DB02A252b5b4814aD;

// Optimism
address constant POOL_OPTIMISM = 0x794a61358D6845594F94dc1DB02A252b5b4814aD;
```

## E-Mode (Efficiency Mode)

E-Mode allows higher LTV for correlated assets (e.g., stablecoins):

```solidity
// Set user to E-Mode category (e.g., 1 = stablecoins)
pool.setUserEMode(1);

// Check user's E-Mode
uint256 eMode = pool.getUserEMode(msg.sender);
```

## Interest Rate Model

```solidity
import {IReserveInterestRateStrategy} from "@aave/v3-core/contracts/interfaces/IReserveInterestRateStrategy.sol";

function getInterestRates(address asset) external view returns (
    uint256 currentLiquidityRate,
    uint256 currentVariableBorrowRate
) {
    DataTypes.ReserveData memory reserve = pool.getReserveData(asset);
    return (
        reserve.currentLiquidityRate,      // APY for suppliers (in ray, 1e27)
        reserve.currentVariableBorrowRate  // APY for borrowers (in ray)
    );
}

// Convert ray to percentage: rate / 1e25 = APY%
```

## Security Considerations

1. **Reentrancy**: Aave uses checks-effects-interactions, but be careful in your integration
2. **Oracle Manipulation**: Aave uses Chainlink oracles with circuit breakers
3. **Liquidation Risk**: Monitor health factor, set up alerts
4. **Flash Loan Attacks**: Don't trust token balances mid-transaction
5. **Interest Accrual**: Interest accrues per block, amounts may differ slightly

## Testing

```solidity
// Fork mainnet for testing
vm.createSelectFork("mainnet", BLOCK_NUMBER);

// Impersonate whale for tokens
vm.prank(USDC_WHALE);
IERC20(USDC).transfer(address(this), 1_000_000e6);
```
