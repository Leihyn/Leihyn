// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Aave V3 Exploit PoC Template
 * @notice Template for exploits involving Aave V3 integrations
 *
 * Common attack vectors:
 * 1. Flash loan + health factor manipulation
 * 2. eMode switching attacks
 * 3. Self-liquidation scenarios (Euler-style)
 * 4. Interest rate manipulation
 */

// Aave V3 Interfaces
interface IPool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) external returns (uint256);
    function flashLoanSimple(address receiverAddress, address asset, uint256 amount, bytes calldata params, uint16 referralCode) external;
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    );
    function setUserEMode(uint8 categoryId) external;
}

interface IPoolAddressesProvider {
    function getPool() external view returns (address);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
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

/**
 * @title AaveV3ExploitPoC
 * @notice Base template for Aave V3 exploits
 */
abstract contract AaveV3ExploitPoC is Test, IFlashLoanSimpleReceiver {
    // Mainnet addresses
    IPool constant AAVE_POOL = IPool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    // Common tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI = 0x6B175474E89094C44Da98b954EedDcDAD11091;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // aTokens (Mainnet)
    address constant aWETH = 0x4d5F47FA6A74757f35C14fD3a6Ef8E3C9BC514E8;
    address constant aUSDC = 0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
        vm.label(address(AAVE_POOL), "AaveV3Pool");
    }

    /// @notice Get user health factor
    function _getHealthFactor(address user) internal view returns (uint256) {
        (,,,,,uint256 hf) = AAVE_POOL.getUserAccountData(user);
        return hf;
    }

    /// @notice Check if position is liquidatable
    function _isLiquidatable(address user) internal view returns (bool) {
        return _getHealthFactor(user) < 1e18;
    }

    /// @notice Log position state
    function _logPosition(address user) internal view {
        (
            uint256 totalCollateral,
            uint256 totalDebt,
            uint256 availableBorrows,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        ) = AAVE_POOL.getUserAccountData(user);

        console.log("=== Position State ===");
        console.log("Collateral (USD):", totalCollateral / 1e8);
        console.log("Debt (USD):", totalDebt / 1e8);
        console.log("Available Borrows:", availableBorrows / 1e8);
        console.log("LTV:", ltv);
        console.log("Liq Threshold:", currentLiquidationThreshold);
        console.log("Health Factor:", healthFactor / 1e16, "%");
    }

    /// @notice Flash loan callback - implement attack here
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external virtual override returns (bool) {
        require(msg.sender == address(AAVE_POOL), "Invalid caller");
        require(initiator == address(this), "Invalid initiator");

        console.log("Flash loan received:", amount);

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeAttack(asset, amount, params);

        // Approve repayment
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(AAVE_POOL), amountOwed);

        return true;
    }

    /// @notice Override this with attack logic
    function _executeAttack(address asset, uint256 amount, bytes calldata params) internal virtual;
}

/**
 * @title AaveHealthFactorManipulation
 * @notice Example: Manipulate health factor via flash loan
 */
contract AaveHealthFactorManipulation is AaveV3ExploitPoC {
    function test_healthFactorManipulation() public {
        vm.startPrank(ATTACKER);

        console.log("=== Aave Health Factor Manipulation ===");

        // Setup: Give attacker some collateral
        deal(WETH, ATTACKER, 10 ether);
        IERC20(WETH).approve(address(AAVE_POOL), type(uint256).max);

        // Step 1: Supply collateral
        AAVE_POOL.supply(WETH, 10 ether, ATTACKER, 0);
        _logPosition(ATTACKER);

        // Step 2: Borrow near max
        (,,uint256 availableBorrows,,,) = AAVE_POOL.getUserAccountData(ATTACKER);
        uint256 borrowAmount = availableBorrows * 95 / 100; // 95% of max

        AAVE_POOL.borrow(USDC, borrowAmount, 2, 0, ATTACKER); // Variable rate
        _logPosition(ATTACKER);

        // Step 3: Flash loan to amplify attack
        // ...implement specific attack

        vm.stopPrank();
    }

    function _executeAttack(address asset, uint256 amount, bytes calldata) internal override {
        // Implement attack during flash loan
    }
}

/**
 * @title AaveEModeAttack
 * @notice Example: eMode switching attack
 */
contract AaveEModeAttack is AaveV3ExploitPoC {
    function test_eModeSwitch() public {
        vm.startPrank(ATTACKER);

        console.log("=== Aave eMode Switch Attack ===");

        // eMode 1 is typically ETH-correlated assets
        // Higher LTV/LT when in eMode

        // Step 1: Supply collateral in eMode
        deal(WETH, ATTACKER, 100 ether);
        IERC20(WETH).approve(address(AAVE_POOL), type(uint256).max);

        AAVE_POOL.setUserEMode(1); // Enable ETH eMode
        AAVE_POOL.supply(WETH, 100 ether, ATTACKER, 0);
        _logPosition(ATTACKER);

        // Step 2: Borrow max under eMode LTV
        (,,uint256 availableBorrows,,,) = AAVE_POOL.getUserAccountData(ATTACKER);
        console.log("Available in eMode:", availableBorrows / 1e8);

        // Step 3: Try to switch eMode (may fail if position becomes unhealthy)
        // AAVE_POOL.setUserEMode(0);

        vm.stopPrank();
    }

    function _executeAttack(address, uint256, bytes calldata) internal override {}
}
