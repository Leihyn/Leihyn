// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Compound V3 (Comet) Exploit PoC Template
 * @notice Template for exploits involving Compound V3 integrations
 *
 * Common attack vectors:
 * 1. Absorption (liquidation) manipulation
 * 2. Interest rate manipulation
 * 3. Supply/borrow cap exploitation
 * 4. Oracle price staleness
 * 5. Collateral factor edge cases
 */

// Compound V3 (Comet) Interfaces
interface IComet {
    function supply(address asset, uint256 amount) external;
    function supplyTo(address dst, address asset, uint256 amount) external;
    function withdraw(address asset, uint256 amount) external;
    function withdrawTo(address to, address asset, uint256 amount) external;
    function withdrawFrom(address src, address to, address asset, uint256 amount) external;

    function absorb(address absorber, address[] calldata accounts) external;
    function buyCollateral(address asset, uint256 minAmount, uint256 baseAmount, address recipient) external;

    function balanceOf(address account) external view returns (int256);
    function borrowBalanceOf(address account) external view returns (uint256);

    function isLiquidatable(address account) external view returns (bool);
    function isBorrowCollateralized(address account) external view returns (bool);

    function getUtilization() external view returns (uint256);
    function getSupplyRate(uint256 utilization) external view returns (uint256);
    function getBorrowRate(uint256 utilization) external view returns (uint256);

    function getAssetInfo(uint8 i) external view returns (AssetInfo memory);
    function getAssetInfoByAddress(address asset) external view returns (AssetInfo memory);
    function numAssets() external view returns (uint8);

    function getPrice(address priceFeed) external view returns (uint256);
    function baseToken() external view returns (address);
    function baseTokenPriceFeed() external view returns (address);

    function userCollateral(address account, address asset) external view returns (uint128, uint128);
    function totalsCollateral(address asset) external view returns (uint128, uint128);

    function quoteCollateral(address asset, uint256 baseAmount) external view returns (uint256);
}

struct AssetInfo {
    uint8 offset;
    address asset;
    address priceFeed;
    uint64 scale;
    uint64 borrowCollateralFactor;
    uint64 liquidateCollateralFactor;
    uint64 liquidationFactor;
    uint128 supplyCap;
}

interface ICometRewards {
    function claim(address comet, address src, bool shouldAccrue) external;
    function getRewardOwed(address comet, address account) external returns (address token, uint256 owed);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title CompoundV3ExploitPoC
 * @notice Base template for Compound V3 exploits
 */
abstract contract CompoundV3ExploitPoC is Test {
    // Mainnet Comet deployments
    IComet constant COMET_USDC = IComet(0xc3d688B66703497DAA19211EEdff47f25384cdc3);
    IComet constant COMET_WETH = IComet(0xA17581A9E3356d9A858b789D68B4d866e593aE94);

    // Common tokens
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address constant COMP = 0xc00e94Cb662C3520282E6f5717214004A7f26888;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
        vm.label(address(COMET_USDC), "Comet_USDC");
    }

    /// @notice Log account state
    function _logAccountState(IComet comet, address account) internal view {
        console.log("=== Account State ===");
        console.log("Base balance (signed):", comet.balanceOf(account));
        console.log("Borrow balance:", comet.borrowBalanceOf(account));
        console.log("Is liquidatable:", comet.isLiquidatable(account));
        console.log("Is borrow collateralized:", comet.isBorrowCollateralized(account));
    }

    /// @notice Log protocol state
    function _logProtocolState(IComet comet) internal view {
        uint256 utilization = comet.getUtilization();
        console.log("=== Protocol State ===");
        console.log("Utilization:", utilization);
        console.log("Supply rate:", comet.getSupplyRate(utilization));
        console.log("Borrow rate:", comet.getBorrowRate(utilization));
    }
}

/**
 * @title AbsorptionManipulation
 * @notice Manipulate accounts into absorption (liquidation)
 *
 * Compound V3 uses "absorption" instead of traditional liquidation.
 * Absorbed collateral is sold to the protocol reserves.
 */
contract AbsorptionManipulation is CompoundV3ExploitPoC {
    function test_absorptionMechanism() public {
        vm.startPrank(ATTACKER);

        console.log("=== Absorption Mechanism Analysis ===");

        // Check available collateral types
        uint8 numAssets = COMET_USDC.numAssets();
        console.log("Number of collateral assets:", numAssets);

        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = COMET_USDC.getAssetInfo(i);
            console.log("\nAsset:", info.asset);
            console.log("Borrow collateral factor:", info.borrowCollateralFactor);
            console.log("Liquidate collateral factor:", info.liquidateCollateralFactor);
            console.log("Liquidation factor:", info.liquidationFactor);
            console.log("Supply cap:", info.supplyCap);
        }

        console.log("\n=== Absorption Attack Vectors ===");
        console.log("1. Oracle manipulation to trigger absorption");
        console.log("2. Mass absorption for discount buying");
        console.log("3. Self-absorption for accounting tricks");

        vm.stopPrank();
    }

    function test_absorptionProfit() public view {
        console.log("=== Absorption Profit Analysis ===");
        console.log("");
        console.log("Absorbers can buy collateral at a discount:");
        console.log("discount = 1 - liquidationFactor");
        console.log("");
        console.log("Example with 10% discount:");
        console.log("1. Account has $1000 WETH collateral, $900 debt");
        console.log("2. Price drops, HF < 1, account absorbed");
        console.log("3. Absorber can buy $1000 WETH for $900 worth of USDC");
        console.log("4. Profit: $100 (10% discount)");
        console.log("");
        console.log("MEV opportunity: front-run absorption + buyCollateral");
    }
}

/**
 * @title InterestRateManipulation
 * @notice Manipulate interest rates via utilization
 */
contract InterestRateManipulation is CompoundV3ExploitPoC {
    function test_interestRateCurve() public view {
        console.log("=== Interest Rate Analysis ===");

        // Sample utilization rates
        uint256[] memory utilizations = new uint256[](5);
        utilizations[0] = 0;
        utilizations[1] = 0.5e18;  // 50%
        utilizations[2] = 0.8e18;  // 80% (typically near kink)
        utilizations[3] = 0.9e18;  // 90%
        utilizations[4] = 1e18;    // 100%

        console.log("Utilization -> Supply Rate, Borrow Rate");
        for (uint256 i = 0; i < utilizations.length; i++) {
            uint256 supplyRate = COMET_USDC.getSupplyRate(utilizations[i]);
            uint256 borrowRate = COMET_USDC.getBorrowRate(utilizations[i]);
            console.log(utilizations[i] / 1e16, "% ->", supplyRate, borrowRate);
        }

        console.log("\n=== Rate Manipulation Attack ===");
        console.log("1. Identify low-utilization market");
        console.log("2. Flash loan large supply");
        console.log("3. Push utilization to extreme");
        console.log("4. Existing borrowers pay high rates");
        console.log("5. Or: push down rates for arbitrage");
    }

    function test_utilizationManipulation() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 1000 ether);

        console.log("=== Utilization Manipulation ===");

        // Current state
        uint256 currentUtil = COMET_USDC.getUtilization();
        console.log("Current utilization:", currentUtil / 1e16, "%");

        // Large supply would lower utilization
        // Large borrow would raise utilization

        console.log("\nManipulation cost analysis:");
        console.log("To move utilization 10% requires:");
        console.log("1. Flash loan ~10% of total supply");
        console.log("2. Supply or borrow the amount");
        console.log("3. Execute target action at manipulated rate");
        console.log("4. Reverse position");

        vm.stopPrank();
    }
}

/**
 * @title SupplyCapExploitation
 * @notice Exploit supply cap edge cases
 */
contract SupplyCapExploitation is CompoundV3ExploitPoC {
    function test_supplyCapAnalysis() public view {
        console.log("=== Supply Cap Analysis ===");

        uint8 numAssets = COMET_USDC.numAssets();
        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = COMET_USDC.getAssetInfo(i);
            (uint128 totalSupply,) = COMET_USDC.totalsCollateral(info.asset);

            console.log("\nAsset:", info.asset);
            console.log("Supply cap:", info.supplyCap);
            console.log("Current supply:", totalSupply);
            console.log("Remaining capacity:", uint256(info.supplyCap) - uint256(totalSupply));

            if (totalSupply > info.supplyCap * 90 / 100) {
                console.log("WARNING: Near supply cap!");
            }
        }

        console.log("\n=== Cap Exploitation Vectors ===");
        console.log("1. Front-run deposits to hit cap");
        console.log("2. DOS other users from depositing");
        console.log("3. Manipulate collateral availability");
    }
}

/**
 * @title OracleStaleness
 * @notice Oracle price staleness attacks
 */
contract OracleStaleness is CompoundV3ExploitPoC {
    function test_oracleAnalysis() public view {
        console.log("=== Oracle Analysis ===");

        // Get base token price feed
        address basePriceFeed = COMET_USDC.baseTokenPriceFeed();
        console.log("Base token price feed:", basePriceFeed);

        // Get collateral price feeds
        uint8 numAssets = COMET_USDC.numAssets();
        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = COMET_USDC.getAssetInfo(i);
            console.log("\nAsset:", info.asset);
            console.log("Price feed:", info.priceFeed);

            uint256 price = COMET_USDC.getPrice(info.priceFeed);
            console.log("Current price:", price);
        }

        console.log("\n=== Staleness Attack Vectors ===");
        console.log("1. Monitor oracle for staleness");
        console.log("2. If stale during volatility:");
        console.log("   - Borrow at favorable rate");
        console.log("   - Avoid liquidation with stale price");
        console.log("   - Exit when oracle updates");
    }
}

/**
 * @title CollateralFactorEdgeCases
 * @notice Edge cases in collateral factor calculations
 */
contract CollateralFactorEdgeCases is CompoundV3ExploitPoC {
    function test_collateralFactorEdges() public view {
        console.log("=== Collateral Factor Edge Cases ===");

        uint8 numAssets = COMET_USDC.numAssets();
        for (uint8 i = 0; i < numAssets; i++) {
            AssetInfo memory info = COMET_USDC.getAssetInfo(i);
            uint64 bcf = info.borrowCollateralFactor;
            uint64 lcf = info.liquidateCollateralFactor;

            console.log("\nAsset:", info.asset);
            console.log("Borrow CF:", bcf);
            console.log("Liquidate CF:", lcf);
            console.log("Buffer:", uint256(lcf) - uint256(bcf));

            // Small buffer = easier to push into liquidation
            if (lcf - bcf < 0.05e18) {
                console.log("WARNING: Small liquidation buffer!");
            }
        }

        console.log("\n=== Edge Case Attacks ===");
        console.log("1. Positions at exact borrow CF boundary");
        console.log("2. Rounding issues in collateral calculations");
        console.log("3. Multi-collateral factor optimization");
    }
}

/**
 * @title FlashLoanWithComet
 * @notice Using Compound V3 for/in flash loan attacks
 */
contract FlashLoanWithComet is CompoundV3ExploitPoC {
    function test_cometWithFlashLoan() public view {
        console.log("=== Compound V3 + Flash Loan Attacks ===");
        console.log("");
        console.log("Attack patterns:");
        console.log("");
        console.log("1. Flash Supply Attack");
        console.log("   - Flash loan large amount");
        console.log("   - Supply to Comet as collateral");
        console.log("   - Borrow base token");
        console.log("   - Execute attack with borrowed funds");
        console.log("   - Repay and withdraw collateral");
        console.log("");
        console.log("2. Flash Liquidation");
        console.log("   - Flash loan base token");
        console.log("   - Absorb underwater account");
        console.log("   - Buy collateral at discount");
        console.log("   - Sell collateral for profit");
        console.log("   - Repay flash loan");
        console.log("");
        console.log("3. Rate Manipulation");
        console.log("   - Flash loan and supply");
        console.log("   - Lower utilization = lower borrow rate");
        console.log("   - Borrow at reduced rate");
        console.log("   - Withdraw flash-supplied funds");
    }
}

/**
 * @title VulnerableCometIntegration
 * @notice Example of vulnerable Comet integration
 */
contract VulnerableCometIntegration {
    IComet public comet;

    constructor(address _comet) {
        comet = IComet(_comet);
    }

    /// @notice VULNERABLE: Doesn't check if position is healthy
    function leverageUp(address collateral, uint256 amount) external {
        // Supply collateral
        IERC20(collateral).transferFrom(msg.sender, address(this), amount);
        IERC20(collateral).approve(address(comet), amount);
        comet.supply(collateral, amount);

        // Borrow maximum - VULNERABLE: no health check!
        address base = comet.baseToken();
        uint256 borrowAmount = comet.quoteCollateral(collateral, amount) * 80 / 100;
        comet.withdraw(base, borrowAmount);

        // User gets borrowed funds but position may be unhealthy
        IERC20(base).transfer(msg.sender, borrowAmount);
    }
}

/**
 * @title SafeCometIntegration
 * @notice Example of safe Comet integration
 */
contract SafeCometIntegration {
    IComet public comet;

    constructor(address _comet) {
        comet = IComet(_comet);
    }

    /// @notice SAFE: Checks position health
    function leverageUp(address collateral, uint256 amount, uint256 maxBorrow) external {
        // Supply collateral
        IERC20(collateral).transferFrom(msg.sender, address(this), amount);
        IERC20(collateral).approve(address(comet), amount);
        comet.supply(collateral, amount);

        // Calculate safe borrow amount
        address base = comet.baseToken();
        uint256 maxSafeBorrow = comet.quoteCollateral(collateral, amount) * 75 / 100; // 75% to be safe
        uint256 borrowAmount = maxBorrow < maxSafeBorrow ? maxBorrow : maxSafeBorrow;

        // Borrow
        comet.withdraw(base, borrowAmount);

        // IMPORTANT: Verify position is healthy!
        require(comet.isBorrowCollateralized(address(this)), "Position unhealthy");

        IERC20(base).transfer(msg.sender, borrowAmount);
    }
}
