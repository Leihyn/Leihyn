// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title GMX V2 Exploit PoC Template
 * @notice Template for exploits involving GMX perpetual protocol
 *
 * Common attack vectors:
 * 1. Price impact manipulation
 * 2. Funding rate exploitation
 * 3. Oracle latency arbitrage
 * 4. Keeper MEV extraction
 * 5. Liquidation manipulation
 */

// GMX V2 Interfaces
interface IExchangeRouter {
    struct CreateOrderParams {
        CreateOrderParamsAddresses addresses;
        CreateOrderParamsNumbers numbers;
        bytes32 orderType;
        bytes32 decreasePositionSwapType;
        bool isLong;
        bool shouldUnwrapNativeToken;
        bytes32 referralCode;
    }

    struct CreateOrderParamsAddresses {
        address receiver;
        address callbackContract;
        address uiFeeReceiver;
        address market;
        address initialCollateralToken;
        address[] swapPath;
    }

    struct CreateOrderParamsNumbers {
        uint256 sizeDeltaUsd;
        uint256 initialCollateralDeltaAmount;
        uint256 triggerPrice;
        uint256 acceptablePrice;
        uint256 executionFee;
        uint256 callbackGasLimit;
        uint256 minOutputAmount;
    }

    function createOrder(CreateOrderParams calldata params) external payable returns (bytes32);
    function cancelOrder(bytes32 key) external;
}

interface IReader {
    function getMarket(address dataStore, address marketAddress) external view returns (Market memory);
    function getPosition(address dataStore, bytes32 key) external view returns (Position memory);
    function getPositionInfo(
        address dataStore,
        address referralStorage,
        bytes32 positionKey,
        MarketPrices memory prices,
        uint256 sizeDeltaUsd,
        address uiFeeReceiver,
        bool usePositionSizeAsSizeDeltaUsd
    ) external view returns (PositionInfo memory);
}

struct Market {
    address marketToken;
    address indexToken;
    address longToken;
    address shortToken;
}

struct Position {
    address account;
    address market;
    address collateralToken;
    bool isLong;
    uint256 sizeInUsd;
    uint256 sizeInTokens;
    uint256 collateralAmount;
    uint256 increasedAtBlock;
    uint256 decreasedAtBlock;
}

struct MarketPrices {
    PriceProps indexTokenPrice;
    PriceProps longTokenPrice;
    PriceProps shortTokenPrice;
}

struct PriceProps {
    uint256 min;
    uint256 max;
}

struct PositionInfo {
    Position position;
    PositionFees fees;
    int256 pnlUsd;
    int256 uncappedPnlUsd;
}

struct PositionFees {
    uint256 positionFeeAmount;
    uint256 borrowingFeeAmount;
    uint256 fundingFeeAmount;
}

interface IOrderHandler {
    function executeOrder(bytes32 key, OracleParams calldata oracleParams) external;
}

struct OracleParams {
    address[] tokens;
    address[] providers;
    bytes[] data;
}

interface IDataStore {
    function getUint(bytes32 key) external view returns (uint256);
    function getAddress(bytes32 key) external view returns (address);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title GMXExploitPoC
 * @notice Base template for GMX exploits
 */
abstract contract GMXExploitPoC is Test {
    // Arbitrum addresses (GMX is primarily on Arbitrum)
    address constant EXCHANGE_ROUTER = 0x7C68C7866A64FA2160F78EEaE12217FFbf871fa8;
    address constant READER = 0xf60becbba223EEA9495Da3f606753867eC10d139;
    address constant DATA_STORE = 0xFD70de6b91282D8017aA4E741e9Ae325CAb992d8;
    address constant ORDER_HANDLER = 0x352f684ab9e97a6321a13CF03A61316B681D9fD2;

    // Markets
    address constant ETH_USD_MARKET = 0x70d95587d40A2caf56bd97485aB3Eec10Bee6336;
    address constant BTC_USD_MARKET = 0x47c031236e19d024b42f8AE6780E44A573170703;

    // Tokens
    address constant WETH = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
    address constant USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;
    address constant WBTC = 0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork Arbitrum
        vm.createSelectFork("arbitrum", 150_000_000);
    }

    /// @notice Log position state
    function _logPosition(bytes32 positionKey) internal view {
        console.log("=== Position State ===");
        console.log("Position key:", uint256(positionKey));
        // Read position from datastore
    }
}

/**
 * @title PriceImpactManipulation
 * @notice Manipulate price impact for profit
 *
 * GMX has price impact based on open interest imbalance.
 * Large positions can manipulate this for profit.
 */
contract PriceImpactManipulation is GMXExploitPoC {
    function test_priceImpactAnalysis() public view {
        console.log("=== Price Impact Manipulation ===");
        console.log("");
        console.log("GMX price impact is calculated based on:");
        console.log("1. Open interest imbalance (long vs short)");
        console.log("2. Position size relative to pool");
        console.log("3. Impact pool size");
        console.log("");
        console.log("Attack vectors:");
        console.log("1. Open large position in one direction");
        console.log("2. Price impact shifts in that direction");
        console.log("3. Open opposite position at favorable price");
        console.log("4. Close original position");
        console.log("5. Profit from price impact differential");
        console.log("");
        console.log("Mitigations:");
        console.log("- Maximum price impact caps");
        console.log("- Time-weighted position changes");
        console.log("- Impact pool reserves");
    }

    function test_priceImpactCalculation() public view {
        console.log("=== Price Impact Calculation ===");
        console.log("");
        console.log("Price impact = impactExponent * (sizeDelta / poolSize) ^ 2");
        console.log("");
        console.log("Example:");
        console.log("Pool size: $100M");
        console.log("Position: $10M");
        console.log("Impact factor: 0.1%");
        console.log("Price impact: 0.1% * (10/100)^2 = 0.001%");
        console.log("");
        console.log("For large positions:");
        console.log("Position: $50M");
        console.log("Price impact: 0.1% * (50/100)^2 = 0.025%");
    }
}

/**
 * @title FundingRateExploitation
 * @notice Exploit funding rate imbalances
 *
 * When open interest is heavily skewed, funding rates
 * can create profitable opportunities.
 */
contract FundingRateExploitation is GMXExploitPoC {
    function test_fundingRateAnalysis() public view {
        console.log("=== Funding Rate Exploitation ===");
        console.log("");
        console.log("Funding rate mechanism:");
        console.log("- Longs pay shorts when long OI > short OI");
        console.log("- Shorts pay longs when short OI > long OI");
        console.log("- Rate proportional to imbalance");
        console.log("");
        console.log("Attack vectors:");
        console.log("1. Identify heavily skewed markets");
        console.log("2. Take opposite side (receiving funding)");
        console.log("3. Hedge on other venue");
        console.log("4. Collect funding while delta-neutral");
        console.log("");
        console.log("Risk factors:");
        console.log("- Funding rates can reverse quickly");
        console.log("- Hedging costs on other venues");
        console.log("- Liquidation risk on GMX position");
    }

    function test_fundingRateArbitrage() public view {
        console.log("=== Funding Rate Arbitrage ===");
        console.log("");
        console.log("Cross-venue funding arbitrage:");
        console.log("1. GMX longs paying 0.1%/day");
        console.log("2. Binance shorts paying 0.05%/day");
        console.log("");
        console.log("Strategy:");
        console.log("1. Short on GMX (receive 0.1%/day)");
        console.log("2. Long on Binance (pay 0.05%/day)");
        console.log("3. Net profit: 0.05%/day delta-neutral");
        console.log("");
        console.log("Considerations:");
        console.log("- Funding timing differences");
        console.log("- Margin requirements on both venues");
        console.log("- Exchange risk");
    }
}

/**
 * @title OracleLatencyArbitrage
 * @notice Exploit oracle price update delays
 *
 * GMX uses Chainlink oracles with some latency.
 * Fast actors can exploit this.
 */
contract OracleLatencyArbitrage is GMXExploitPoC {
    function test_oracleLatencyAttack() public view {
        console.log("=== Oracle Latency Arbitrage ===");
        console.log("");
        console.log("GMX oracle update flow:");
        console.log("1. CEX price moves");
        console.log("2. Chainlink nodes detect change");
        console.log("3. Nodes submit to blockchain");
        console.log("4. GMX uses updated price");
        console.log("");
        console.log("Latency window: 1-30 seconds typically");
        console.log("");
        console.log("Attack (if execution is too fast):");
        console.log("1. Monitor CEX for large price move");
        console.log("2. Open position on GMX BEFORE oracle updates");
        console.log("3. Execute with stale (favorable) price");
        console.log("4. Profit from price correction");
        console.log("");
        console.log("GMX mitigations:");
        console.log("- Keeper-based execution (not instant)");
        console.log("- Price bounds on order acceptance");
        console.log("- Two-phase order (create then execute)");
    }
}

/**
 * @title KeeperMEV
 * @notice MEV extraction by keepers
 *
 * GMX keepers execute orders and can extract value
 * through order sequencing and price selection.
 */
contract KeeperMEV is GMXExploitPoC {
    function test_keeperMEVVectors() public view {
        console.log("=== Keeper MEV Vectors ===");
        console.log("");
        console.log("Keepers can extract value through:");
        console.log("");
        console.log("1. Order Sequencing");
        console.log("   - Execute liquidations before limit orders");
        console.log("   - Prioritize orders by tip amount");
        console.log("");
        console.log("2. Price Selection");
        console.log("   - Choose min/max price within bounds");
        console.log("   - Favor certain order directions");
        console.log("");
        console.log("3. Timing Games");
        console.log("   - Delay execution to unfavorable price");
        console.log("   - Speed up execution for favorable price");
        console.log("");
        console.log("User protections:");
        console.log("- Set tight acceptable price bounds");
        console.log("- Use block.timestamp-based deadlines");
        console.log("- Monitor pending order queue");
    }
}

/**
 * @title LiquidationManipulation
 * @notice Manipulate positions into liquidation
 */
contract LiquidationManipulation is GMXExploitPoC {
    function test_liquidationAttack() public view {
        console.log("=== Liquidation Manipulation ===");
        console.log("");
        console.log("Attack vectors:");
        console.log("");
        console.log("1. Flash Crash Liquidation");
        console.log("   - Large market order to push price");
        console.log("   - Trigger liquidations at extreme price");
        console.log("   - Liquidation penalty goes to liquidator");
        console.log("");
        console.log("2. Funding Rate Accumulation");
        console.log("   - Push OI imbalance via large position");
        console.log("   - Existing positions accrue high funding");
        console.log("   - Positions become liquidatable over time");
        console.log("");
        console.log("3. Collateral Token Manipulation");
        console.log("   - If collateral is manipulable token");
        console.log("   - Crash collateral value");
        console.log("   - Positions become under-collateralized");
        console.log("");
        console.log("GMX protections:");
        console.log("- Min collateral requirements");
        console.log("- Max leverage caps");
        console.log("- Gradual liquidation (ADL)");
    }
}

/**
 * @title PositionSizeLimit
 * @notice Analyze position size limits and their implications
 */
contract PositionSizeLimit is GMXExploitPoC {
    function test_positionLimits() public view {
        console.log("=== Position Size Analysis ===");
        console.log("");
        console.log("GMX position limits:");
        console.log("- Max leverage: 50x typically");
        console.log("- Max position size: Market-dependent");
        console.log("- Max open interest per side");
        console.log("");
        console.log("Attack consideration:");
        console.log("If limits are too high relative to liquidity,");
        console.log("single actors can manipulate markets.");
        console.log("");
        console.log("Check:");
        console.log("- Max position / Pool liquidity ratio");
        console.log("- Max OI / Pool liquidity ratio");
        console.log("- Single actor position concentration");
    }
}

/**
 * @title ADLVictimization
 * @notice Auto-deleveraging (ADL) exploitation
 */
contract ADLVictimization is GMXExploitPoC {
    function test_adlAttack() public view {
        console.log("=== ADL (Auto-Deleverage) Attack ===");
        console.log("");
        console.log("ADL triggers when profitable positions");
        console.log("exceed available liquidity to pay them.");
        console.log("");
        console.log("Attack vector:");
        console.log("1. Open large profitable position");
        console.log("2. Push price further in your direction");
        console.log("3. Pool can't pay full profit");
        console.log("4. Opposing positions get ADL'd");
        console.log("");
        console.log("Victim impact:");
        console.log("- Forced position closure");
        console.log("- May close at unfavorable price");
        console.log("- Trading strategy disrupted");
        console.log("");
        console.log("This is a designed feature, not a bug.");
        console.log("But can be weaponized against specific users.");
    }
}

/**
 * @title GMXIntegrationChecklist
 * @notice Checklist for auditing GMX integrations
 */
contract GMXIntegrationChecklist is GMXExploitPoC {
    function test_integrationChecklist() public view {
        console.log("=== GMX Integration Audit Checklist ===");
        console.log("");
        console.log("1. Price Handling");
        console.log("   [ ] Acceptable price bounds set?");
        console.log("   [ ] Min/max price spread handled?");
        console.log("   [ ] Oracle staleness checked?");
        console.log("");
        console.log("2. Order Management");
        console.log("   [ ] Order cancellation possible?");
        console.log("   [ ] Failed order handling?");
        console.log("   [ ] Execution timeout handling?");
        console.log("");
        console.log("3. Position Management");
        console.log("   [ ] Liquidation risk monitored?");
        console.log("   [ ] ADL risk considered?");
        console.log("   [ ] Funding rate exposure managed?");
        console.log("");
        console.log("4. Callback Security");
        console.log("   [ ] Callback caller validated?");
        console.log("   [ ] Reentrancy protection?");
        console.log("   [ ] Gas limit considerations?");
        console.log("");
        console.log("5. Economic Security");
        console.log("   [ ] Flash loan attack resistant?");
        console.log("   [ ] Price impact bounds?");
        console.log("   [ ] Maximum position sizes?");
    }
}
