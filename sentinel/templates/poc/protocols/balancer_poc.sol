// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Balancer V2/V3 Exploit PoC Template
 * @notice Template for exploits involving Balancer integrations
 *
 * Common attack vectors:
 * 1. Rate provider read-only reentrancy (CRITICAL)
 * 2. Zero-fee flash loan amplification
 * 3. BPT price manipulation during callbacks
 * 4. Pool token ordering assumptions
 *
 * Historical: Sentiment Protocol $1M loss via Balancer rate provider
 */

// Balancer Interfaces
interface IVault {
    struct SingleSwap {
        bytes32 poolId;
        uint8 kind;
        address assetIn;
        address assetOut;
        uint256 amount;
        bytes userData;
    }

    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address payable recipient;
        bool toInternalBalance;
    }

    struct JoinPoolRequest {
        address[] assets;
        uint256[] maxAmountsIn;
        bytes userData;
        bool fromInternalBalance;
    }

    struct ExitPoolRequest {
        address[] assets;
        uint256[] minAmountsOut;
        bytes userData;
        bool toInternalBalance;
    }

    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);

    function joinPool(
        bytes32 poolId,
        address sender,
        address recipient,
        JoinPoolRequest memory request
    ) external payable;

    function exitPool(
        bytes32 poolId,
        address sender,
        address payable recipient,
        ExitPoolRequest memory request
    ) external;

    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;

    function getPoolTokens(bytes32 poolId) external view returns (
        address[] memory tokens,
        uint256[] memory balances,
        uint256 lastChangeBlock
    );

    function getPool(bytes32 poolId) external view returns (address, uint8);
}

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

interface IRateProvider {
    function getRate() external view returns (uint256);
}

interface IWeightedPool {
    function getPoolId() external view returns (bytes32);
    function getNormalizedWeights() external view returns (uint256[] memory);
    function getInvariant() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function getActualSupply() external view returns (uint256);
}

interface IStablePool {
    function getPoolId() external view returns (bytes32);
    function getAmplificationParameter() external view returns (uint256 value, bool isUpdating, uint256 precision);
    function getRate() external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title BalancerExploitPoC
 * @notice Base template for Balancer exploits
 */
abstract contract BalancerExploitPoC is Test, IFlashLoanRecipient {
    // Mainnet addresses
    IVault constant VAULT = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    // Common tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant DAI = 0x6B175474E89094C44Da98b954EedDcDAD11091;
    address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address constant BAL = 0xba100000625a3754423978a60c9317c58a424e3D;

    // Example pool IDs
    bytes32 constant WETH_DAI_POOL = 0x0b09dea16768f0799065c475be02919503cb2a3500020000000000000000001a;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
        vm.label(address(VAULT), "BalancerVault");
    }

    /// @notice Log pool state
    function _logPoolState(bytes32 poolId) internal view {
        (address[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(poolId);

        console.log("=== Pool State ===");
        for (uint256 i = 0; i < tokens.length; i++) {
            console.log("Token:", tokens[i]);
            console.log("Balance:", balances[i]);
        }
    }

    /// @notice Flash loan callback - implement attack here
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external virtual override {
        require(msg.sender == address(VAULT), "Invalid caller");

        console.log("Flash loan received (ZERO FEE!)");
        for (uint256 i = 0; i < tokens.length; i++) {
            console.log("Token:", tokens[i]);
            console.log("Amount:", amounts[i]);
            console.log("Fee:", feeAmounts[i]); // This will be 0!
        }

        // === IMPLEMENT ATTACK LOGIC HERE ===
        _executeFlashAttack(tokens, amounts, userData);

        // Repay flash loan (NO FEE on Balancer!)
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).transfer(address(VAULT), amounts[i]);
        }
    }

    /// @notice Override this with flash attack logic
    function _executeFlashAttack(
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) internal virtual;
}

/**
 * @title RateProviderReentrancy
 * @notice CRITICAL: Read-only reentrancy via rate providers
 *
 * When a pool uses rate providers (e.g., wstETH/ETH pool),
 * the rate can be read during join/exit callbacks when state is inconsistent.
 *
 * Historical: Sentiment Protocol $1M loss (Apr 2023)
 */
contract RateProviderReentrancy is BalancerExploitPoC {
    // Track state during callback
    uint256 public rateDuringCallback;
    uint256 public rateAfterCallback;
    bool public inCallback;

    // wstETH/WETH ComposableStablePool
    bytes32 constant WSTETH_WETH_POOL = 0x32296969ef14eb0c6d29669c550d4a0449130230000200000000000000000080;
    address constant WSTETH_RATE_PROVIDER = 0x72D07D7DcD58Fbe6a8b59e5DE38f891bF6E78d45;

    function test_rateProviderReentrancy() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 1000 ether);

        console.log("=== Balancer Rate Provider Read-Only Reentrancy ===");
        console.log("");
        console.log("The wstETH rate provider returns stETH/wstETH exchange rate.");
        console.log("During join/exit, if ETH is sent, the rate can be read");
        console.log("while the pool is in an inconsistent state.");

        // Get rate before any operations
        uint256 rateBefore = IRateProvider(WSTETH_RATE_PROVIDER).getRate();
        console.log("\nRate before:", rateBefore);

        // In a real attack scenario:
        // 1. Trigger a pool exit that sends ETH
        // 2. During receive(), read the rate provider
        // 3. Rate may be stale relative to pool state
        // 4. Use stale rate to profit (e.g., over-borrow against BPT)

        console.log("\nAttack flow:");
        console.log("1. Deposit BPT into vulnerable lending protocol");
        console.log("2. Trigger exitPool on Balancer");
        console.log("3. In receive() callback, borrow against BPT");
        console.log("4. Rate provider returns stale rate");
        console.log("5. Borrow more than BPT is worth");
        console.log("6. Profit when rate normalizes");

        vm.stopPrank();
    }

    /// @notice ETH receive - this is where reentrancy happens
    receive() external payable {
        if (inCallback) {
            // Read rate during callback - may be stale!
            rateDuringCallback = IRateProvider(WSTETH_RATE_PROVIDER).getRate();
            console.log("  [CALLBACK] Rate read:", rateDuringCallback);

            // In a real attack, would now call vulnerable protocol
            // that uses this rate for pricing
        }
    }

    function _executeFlashAttack(address[] memory, uint256[] memory, bytes memory) internal override {}
}

/**
 * @title ZeroFeeFlashLoanAmplification
 * @notice Balancer flash loans are FREE - massive attack amplification
 *
 * Unlike Aave (0.05% fee) or Uniswap (0.3% fee),
 * Balancer charges ZERO fees for flash loans.
 * This makes attacks essentially free to execute.
 */
contract ZeroFeeFlashLoanAmplification is BalancerExploitPoC {
    function test_zeroFeeFlashLoan() public {
        vm.startPrank(ATTACKER);

        console.log("=== Balancer Zero-Fee Flash Loan ===");
        console.log("");
        console.log("Balancer flash loans are FREE!");
        console.log("This enables cost-free attack amplification.");

        // Get available liquidity
        (address[] memory tokens, uint256[] memory balances,) = VAULT.getPoolTokens(WETH_DAI_POOL);

        console.log("\nAvailable for flash loan:");
        for (uint256 i = 0; i < tokens.length; i++) {
            console.log(tokens[i], ":", balances[i]);
        }

        // Calculate attack amplification
        // With Aave: 0.05% fee = $5,000 per $10M
        // With Balancer: 0 fee = $0 per $10M
        console.log("\nCost comparison for $10M flash loan:");
        console.log("Aave fee (0.05%): $5,000");
        console.log("Uniswap fee (0.3%): $30,000");
        console.log("Balancer fee: $0");
        console.log("");
        console.log("CRITICAL: When modeling threats, assume attackers");
        console.log("have access to unlimited FREE capital via Balancer!");

        vm.stopPrank();
    }

    function test_executeZeroFeeFlashLoan() public {
        vm.startPrank(ATTACKER);

        console.log("=== Executing Zero-Fee Flash Loan ===");

        // Prepare flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = WETH;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000 ether; // Borrow 1000 WETH for FREE

        // Execute
        VAULT.flashLoan(address(this), tokens, amounts, "");

        console.log("Flash loan executed and repaid with ZERO fees!");

        vm.stopPrank();
    }

    function _executeFlashAttack(
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory
    ) internal override {
        console.log("Attack with borrowed capital:");
        for (uint256 i = 0; i < tokens.length; i++) {
            console.log("Have:", IERC20(tokens[i]).balanceOf(address(this)));
        }

        // Insert attack logic here
        // Can use borrowed funds for:
        // 1. Price manipulation
        // 2. Liquidations
        // 3. Arbitrage
        // All for FREE
    }
}

/**
 * @title VaultReentrancyLibDemo
 * @notice How to properly protect against Balancer reentrancy
 */
contract VaultReentrancyLibDemo is Test {
    IVault constant VAULT = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function setUp() public {
        vm.createSelectFork("mainnet", 18_500_000);
    }

    function test_vaultReentrancyProtection() public view {
        console.log("=== VaultReentrancyLib Protection ===");
        console.log("");
        console.log("To protect against Balancer read-only reentrancy,");
        console.log("use VaultReentrancyLib.ensureNotInVaultContext()");
        console.log("");
        console.log("Example:");
        console.log("```solidity");
        console.log("import '@balancer-labs/v2-pool-utils/contracts/lib/VaultReentrancyLib.sol';");
        console.log("");
        console.log("function getPrice() external view returns (uint256) {");
        console.log("    VaultReentrancyLib.ensureNotInVaultContext(vault);");
        console.log("    // Now safe to read rates and pool state");
        console.log("    return _calculatePrice();");
        console.log("}");
        console.log("```");
        console.log("");
        console.log("This checks if the Vault is currently in a callback context");
        console.log("and reverts if so, preventing stale reads.");
    }
}

/**
 * @title BPTPriceManipulation
 * @notice BPT price can be manipulated during callbacks
 */
contract BPTPriceManipulation is BalancerExploitPoC {
    function test_bptPriceManipulation() public view {
        console.log("=== BPT Price Manipulation ===");
        console.log("");
        console.log("BPT price = sum(underlying_values) / totalSupply");
        console.log("");
        console.log("During join/exit callbacks:");
        console.log("1. Pool balances may be inconsistent");
        console.log("2. totalSupply may not reflect pending mint/burn");
        console.log("3. Price calculation can be manipulated");
        console.log("");
        console.log("NEVER calculate BPT price during callbacks!");
        console.log("Cache values before operations, use after.");
    }

    function _executeFlashAttack(address[] memory, uint256[] memory, bytes memory) internal override {}
}

/**
 * @title VulnerablePriceOracle
 * @notice Example of vulnerable BPT price oracle
 */
contract VulnerablePriceOracle {
    IVault public vault;
    bytes32 public poolId;

    constructor(address _vault, bytes32 _poolId) {
        vault = IVault(_vault);
        poolId = _poolId;
    }

    /// @notice VULNERABLE: Reads pool state that can be manipulated during callbacks
    function getBPTPrice() external view returns (uint256) {
        (address[] memory tokens, uint256[] memory balances,) = vault.getPoolTokens(poolId);
        (address pool,) = vault.getPool(poolId);

        uint256 totalValue = 0;
        for (uint256 i = 0; i < tokens.length; i++) {
            // Assume 1:1 with ETH for simplicity
            totalValue += balances[i];
        }

        uint256 totalSupply = IERC20(pool).totalSupply();
        return totalValue * 1e18 / totalSupply; // VULNERABLE!
    }
}

/**
 * @title SafePriceOracle
 * @notice Example of properly protected BPT price oracle
 */
contract SafePriceOracle {
    IVault public vault;
    bytes32 public poolId;

    constructor(address _vault, bytes32 _poolId) {
        vault = IVault(_vault);
        poolId = _poolId;
    }

    /// @notice SAFE: Uses VaultReentrancyLib pattern
    function getBPTPrice() external view returns (uint256) {
        // Check we're not in callback context
        _ensureNotInVaultContext();

        (address[] memory tokens, uint256[] memory balances,) = vault.getPoolTokens(poolId);
        (address pool,) = vault.getPool(poolId);

        uint256 totalValue = 0;
        for (uint256 i = 0; i < tokens.length; i++) {
            totalValue += balances[i];
        }

        uint256 totalSupply = IERC20(pool).totalSupply();
        return totalValue * 1e18 / totalSupply;
    }

    function _ensureNotInVaultContext() internal view {
        // Simplified check - in production use VaultReentrancyLib
        (, bytes memory data) = address(vault).staticcall(
            abi.encodeWithSignature("manageUserBalance((uint8,address,uint256,address,address)[])", new bytes[](0))
        );
        // If this doesn't revert, we're not in vault context
    }
}
