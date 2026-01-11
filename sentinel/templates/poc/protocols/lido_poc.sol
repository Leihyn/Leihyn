// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Lido stETH/wstETH Exploit PoC Template
 * @notice Template for exploits involving Lido integrations
 *
 * Common attack vectors:
 * 1. Rebasing balance caching (CRITICAL)
 * 2. Share vs balance confusion
 * 3. Transfer amount mismatch
 * 4. Negative rebase (slashing) handling
 * 5. wstETH/stETH type confusion
 */

// Lido Interfaces
interface IStETH {
    function submit(address _referral) external payable returns (uint256);
    function balanceOf(address _account) external view returns (uint256);
    function transfer(address _recipient, uint256 _amount) external returns (bool);
    function transferFrom(address _sender, address _recipient, uint256 _amount) external returns (bool);
    function approve(address _spender, uint256 _amount) external returns (bool);

    // Shares-based functions (IMPORTANT!)
    function sharesOf(address _account) external view returns (uint256);
    function getSharesByPooledEth(uint256 _ethAmount) external view returns (uint256);
    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);
    function transferShares(address _recipient, uint256 _sharesAmount) external returns (uint256);
    function transferSharesFrom(address _sender, address _recipient, uint256 _sharesAmount) external returns (uint256);

    // Protocol info
    function getTotalPooledEther() external view returns (uint256);
    function getTotalShares() external view returns (uint256);
}

interface IWstETH {
    function wrap(uint256 _stETHAmount) external returns (uint256);
    function unwrap(uint256 _wstETHAmount) external returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);

    // Conversion functions
    function stEthPerToken() external view returns (uint256);
    function tokensPerStEth() external view returns (uint256);
    function getStETHByWstETH(uint256 _wstETHAmount) external view returns (uint256);
    function getWstETHByStETH(uint256 _stETHAmount) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/**
 * @title LidoExploitPoC
 * @notice Base template for Lido exploits
 */
abstract contract LidoExploitPoC is Test {
    // Mainnet addresses
    IStETH constant STETH = IStETH(0xae7ab96520DE3A18E5e111B5EaAb4dc8cd83CE9);
    IWstETH constant WSTETH = IWstETH(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0);

    address constant ATTACKER = address(0xBAD);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_500_000);
        vm.label(address(STETH), "stETH");
        vm.label(address(WSTETH), "wstETH");
    }

    /// @notice Log stETH state
    function _logStETHState(address user) internal view {
        console.log("=== stETH State ===");
        console.log("Balance (rebasing):", STETH.balanceOf(user));
        console.log("Shares (constant):", STETH.sharesOf(user));
        console.log("Total pooled ETH:", STETH.getTotalPooledEther());
        console.log("Total shares:", STETH.getTotalShares());
        console.log("1 share = ETH:", STETH.getPooledEthByShares(1e18));
    }

    /// @notice Log wstETH state
    function _logWstETHState(address user) internal view {
        console.log("=== wstETH State ===");
        console.log("Balance:", WSTETH.balanceOf(user));
        console.log("stETH per token:", WSTETH.stEthPerToken());
        console.log("Equivalent stETH:", WSTETH.getStETHByWstETH(WSTETH.balanceOf(user)));
    }

    /// @notice Simulate a rebase (positive rewards)
    function _simulatePositiveRebase(uint256 rewardPercent) internal {
        // Get current state
        uint256 totalPooledEther = STETH.getTotalPooledEther();
        uint256 reward = totalPooledEther * rewardPercent / 10000;

        // Mock the oracle report that increases pooled ether
        // In reality, this happens through Lido oracle
        vm.deal(address(STETH), address(STETH).balance + reward);

        console.log("Simulated rebase: +", rewardPercent, "bps");
    }
}

/**
 * @title RebasingBalanceCache
 * @notice CRITICAL: Caching stETH balance leads to incorrect accounting
 *
 * stETH balances CHANGE between transactions (and sometimes within!)
 * due to the rebasing mechanism. Any code that caches balanceOf()
 * and uses it later is vulnerable.
 */
contract RebasingBalanceCache is LidoExploitPoC {
    function test_rebasingBalanceCache() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 100 ether);

        console.log("=== Rebasing Balance Cache Vulnerability ===");

        // Step 1: Submit ETH to get stETH
        console.log("\n--- Step 1: Get stETH ---");
        STETH.submit{value: 100 ether}(address(0));
        _logStETHState(ATTACKER);

        uint256 initialBalance = STETH.balanceOf(ATTACKER);
        uint256 initialShares = STETH.sharesOf(ATTACKER);

        console.log("\nCached balance:", initialBalance);
        console.log("Shares (constant):", initialShares);

        // Step 2: Simulate a positive rebase (rewards)
        console.log("\n--- Step 2: Simulate Rebase (+100 bps) ---");
        _simulatePositiveRebase(100); // 1% reward

        // Step 3: Check balance change
        console.log("\n--- Step 3: After Rebase ---");
        uint256 newBalance = STETH.balanceOf(ATTACKER);
        uint256 newShares = STETH.sharesOf(ATTACKER);

        console.log("New balance:", newBalance);
        console.log("Balance change:", int256(newBalance) - int256(initialBalance));
        console.log("Shares (unchanged):", newShares);

        // Demonstrate the vulnerability
        console.log("\n--- Vulnerability Demo ---");
        console.log("If a protocol cached the initial balance:", initialBalance);
        console.log("But user actually has:", newBalance);
        console.log("Difference:", newBalance - initialBalance);
        console.log("");
        console.log("This can lead to:");
        console.log("1. Under-accounting user deposits");
        console.log("2. Over-allowing withdrawals (from cache)");
        console.log("3. Incorrect collateral calculations");

        vm.stopPrank();
    }
}

/**
 * @title SharesVsBalance
 * @notice The correct way to handle stETH: use shares, not balances
 */
contract SharesVsBalance is LidoExploitPoC {
    function test_sharesVsBalance() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 100 ether);

        console.log("=== Shares vs Balance ===");

        // Get stETH
        STETH.submit{value: 100 ether}(address(0));

        uint256 balance = STETH.balanceOf(ATTACKER);
        uint256 shares = STETH.sharesOf(ATTACKER);

        console.log("Initial state:");
        console.log("Balance:", balance);
        console.log("Shares:", shares);

        // Simulate rebase
        _simulatePositiveRebase(200); // 2% reward

        uint256 newBalance = STETH.balanceOf(ATTACKER);
        uint256 newShares = STETH.sharesOf(ATTACKER);

        console.log("\nAfter 2% rebase:");
        console.log("Balance:", newBalance, "(changed!)");
        console.log("Shares:", newShares, "(same!)");

        console.log("\n=== Key Insight ===");
        console.log("BALANCE changes with rebases (unpredictable)");
        console.log("SHARES remain constant (predictable)");
        console.log("");
        console.log("Always use sharesOf() for accounting!");
        console.log("Convert to balance only when needed for display.");

        vm.stopPrank();
    }
}

/**
 * @title TransferAmountMismatch
 * @notice stETH.transfer(amount) may not transfer exactly `amount`
 *
 * Due to rounding in the shares calculation, the actual amount
 * transferred can differ by 1-2 wei from the specified amount.
 */
contract TransferAmountMismatch is LidoExploitPoC {
    function test_transferMismatch() public {
        vm.deal(ATTACKER, 100 ether);
        vm.deal(address(1), 100 ether);

        vm.prank(ATTACKER);
        STETH.submit{value: 100 ether}(address(0));

        vm.prank(address(1));
        STETH.submit{value: 100 ether}(address(0));

        console.log("=== Transfer Amount Mismatch ===");

        address recipient = address(0x123);

        // Record state before
        uint256 senderBefore = STETH.balanceOf(ATTACKER);
        uint256 recipientBefore = STETH.balanceOf(recipient);

        console.log("Before transfer:");
        console.log("Sender balance:", senderBefore);
        console.log("Recipient balance:", recipientBefore);

        // Transfer specific amount
        uint256 transferAmount = 50 ether;
        console.log("\nAttempting to transfer:", transferAmount);

        vm.prank(ATTACKER);
        STETH.transfer(recipient, transferAmount);

        // Check actual amounts
        uint256 senderAfter = STETH.balanceOf(ATTACKER);
        uint256 recipientAfter = STETH.balanceOf(recipient);

        uint256 actualSent = senderBefore - senderAfter;
        uint256 actualReceived = recipientAfter - recipientBefore;

        console.log("\nAfter transfer:");
        console.log("Sender balance:", senderAfter);
        console.log("Recipient balance:", recipientAfter);
        console.log("Actually sent:", actualSent);
        console.log("Actually received:", actualReceived);
        console.log("Requested vs sent diff:", int256(transferAmount) - int256(actualSent));

        console.log("\n=== Use transferShares() for precision! ===");
        console.log("transferShares() transfers exact share amount");
        console.log("No rounding issues with share-based transfers");

        vm.stopPrank();
    }

    function test_transferSharesPrecision() public {
        vm.deal(ATTACKER, 100 ether);

        vm.prank(ATTACKER);
        STETH.submit{value: 100 ether}(address(0));

        console.log("=== transferShares() Precision ===");

        address recipient = address(0x123);
        uint256 sharesToTransfer = STETH.sharesOf(ATTACKER) / 2;

        uint256 senderSharesBefore = STETH.sharesOf(ATTACKER);
        uint256 recipientSharesBefore = STETH.sharesOf(recipient);

        console.log("Transferring shares:", sharesToTransfer);

        vm.prank(ATTACKER);
        STETH.transferShares(recipient, sharesToTransfer);

        uint256 senderSharesAfter = STETH.sharesOf(ATTACKER);
        uint256 recipientSharesAfter = STETH.sharesOf(recipient);

        console.log("Sender shares change:", senderSharesBefore - senderSharesAfter);
        console.log("Recipient shares change:", recipientSharesAfter - recipientSharesBefore);
        console.log("Exact match!");
    }
}

/**
 * @title WstETHvsStETH
 * @notice wstETH is NON-rebasing, stETH IS rebasing
 *
 * Common confusion leads to bugs when protocols treat
 * wstETH as if it rebases, or stETH as if it doesn't.
 */
contract WstETHvsStETH is LidoExploitPoC {
    function test_wstethVsSteth() public {
        vm.startPrank(ATTACKER);
        vm.deal(ATTACKER, 100 ether);

        console.log("=== wstETH vs stETH ===");

        // Get stETH
        STETH.submit{value: 100 ether}(address(0));
        uint256 stethBalance = STETH.balanceOf(ATTACKER);

        // Wrap half to wstETH
        STETH.approve(address(WSTETH), stethBalance / 2);
        uint256 wstethReceived = WSTETH.wrap(stethBalance / 2);

        console.log("Initial state:");
        console.log("stETH balance:", STETH.balanceOf(ATTACKER));
        console.log("wstETH balance:", WSTETH.balanceOf(ATTACKER));

        // Simulate rebase
        _simulatePositiveRebase(500); // 5% reward

        console.log("\nAfter 5% rebase:");
        console.log("stETH balance:", STETH.balanceOf(ATTACKER), "(increased!)");
        console.log("wstETH balance:", WSTETH.balanceOf(ATTACKER), "(same!)");
        console.log("wstETH value in stETH:", WSTETH.getStETHByWstETH(WSTETH.balanceOf(ATTACKER)), "(increased!)");

        console.log("\n=== Key Difference ===");
        console.log("stETH: Balance changes, value represented directly");
        console.log("wstETH: Balance constant, value increases via exchange rate");
        console.log("");
        console.log("Use wstETH when you need constant balance accounting!");
        console.log("Use stETH when you want automatic balance updates.");

        vm.stopPrank();
    }
}

/**
 * @title NegativeRebase
 * @notice stETH can have NEGATIVE rebases during slashing events
 */
contract NegativeRebase is LidoExploitPoC {
    function test_negativeRebase() public view {
        console.log("=== Negative Rebase (Slashing) ===");
        console.log("");
        console.log("stETH can DECREASE in value if validators are slashed!");
        console.log("This is rare but possible.");
        console.log("");
        console.log("Protocols that assume stETH only increases are vulnerable:");
        console.log("1. Lending protocols may under-collateralize");
        console.log("2. Yield strategies may have negative returns");
        console.log("3. Fixed-rate products may lose principal");
        console.log("");
        console.log("Always handle the case where stETH value decreases.");
        console.log("Use getPooledEthByShares() to get current value.");
    }
}

/**
 * @title VulnerableStETHVault
 * @notice Example of vulnerable stETH vault using balanceOf
 */
contract VulnerableStETHVault {
    IStETH public steth;
    mapping(address => uint256) public deposits; // VULNERABLE: stores balance

    constructor(address _steth) {
        steth = IStETH(_steth);
    }

    /// @notice VULNERABLE: Caches stETH balance
    function deposit(uint256 amount) external {
        steth.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount; // BUG: amount may differ from actual!
    }

    /// @notice VULNERABLE: Uses cached balance
    function withdraw() external {
        uint256 amount = deposits[msg.sender]; // May be stale!
        deposits[msg.sender] = 0;
        steth.transfer(msg.sender, amount);
    }
}

/**
 * @title SafeStETHVault
 * @notice Example of correct stETH vault using shares
 */
contract SafeStETHVault {
    IStETH public steth;
    mapping(address => uint256) public shares; // SAFE: stores shares

    constructor(address _steth) {
        steth = IStETH(_steth);
    }

    /// @notice SAFE: Tracks shares, not balance
    function deposit(uint256 stethAmount) external {
        // Transfer stETH
        uint256 sharesBefore = steth.sharesOf(address(this));
        steth.transferFrom(msg.sender, address(this), stethAmount);
        uint256 sharesAfter = steth.sharesOf(address(this));

        // Record actual shares received
        uint256 sharesReceived = sharesAfter - sharesBefore;
        shares[msg.sender] += sharesReceived;
    }

    /// @notice SAFE: Converts shares to current balance value
    function withdraw() external {
        uint256 userShares = shares[msg.sender];
        shares[msg.sender] = 0;

        // Transfer shares (not balance!)
        steth.transferShares(msg.sender, userShares);
    }

    /// @notice Get user's current stETH value
    function balanceOf(address user) external view returns (uint256) {
        return steth.getPooledEthByShares(shares[user]);
    }
}
