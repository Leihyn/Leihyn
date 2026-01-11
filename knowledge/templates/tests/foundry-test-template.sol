// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {MyContract} from "../src/MyContract.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MyContractTest
 * @notice Foundry test template with common patterns
 */
contract MyContractTest is Test {
    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    MyContract public myContract;

    address public owner = makeAddr("owner");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public attacker = makeAddr("attacker");

    uint256 public constant INITIAL_BALANCE = 100 ether;

    function setUp() public {
        // Deploy contracts
        vm.startPrank(owner);
        myContract = new MyContract();
        vm.stopPrank();

        // Fund accounts
        vm.deal(user1, INITIAL_BALANCE);
        vm.deal(user2, INITIAL_BALANCE);
    }

    /*//////////////////////////////////////////////////////////////
                              UNIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertEq(myContract.owner(), owner);
    }

    function test_SomeFunction() public {
        vm.prank(user1);
        myContract.someFunction();

        assertEq(myContract.someValue(), 1);
    }

    function test_RevertWhen_Unauthorized() public {
        vm.prank(attacker);
        vm.expectRevert(); // or vm.expectRevert(MyContract.Unauthorized.selector);
        myContract.adminFunction();
    }

    function test_EmitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit MyContract.SomeEvent(user1, 100);

        vm.prank(user1);
        myContract.functionThatEmits(100);
    }

    /*//////////////////////////////////////////////////////////////
                             FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Deposit(uint256 amount) public {
        // Bound inputs to reasonable ranges
        amount = bound(amount, 1, 1000 ether);

        vm.deal(user1, amount);
        vm.prank(user1);
        myContract.deposit{value: amount}();

        assertEq(myContract.balances(user1), amount);
    }

    function testFuzz_Transfer(address to, uint256 amount) public {
        // Assume valid inputs
        vm.assume(to != address(0));
        vm.assume(to != address(myContract));
        amount = bound(amount, 1, INITIAL_BALANCE);

        vm.prank(user1);
        myContract.transfer(to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT TESTS
    //////////////////////////////////////////////////////////////*/

    function invariant_TotalSupplyMatchesBalances() public view {
        // Total supply should always equal sum of all balances
        // (Implement actual check based on your contract)
    }

    /*//////////////////////////////////////////////////////////////
                             FORK TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Fork_InteractWithMainnet() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", 18_000_000);

        // Interact with mainnet contracts
        IERC20 usdc = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

        // Impersonate whale
        address whale = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;
        vm.prank(whale);
        usdc.transfer(user1, 1_000_000e6);

        assertGt(usdc.balanceOf(user1), 0);
    }

    /*//////////////////////////////////////////////////////////////
                           HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _depositFor(address user, uint256 amount) internal {
        vm.deal(user, amount);
        vm.prank(user);
        myContract.deposit{value: amount}();
    }

    function _advanceTime(uint256 seconds_) internal {
        vm.warp(block.timestamp + seconds_);
    }

    function _advanceBlocks(uint256 blocks) internal {
        vm.roll(block.number + blocks);
    }
}

/*//////////////////////////////////////////////////////////////
                        COMMON CHEATCODES
//////////////////////////////////////////////////////////////*/

/*
 * PRANKING:
 * vm.prank(address) - Next call from address
 * vm.startPrank(address) - All calls from address until stopPrank
 * vm.stopPrank() - Stop pranking
 *
 * EXPECTATIONS:
 * vm.expectRevert() - Next call should revert
 * vm.expectRevert(bytes4) - Revert with specific selector
 * vm.expectEmit(bool, bool, bool, bool) - Check event
 *
 * STATE:
 * vm.deal(address, uint256) - Set ETH balance
 * vm.warp(uint256) - Set block.timestamp
 * vm.roll(uint256) - Set block.number
 * vm.store(address, bytes32, bytes32) - Set storage slot
 * vm.load(address, bytes32) - Read storage slot
 *
 * FORKING:
 * vm.createSelectFork(string) - Fork network
 * vm.createSelectFork(string, uint256) - Fork at block
 *
 * LABELS:
 * vm.label(address, string) - Label address in traces
 *
 * SNAPSHOTS:
 * uint256 id = vm.snapshot() - Save state
 * vm.revertTo(id) - Restore state
 *
 * RECORDING:
 * vm.record() - Start recording storage access
 * vm.accesses(address) - Get reads/writes
 */
