"""
On-Chain Simulation - Test Against REAL State

The difference between theory and practice:
- Pattern matching: "This MIGHT be vulnerable"
- On-chain simulation: "This IS vulnerable, here's the TX"

This module:
1. Forks mainnet at any block
2. Simulates attack transactions
3. Measures actual profit/loss
4. Generates executable exploit TXs
"""

import subprocess
import json
import tempfile
import os
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class Chain(Enum):
    ETHEREUM = "ethereum"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"
    BASE = "base"


@dataclass
class SimulationResult:
    """Result of on-chain simulation."""
    success: bool
    profit_usd: float
    profit_tokens: dict[str, float]
    gas_used: int
    gas_cost_usd: float
    net_profit_usd: float
    execution_trace: list[dict]
    state_changes: dict[str, dict]
    error: Optional[str] = None


@dataclass
class ContractState:
    """Snapshot of contract state."""
    address: str
    balance_eth: float
    token_balances: dict[str, float]
    storage_slots: dict[str, str]
    code_hash: str


class OnChainSimulator:
    """
    Simulate transactions against real blockchain state.

    Uses Foundry's anvil for local forking.
    """

    # RPC endpoints for different chains
    RPC_ENDPOINTS = {
        Chain.ETHEREUM: "https://eth.llamarpc.com",
        Chain.ARBITRUM: "https://arb1.arbitrum.io/rpc",
        Chain.OPTIMISM: "https://mainnet.optimism.io",
        Chain.POLYGON: "https://polygon-rpc.com",
        Chain.BSC: "https://bsc-dataseed.binance.org",
        Chain.AVALANCHE: "https://api.avax.network/ext/bc/C/rpc",
        Chain.BASE: "https://mainnet.base.org",
    }

    def __init__(self, chain: Chain = Chain.ETHEREUM, rpc_url: Optional[str] = None):
        self.chain = chain
        self.rpc_url = rpc_url or self.RPC_ENDPOINTS.get(chain)
        self.anvil_process = None
        self.fork_block = None

    def fork_at_block(self, block_number: Optional[int] = None) -> str:
        """
        Fork the chain at a specific block.

        Returns the local RPC URL for the fork.
        """
        cmd = ["anvil", "--fork-url", self.rpc_url]

        if block_number:
            cmd.extend(["--fork-block-number", str(block_number)])
            self.fork_block = block_number

        # Start anvil in background
        self.anvil_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return "http://127.0.0.1:8545"

    def stop_fork(self):
        """Stop the forked node."""
        if self.anvil_process:
            self.anvil_process.terminate()
            self.anvil_process = None

    def get_contract_state(self, address: str) -> ContractState:
        """Get current state of a contract."""
        # Using cast to query state
        try:
            # Get ETH balance
            balance_result = subprocess.run(
                ["cast", "balance", address, "--rpc-url", self.rpc_url],
                capture_output=True,
                text=True,
            )
            balance_eth = float(balance_result.stdout.strip()) / 1e18 if balance_result.stdout else 0

            # Get code hash
            code_result = subprocess.run(
                ["cast", "code", address, "--rpc-url", self.rpc_url],
                capture_output=True,
                text=True,
            )
            code_hash = hash(code_result.stdout) if code_result.stdout else ""

            return ContractState(
                address=address,
                balance_eth=balance_eth,
                token_balances={},
                storage_slots={},
                code_hash=str(code_hash),
            )
        except Exception as e:
            return ContractState(
                address=address,
                balance_eth=0,
                token_balances={},
                storage_slots={},
                code_hash="",
            )

    def simulate_transaction(
        self,
        to: str,
        data: str,
        value: int = 0,
        from_address: Optional[str] = None,
    ) -> dict:
        """
        Simulate a transaction without broadcasting.

        Returns execution result and state changes.
        """
        from_addr = from_address or "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil default

        try:
            result = subprocess.run(
                [
                    "cast", "call",
                    to,
                    data,
                    "--from", from_addr,
                    "--value", str(value),
                    "--rpc-url", self.rpc_url,
                    "--trace",
                ],
                capture_output=True,
                text=True,
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
            }

    def execute_attack_sequence(
        self,
        steps: list[dict],
        attacker_address: str,
    ) -> SimulationResult:
        """
        Execute a multi-step attack sequence.

        Each step: {to, data, value, description}
        """
        # Record initial state
        initial_balance = self.get_contract_state(attacker_address).balance_eth

        execution_trace = []
        total_gas = 0

        for i, step in enumerate(steps):
            result = self.simulate_transaction(
                to=step["to"],
                data=step["data"],
                value=step.get("value", 0),
                from_address=attacker_address,
            )

            execution_trace.append({
                "step": i + 1,
                "description": step.get("description", ""),
                "success": result["success"],
                "output": result["output"][:200],  # Truncate
            })

            if not result["success"]:
                return SimulationResult(
                    success=False,
                    profit_usd=0,
                    profit_tokens={},
                    gas_used=total_gas,
                    gas_cost_usd=0,
                    net_profit_usd=0,
                    execution_trace=execution_trace,
                    state_changes={},
                    error=f"Step {i+1} failed: {result['error']}",
                )

        # Record final state
        final_balance = self.get_contract_state(attacker_address).balance_eth
        profit_eth = final_balance - initial_balance

        # Estimate USD value (simplified)
        eth_price = 2500  # Would fetch from oracle in production
        profit_usd = profit_eth * eth_price
        gas_cost_usd = (total_gas * 30e-9) * eth_price  # 30 gwei

        return SimulationResult(
            success=True,
            profit_usd=profit_usd,
            profit_tokens={"ETH": profit_eth},
            gas_used=total_gas,
            gas_cost_usd=gas_cost_usd,
            net_profit_usd=profit_usd - gas_cost_usd,
            execution_trace=execution_trace,
            state_changes={},
        )


def fork_and_test(
    poc_code: str,
    chain: Chain = Chain.ETHEREUM,
    block_number: Optional[int] = None,
) -> SimulationResult:
    """
    Fork chain and test PoC code.

    This is the ultimate validation - does the exploit actually work?
    """
    simulator = OnChainSimulator(chain)

    try:
        # Create temp file with PoC
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.sol',
            delete=False,
            dir='.'
        ) as f:
            f.write(poc_code)
            poc_path = f.name

        # Fork the chain
        local_rpc = simulator.fork_at_block(block_number)

        # Compile and deploy PoC
        compile_result = subprocess.run(
            ["forge", "build", poc_path],
            capture_output=True,
            text=True,
        )

        if compile_result.returncode != 0:
            return SimulationResult(
                success=False,
                profit_usd=0,
                profit_tokens={},
                gas_used=0,
                gas_cost_usd=0,
                net_profit_usd=0,
                execution_trace=[],
                state_changes={},
                error=f"Compilation failed: {compile_result.stderr}",
            )

        # Run the test
        test_result = subprocess.run(
            [
                "forge", "test",
                "--fork-url", local_rpc,
                "--match-path", poc_path,
                "-vvvv",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        return SimulationResult(
            success=test_result.returncode == 0,
            profit_usd=0,  # Parse from output
            profit_tokens={},
            gas_used=0,
            gas_cost_usd=0,
            net_profit_usd=0,
            execution_trace=[{"output": test_result.stdout}],
            state_changes={},
            error=test_result.stderr if test_result.returncode != 0 else None,
        )

    except subprocess.TimeoutExpired:
        return SimulationResult(
            success=False,
            profit_usd=0,
            profit_tokens={},
            gas_used=0,
            gas_cost_usd=0,
            net_profit_usd=0,
            execution_trace=[],
            state_changes={},
            error="Test timed out",
        )
    finally:
        simulator.stop_fork()
        if 'poc_path' in locals():
            os.unlink(poc_path)


def simulate_attack(
    target_address: str,
    attack_calldata: str,
    chain: Chain = Chain.ETHEREUM,
    value: int = 0,
) -> dict:
    """
    Simulate a single attack transaction.

    Quick check if an attack would succeed.
    """
    simulator = OnChainSimulator(chain)
    return simulator.simulate_transaction(
        to=target_address,
        data=attack_calldata,
        value=value,
    )


def get_contract_state(address: str, chain: Chain = Chain.ETHEREUM) -> ContractState:
    """Get current on-chain state of a contract."""
    simulator = OnChainSimulator(chain)
    return simulator.get_contract_state(address)


class FlashLoanSimulator:
    """
    Simulate flash loan attacks.

    Supports:
    - Aave V3
    - Uniswap V3
    - Balancer
    - dYdX
    - Maker
    """

    FLASH_LOAN_PROVIDERS = {
        "aave_v3": {
            "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
            "fee": 0.0009,  # 0.09%
            "function": "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
        },
        "uniswap_v3": {
            "factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "fee": 0.003,  # 0.3% (actually 0.05/0.3/1% depending on pool)
            "function": "flash(address,uint256,uint256,bytes)",
        },
        "balancer": {
            "vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
            "fee": 0,  # Free!
            "function": "flashLoan(address,address[],uint256[],bytes)",
        },
    }

    def build_flash_loan_poc(
        self,
        provider: str,
        borrow_token: str,
        borrow_amount: int,
        attack_logic: str,
    ) -> str:
        """Build complete flash loan PoC."""
        if provider == "aave_v3":
            return self._build_aave_poc(borrow_token, borrow_amount, attack_logic)
        elif provider == "balancer":
            return self._build_balancer_poc(borrow_token, borrow_amount, attack_logic)
        elif provider == "uniswap_v3":
            return self._build_uniswap_poc(borrow_token, borrow_amount, attack_logic)
        return ""

    def _build_aave_poc(self, token: str, amount: int, logic: str) -> str:
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IPool {{
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}}

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}}

contract FlashLoanExploit is Test {{
    IPool constant AAVE = IPool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address constant TOKEN = {token};
    uint256 constant AMOUNT = {amount};

    function test_exploit() external {{
        address[] memory assets = new address[](1);
        assets[0] = TOKEN;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = AMOUNT;

        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;  // No debt

        AAVE.flashLoan(
            address(this),
            assets,
            amounts,
            modes,
            address(this),
            "",
            0
        );
    }}

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {{
        // We now have {amount} of {token}

        // ============ ATTACK LOGIC ============
        {logic}
        // ======================================

        // Approve repayment
        uint256 amountOwed = amounts[0] + premiums[0];
        IERC20(assets[0]).approve(address(AAVE), amountOwed);

        return true;
    }}
}}
'''

    def _build_balancer_poc(self, token: str, amount: int, logic: str) -> str:
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVault {{
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}}

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}}

contract BalancerExploit is Test {{
    IVault constant VAULT = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address constant TOKEN = {token};
    uint256 constant AMOUNT = {amount};

    function test_exploit() external {{
        address[] memory tokens = new address[](1);
        tokens[0] = TOKEN;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = AMOUNT;

        VAULT.flashLoan(address(this), tokens, amounts, "");
    }}

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {{
        // We now have {amount} of {token} (FREE, no fee!)

        // ============ ATTACK LOGIC ============
        {logic}
        // ======================================

        // Repay (no fee for Balancer!)
        IERC20(tokens[0]).transfer(address(VAULT), amounts[0]);
    }}
}}
'''

    def _build_uniswap_poc(self, token: str, amount: int, logic: str) -> str:
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IUniswapV3Pool {{
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}}

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}}

contract UniswapExploit is Test {{
    address constant POOL = 0x...; // Specific pool address
    address constant TOKEN = {token};
    uint256 constant AMOUNT = {amount};

    function test_exploit() external {{
        IUniswapV3Pool(POOL).flash(
            address(this),
            AMOUNT,  // amount0 or amount1 depending on token
            0,
            ""
        );
    }}

    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {{
        // We now have {amount} of {token}

        // ============ ATTACK LOGIC ============
        {logic}
        // ======================================

        // Repay with fee
        IERC20(TOKEN).transfer(msg.sender, AMOUNT + fee0);
    }}
}}
'''
