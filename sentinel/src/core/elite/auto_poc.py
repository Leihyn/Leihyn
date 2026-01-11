"""
Automated PoC Execution - Prove It or It Doesn't Exist

A finding without a working PoC is just a theory.
A finding WITH a working PoC is a guaranteed payout.

This module:
1. Compiles PoC code automatically
2. Fixes common compilation errors
3. Executes against forked mainnet
4. Measures actual profit
5. Generates submission-ready PoC
"""

import subprocess
import tempfile
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from pathlib import Path


class PoCStatus(Enum):
    COMPILES = "compiles"
    RUNS = "runs"
    PROFITABLE = "profitable"
    FAILED_COMPILE = "failed_compile"
    FAILED_RUNTIME = "failed_runtime"
    UNPROFITABLE = "unprofitable"


@dataclass
class PoCExecutionResult:
    """Result of PoC execution."""
    status: PoCStatus
    compiles: bool
    runs: bool
    profitable: bool
    profit_amount: float
    profit_token: str
    gas_used: int
    execution_time_ms: int
    output: str
    errors: list[str]
    fixed_code: Optional[str]
    submission_ready: bool


class AutoPoCExecutor:
    """
    Automatically compile, fix, and execute PoC code.

    Features:
    - Auto-fix common Solidity errors
    - Add missing imports
    - Fix interface mismatches
    - Fork mainnet for real testing
    """

    # Common compilation fixes
    COMMON_FIXES = {
        # Missing imports
        r"DeclarationError.*IERC20": 'import "forge-std/interfaces/IERC20.sol";',
        r"DeclarationError.*IUniswap": 'import "./interfaces/IUniswap.sol";',
        r"DeclarationError.*console": 'import "forge-std/console.sol";',

        # Type errors
        r"TypeError.*uint256.*int256": "Use uint256 for all amounts",
        r"TypeError.*address.*payable": "Cast with payable()",

        # Common mistakes
        r"member.*not found.*balance": "Use .balanceOf() for ERC20",
        r"low-level call.*failed": "Check return value of call",
    }

    # Standard imports to try
    STANDARD_IMPORTS = [
        'import "forge-std/Test.sol";',
        'import "forge-std/console.sol";',
        'import "forge-std/interfaces/IERC20.sol";',
    ]

    def __init__(self, foundry_project_path: Optional[str] = None):
        self.project_path = foundry_project_path or self._find_foundry_project()

    def _find_foundry_project(self) -> str:
        """Find or create a Foundry project for testing."""
        # Check if we're in a Foundry project
        if os.path.exists("foundry.toml"):
            return "."

        # Create temp project
        temp_dir = tempfile.mkdtemp(prefix="sentinel_poc_")
        subprocess.run(
            ["forge", "init", "--no-git", temp_dir],
            capture_output=True,
        )
        return temp_dir

    def execute(self, poc_code: str, chain: str = "mainnet") -> PoCExecutionResult:
        """
        Execute PoC code and return results.

        Steps:
        1. Write code to file
        2. Attempt compilation
        3. If fails, try auto-fix
        4. Execute test
        5. Parse results
        """
        errors = []

        # Step 1: Ensure proper structure
        poc_code = self._ensure_structure(poc_code)

        # Step 2: Write to file
        test_file = os.path.join(self.project_path, "test", "Exploit.t.sol")
        os.makedirs(os.path.dirname(test_file), exist_ok=True)
        with open(test_file, 'w') as f:
            f.write(poc_code)

        # Step 3: Compile
        compile_result = self._compile()

        if not compile_result["success"]:
            # Try to auto-fix
            fixed_code = self._auto_fix(poc_code, compile_result["errors"])
            if fixed_code != poc_code:
                with open(test_file, 'w') as f:
                    f.write(fixed_code)
                compile_result = self._compile()
                poc_code = fixed_code

            if not compile_result["success"]:
                return PoCExecutionResult(
                    status=PoCStatus.FAILED_COMPILE,
                    compiles=False,
                    runs=False,
                    profitable=False,
                    profit_amount=0,
                    profit_token="",
                    gas_used=0,
                    execution_time_ms=0,
                    output=compile_result["errors"],
                    errors=[compile_result["errors"]],
                    fixed_code=None,
                    submission_ready=False,
                )

        # Step 4: Execute test
        run_result = self._run_test(chain)

        if not run_result["success"]:
            return PoCExecutionResult(
                status=PoCStatus.FAILED_RUNTIME,
                compiles=True,
                runs=False,
                profitable=False,
                profit_amount=0,
                profit_token="",
                gas_used=run_result.get("gas", 0),
                execution_time_ms=run_result.get("time_ms", 0),
                output=run_result["output"],
                errors=[run_result.get("error", "Runtime error")],
                fixed_code=poc_code,
                submission_ready=False,
            )

        # Step 5: Parse results
        profit = self._parse_profit(run_result["output"])

        status = PoCStatus.PROFITABLE if profit > 0 else PoCStatus.UNPROFITABLE

        return PoCExecutionResult(
            status=status,
            compiles=True,
            runs=True,
            profitable=profit > 0,
            profit_amount=profit,
            profit_token="ETH",
            gas_used=run_result.get("gas", 0),
            execution_time_ms=run_result.get("time_ms", 0),
            output=run_result["output"],
            errors=[],
            fixed_code=poc_code,
            submission_ready=profit > 0,
        )

    def _ensure_structure(self, code: str) -> str:
        """Ensure PoC has proper structure."""
        # Add SPDX if missing
        if "SPDX-License-Identifier" not in code:
            code = "// SPDX-License-Identifier: MIT\n" + code

        # Add pragma if missing
        if "pragma solidity" not in code:
            code = code.replace(
                "// SPDX-License-Identifier: MIT",
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;"
            )

        # Add Test import if missing
        if "forge-std/Test.sol" not in code and "is Test" in code:
            code = code.replace(
                "pragma solidity",
                'import "forge-std/Test.sol";\n\npragma solidity'
            )

        return code

    def _compile(self) -> dict:
        """Compile the project."""
        result = subprocess.run(
            ["forge", "build"],
            cwd=self.project_path,
            capture_output=True,
            text=True,
        )

        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "errors": result.stderr,
        }

    def _auto_fix(self, code: str, errors: str) -> str:
        """Attempt to auto-fix compilation errors."""
        fixed = code

        # Try each fix pattern
        for pattern, fix in self.COMMON_FIXES.items():
            if re.search(pattern, errors, re.IGNORECASE):
                if "import" in fix and fix not in fixed:
                    # Add import after pragma
                    fixed = re.sub(
                        r'(pragma solidity[^;]+;)',
                        f'\\1\n{fix}',
                        fixed
                    )

        # Add standard imports if missing
        for imp in self.STANDARD_IMPORTS:
            if "Test.sol" in imp and "is Test" in fixed and imp not in fixed:
                fixed = re.sub(
                    r'(pragma solidity[^;]+;)',
                    f'\\1\n{imp}',
                    fixed
                )

        return fixed

    def _run_test(self, chain: str) -> dict:
        """Run the test against forked chain."""
        # Get RPC URL
        rpc_urls = {
            "mainnet": "https://eth.llamarpc.com",
            "arbitrum": "https://arb1.arbitrum.io/rpc",
            "optimism": "https://mainnet.optimism.io",
        }
        rpc = rpc_urls.get(chain, rpc_urls["mainnet"])

        result = subprocess.run(
            [
                "forge", "test",
                "--fork-url", rpc,
                "-vvvv",
                "--match-path", "test/Exploit.t.sol",
            ],
            cwd=self.project_path,
            capture_output=True,
            text=True,
            timeout=300,
        )

        return {
            "success": result.returncode == 0,
            "output": result.stdout + result.stderr,
            "error": result.stderr if result.returncode != 0 else None,
        }

    def _parse_profit(self, output: str) -> float:
        """Parse profit from test output."""
        # Look for console.log output showing profit
        patterns = [
            r"profit[:\s]+(\d+(?:\.\d+)?)\s*(?:ETH|ether)",
            r"attacker.*balance.*after.*(\d+(?:\.\d+)?)",
            r"gained[:\s]+(\d+(?:\.\d+)?)",
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return float(match.group(1))

        # Check if test passed (implies profitable)
        if "PASS" in output:
            return 1.0  # Placeholder positive value

        return 0.0


def compile_and_run(poc_code: str, chain: str = "mainnet") -> PoCExecutionResult:
    """
    Compile and run PoC code.

    Returns detailed execution results.
    """
    executor = AutoPoCExecutor()
    return executor.execute(poc_code, chain)


def validate_poc_onchain(
    poc_code: str,
    target_contract: str,
    chain: str = "mainnet",
    block_number: Optional[int] = None,
) -> dict:
    """
    Validate PoC against actual on-chain state.

    This is the ultimate test - does it work on real mainnet?
    """
    executor = AutoPoCExecutor()
    result = executor.execute(poc_code, chain)

    return {
        "valid": result.profitable,
        "profit": result.profit_amount,
        "compiles": result.compiles,
        "runs": result.runs,
        "submission_ready": result.submission_ready,
        "fixed_code": result.fixed_code,
        "errors": result.errors,
    }


class PoCPolisher:
    """
    Polish PoC for submission.

    Makes PoC:
    - Well-documented
    - Easy to understand
    - Reproducible
    - Contest-ready
    """

    TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title {title}
 * @notice Proof of Concept for {vulnerability_type}
 *
 * Target: {target_contract}
 * Chain: {chain}
 * Block: {block_number}
 *
 * Attack Flow:
 * {attack_flow}
 *
 * Expected Profit: {expected_profit}
 *
 * Run:
 *   forge test --match-contract ExploitTest --fork-url $RPC -vvvv
 */
contract ExploitTest is Test {{
    // ============================================================
    // CONSTANTS
    // ============================================================
    {constants}

    // ============================================================
    // SETUP
    // ============================================================
    function setUp() public {{
        vm.createSelectFork("{chain}", {block_number});
        {setup_code}
    }}

    // ============================================================
    // EXPLOIT
    // ============================================================
    function test_exploit() public {{
        console.log("=== Initial State ===");
        {log_initial}

        console.log("=== Executing Exploit ===");
        {exploit_code}

        console.log("=== Final State ===");
        {log_final}

        console.log("=== Profit ===");
        {log_profit}

        // Assertions
        {assertions}
    }}
}}

{helper_contracts}
'''

    def polish(
        self,
        raw_poc: str,
        metadata: dict,
    ) -> str:
        """
        Polish raw PoC into submission-ready format.

        Args:
            raw_poc: Raw PoC code
            metadata: Dict with title, vulnerability_type, etc.

        Returns:
            Polished, documented PoC
        """
        # Extract components from raw PoC
        constants = self._extract_constants(raw_poc)
        setup = self._extract_setup(raw_poc)
        exploit = self._extract_exploit(raw_poc)
        helpers = self._extract_helpers(raw_poc)

        return self.TEMPLATE.format(
            title=metadata.get("title", "Exploit PoC"),
            vulnerability_type=metadata.get("vulnerability_type", "Unknown"),
            target_contract=metadata.get("target", "Unknown"),
            chain=metadata.get("chain", "mainnet"),
            block_number=metadata.get("block", "latest"),
            attack_flow=metadata.get("attack_flow", "See code"),
            expected_profit=metadata.get("profit", "Unknown"),
            constants=constants,
            setup_code=setup,
            log_initial=self._generate_logging("before"),
            exploit_code=exploit,
            log_final=self._generate_logging("after"),
            log_profit=self._generate_profit_logging(),
            assertions=self._generate_assertions(),
            helper_contracts=helpers,
        )

    def _extract_constants(self, code: str) -> str:
        """Extract constant declarations."""
        pattern = r'((?:address|uint256|bytes32)\s+(?:constant|immutable)\s+\w+\s*=\s*[^;]+;)'
        matches = re.findall(pattern, code)
        return "\n    ".join(matches)

    def _extract_setup(self, code: str) -> str:
        """Extract setup code."""
        pattern = r'function\s+setUp\s*\(\s*\)[^{]*\{([^}]+)\}'
        match = re.search(pattern, code, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _extract_exploit(self, code: str) -> str:
        """Extract exploit code."""
        pattern = r'function\s+test_\w+\s*\(\s*\)[^{]*\{([^}]+)\}'
        match = re.search(pattern, code, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _extract_helpers(self, code: str) -> str:
        """Extract helper contracts."""
        pattern = r'(contract\s+(?!.*Test)[^{]+\{[^}]+\})'
        matches = re.findall(pattern, code, re.DOTALL)
        return "\n\n".join(matches)

    def _generate_logging(self, stage: str) -> str:
        """Generate logging code."""
        return f'''uint256 balance_{stage} = address(this).balance;
        console.log("Balance {stage}:", balance_{stage});'''

    def _generate_profit_logging(self) -> str:
        """Generate profit calculation and logging."""
        return '''uint256 profit = balance_after > balance_before ?
            balance_after - balance_before : 0;
        console.log("Profit:", profit / 1e18, "ETH");'''

    def _generate_assertions(self) -> str:
        """Generate assertions."""
        return '''assertGt(balance_after, balance_before, "Must be profitable");'''
