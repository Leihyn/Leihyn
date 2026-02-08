"""
Foundry integration for testing, fuzzing, and PoC execution.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class TestResult:
    """Result of a Foundry test run."""
    success: bool
    test_name: str
    gas_used: Optional[int] = None
    logs: list[str] = None
    traces: Optional[str] = None
    error: Optional[str] = None
    duration_ms: int = 0


@dataclass
class FuzzResult:
    """Result of a fuzzing campaign."""
    success: bool
    runs: int
    counterexample: Optional[dict] = None
    error: Optional[str] = None


def check_foundry_installed() -> bool:
    """Check if Foundry is installed."""
    try:
        result = subprocess.run(
            ["forge", "--version"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def run_forge_test(
    project_path: Path,
    test_contract: Optional[str] = None,
    test_function: Optional[str] = None,
    fork_url: Optional[str] = None,
    fork_block: Optional[int] = None,
    verbosity: int = 2,
    gas_report: bool = False,
) -> list[TestResult]:
    """
    Run Foundry tests.

    Args:
        project_path: Path to Foundry project
        test_contract: Specific contract to test
        test_function: Specific function to test
        fork_url: RPC URL for forking
        fork_block: Block number for fork
        verbosity: Output verbosity (0-5)
        gas_report: Include gas report

    Returns:
        List of test results
    """
    cmd = ["forge", "test", "--json"]

    if test_contract:
        cmd.extend(["--match-contract", test_contract])

    if test_function:
        cmd.extend(["--match-test", test_function])

    if fork_url:
        cmd.extend(["--fork-url", fork_url])

    if fork_block:
        cmd.extend(["--fork-block-number", str(fork_block)])

    if verbosity:
        cmd.append("-" + "v" * verbosity)

    if gas_report:
        cmd.append("--gas-report")

    try:
        result = subprocess.run(
            cmd,
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )
    except subprocess.TimeoutExpired:
        return [TestResult(success=False, test_name="*", error="Test timed out")]
    except FileNotFoundError:
        return [TestResult(success=False, test_name="*", error="Foundry not found")]

    # Parse JSON output
    results = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            data = json.loads(line)

            # Handle test result format
            if "test_results" in data:
                for contract_name, contract_results in data["test_results"].items():
                    for test_name, test_data in contract_results.items():
                        results.append(
                            TestResult(
                                success=test_data.get("status") == "Success",
                                test_name=f"{contract_name}::{test_name}",
                                gas_used=test_data.get("gas_used"),
                                logs=test_data.get("logs", []),
                                error=test_data.get("reason"),
                            )
                        )
        except json.JSONDecodeError:
            continue

    # If no JSON results, parse text output
    if not results and result.returncode != 0:
        results.append(
            TestResult(
                success=False,
                test_name="*",
                error=result.stderr or result.stdout,
            )
        )

    return results


def run_forge_fuzz(
    project_path: Path,
    test_contract: str,
    test_function: str,
    runs: int = 1000,
    fork_url: Optional[str] = None,
    fork_block: Optional[int] = None,
) -> FuzzResult:
    """
    Run Foundry fuzzing on a specific test.

    Args:
        project_path: Path to Foundry project
        test_contract: Contract containing the fuzz test
        test_function: Fuzz test function name
        runs: Number of fuzz runs
        fork_url: RPC URL for forking
        fork_block: Block number for fork

    Returns:
        Fuzzing result
    """
    cmd = [
        "forge", "test",
        "--match-contract", test_contract,
        "--match-test", test_function,
        "--fuzz-runs", str(runs),
        "-vvv",
    ]

    if fork_url:
        cmd.extend(["--fork-url", fork_url])
    if fork_block:
        cmd.extend(["--fork-block-number", str(fork_block)])

    try:
        result = subprocess.run(
            cmd,
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minute timeout for fuzzing
        )
    except subprocess.TimeoutExpired:
        return FuzzResult(success=False, runs=0, error="Fuzzing timed out")

    # Check for counterexample
    counterexample = None
    if "Counterexample:" in result.stdout:
        # Parse counterexample
        ce_start = result.stdout.find("Counterexample:")
        ce_end = result.stdout.find("\n\n", ce_start)
        ce_text = result.stdout[ce_start:ce_end]
        counterexample = {"raw": ce_text}

    return FuzzResult(
        success=result.returncode == 0,
        runs=runs,
        counterexample=counterexample,
        error=result.stderr if result.returncode != 0 else None,
    )


def run_invariant_test(
    project_path: Path,
    test_contract: str,
    runs: int = 256,
    depth: int = 15,
    fork_url: Optional[str] = None,
) -> FuzzResult:
    """
    Run Foundry invariant testing.

    Args:
        project_path: Path to Foundry project
        test_contract: Contract containing invariant tests
        runs: Number of runs
        depth: Call depth per run
        fork_url: RPC URL for forking

    Returns:
        Invariant test result
    """
    cmd = [
        "forge", "test",
        "--match-contract", test_contract,
        "-vvv",
    ]

    # Set invariant config via env
    env = os.environ.copy()
    env["FOUNDRY_INVARIANT_RUNS"] = str(runs)
    env["FOUNDRY_INVARIANT_DEPTH"] = str(depth)

    if fork_url:
        cmd.extend(["--fork-url", fork_url])

    try:
        result = subprocess.run(
            cmd,
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout
            env=env,
        )
    except subprocess.TimeoutExpired:
        return FuzzResult(success=False, runs=0, error="Invariant testing timed out")

    # Parse for violations
    counterexample = None
    if "FAIL" in result.stdout:
        # Find call sequence that broke invariant
        if "Call sequence:" in result.stdout:
            cs_start = result.stdout.find("Call sequence:")
            cs_end = result.stdout.find("\n\n", cs_start)
            counterexample = {"call_sequence": result.stdout[cs_start:cs_end]}

    return FuzzResult(
        success=result.returncode == 0,
        runs=runs,
        counterexample=counterexample,
        error=None if result.returncode == 0 else result.stderr,
    )


def create_poc_project(
    target_address: str,
    poc_code: str,
    fork_url: str,
    fork_block: Optional[int] = None,
) -> Path:
    """
    Create a temporary Foundry project for running a PoC.

    Args:
        target_address: Address of target contract on fork
        poc_code: Solidity PoC code
        fork_url: RPC URL for forking
        fork_block: Block number for fork

    Returns:
        Path to the created project
    """
    # Create temp directory
    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_poc_"))

    # Initialize Foundry project
    subprocess.run(
        ["forge", "init", "--no-git", "--no-commit"],
        cwd=temp_dir,
        capture_output=True,
    )

    # Write PoC to test file
    test_file = temp_dir / "test" / "PoC.t.sol"
    test_file.write_text(poc_code)

    # Update foundry.toml with fork settings
    foundry_toml = temp_dir / "foundry.toml"
    config = f"""
[profile.default]
src = "src"
out = "out"
libs = ["lib"]

[rpc_endpoints]
mainnet = "{fork_url}"

[fuzz]
runs = 256
"""
    if fork_block:
        config += f'\nfork_block_number = {fork_block}'

    foundry_toml.write_text(config)

    return temp_dir


def run_poc(
    poc_code: str,
    fork_url: str,
    fork_block: Optional[int] = None,
    cleanup: bool = True,
) -> TestResult:
    """
    Run a PoC exploit against a forked chain.

    Args:
        poc_code: Complete Foundry test file code
        fork_url: RPC URL for forking
        fork_block: Block number for fork
        cleanup: Whether to cleanup temp files after

    Returns:
        Test result
    """
    # Create project
    project_path = create_poc_project(
        target_address="",  # Will be in poc_code
        poc_code=poc_code,
        fork_url=fork_url,
        fork_block=fork_block,
    )

    try:
        # Run the test
        results = run_forge_test(
            project_path=project_path,
            fork_url=fork_url,
            fork_block=fork_block,
            verbosity=3,
        )

        if results:
            return results[0]
        else:
            return TestResult(success=False, test_name="PoC", error="No test results")

    finally:
        if cleanup:
            import shutil
            shutil.rmtree(project_path, ignore_errors=True)


def start_anvil(
    fork_url: Optional[str] = None,
    fork_block: Optional[int] = None,
    port: int = 8545,
) -> subprocess.Popen:
    """
    Start an Anvil local node.

    Args:
        fork_url: RPC URL to fork from
        fork_block: Block number for fork
        port: Port to run on

    Returns:
        Anvil process handle
    """
    cmd = ["anvil", "--port", str(port)]

    if fork_url:
        cmd.extend(["--fork-url", fork_url])
    if fork_block:
        cmd.extend(["--fork-block-number", str(fork_block)])

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def compile_contract(
    source_path: Path,
    output_dir: Optional[Path] = None,
) -> tuple[bool, str]:
    """
    Compile a Solidity contract using forge.

    Returns:
        Tuple of (success, error_message)
    """
    cmd = ["forge", "build"]

    if output_dir:
        cmd.extend(["--out", str(output_dir)])

    result = subprocess.run(
        cmd,
        cwd=source_path.parent if source_path.is_file() else source_path,
        capture_output=True,
        text=True,
    )

    return result.returncode == 0, result.stderr
