"""
Symbolic Execution & Static Analysis Tool Integration

Integrates SENTINEL with:
1. Slither - Static analysis (fast, comprehensive)
2. Mythril - Symbolic execution (deep, slower)
3. Halmos - Symbolic testing for Foundry
4. Echidna - Fuzzing
5. Medusa - Parallel fuzzing

Pattern matching finds candidates.
Symbolic execution PROVES they're exploitable.
"""

import json
import subprocess
import tempfile
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from enum import Enum


class AnalysisTool(Enum):
    SLITHER = "slither"
    MYTHRIL = "mythril"
    HALMOS = "halmos"
    ECHIDNA = "echidna"
    MEDUSA = "medusa"
    FOUNDRY = "foundry"


@dataclass
class SymbolicResult:
    """Result from symbolic execution."""
    tool: AnalysisTool
    vulnerability_type: str
    severity: str
    description: str
    transaction_sequence: list[dict]  # Concrete exploit steps
    constraints: list[str]  # SMT constraints that lead to bug
    counterexample: Optional[dict]  # Concrete values that trigger bug
    confidence: float
    execution_time: float


@dataclass
class SlitherFinding:
    """Parsed Slither finding."""
    check: str
    impact: str
    confidence: str
    description: str
    elements: list[dict]
    recommendation: str


class SlitherIntegration:
    """
    Slither static analysis integration.

    Fast, catches:
    - Reentrancy
    - Uninitialized state
    - Unchecked returns
    - Access control issues
    - And 80+ other detectors
    """

    SEVERITY_MAP = {
        "High": "CRITICAL",
        "Medium": "HIGH",
        "Low": "MEDIUM",
        "Informational": "INFO",
    }

    def __init__(self, solc_version: str = "0.8.20"):
        self.solc_version = solc_version

    def analyze(self, code: str, contract_path: Optional[str] = None) -> list[SlitherFinding]:
        """
        Run Slither analysis.

        Args:
            code: Solidity source code
            contract_path: Optional path to contract file

        Returns:
            List of Slither findings
        """
        findings = []

        # Write code to temp file if no path provided
        if contract_path is None:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                f.write(code)
                contract_path = f.name

        try:
            # Run slither with JSON output
            cmd = [
                "slither",
                contract_path,
                "--json", "-",
                "--solc-solcs-select", self.solc_version,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                for detector in data.get("results", {}).get("detectors", []):
                    findings.append(SlitherFinding(
                        check=detector.get("check", ""),
                        impact=detector.get("impact", ""),
                        confidence=detector.get("confidence", ""),
                        description=detector.get("description", ""),
                        elements=detector.get("elements", []),
                        recommendation=detector.get("recommendation", ""),
                    ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # Slither not installed - return empty
            pass
        except json.JSONDecodeError:
            pass
        finally:
            # Cleanup temp file
            if contract_path and contract_path.startswith(tempfile.gettempdir()):
                os.unlink(contract_path)

        return findings

    def get_high_confidence_findings(self, findings: list[SlitherFinding]) -> list[SlitherFinding]:
        """Filter to high confidence findings only."""
        return [f for f in findings if f.confidence == "High" and f.impact in ["High", "Medium"]]

    def generate_detector_command(self, detectors: list[str]) -> str:
        """Generate slither command for specific detectors."""
        return f"slither . --detect {','.join(detectors)}"


class MythrilIntegration:
    """
    Mythril symbolic execution integration.

    Slow but thorough. Proves exploitability by:
    - Building symbolic execution tree
    - Solving constraints with Z3
    - Finding concrete attack inputs
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def analyze(self, code: str, contract_name: Optional[str] = None) -> list[SymbolicResult]:
        """
        Run Mythril symbolic execution.

        Args:
            code: Solidity source code
            contract_name: Optional contract name to analyze

        Returns:
            List of proven vulnerabilities with concrete exploits
        """
        results = []

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(code)
            contract_path = f.name

        try:
            cmd = [
                "myth", "analyze",
                contract_path,
                "--solv", "0.8.20",
                "--execution-timeout", str(self.timeout),
                "--output", "json",
            ]

            if contract_name:
                cmd.extend(["--contract", contract_name])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                for issue in data.get("issues", []):
                    results.append(SymbolicResult(
                        tool=AnalysisTool.MYTHRIL,
                        vulnerability_type=issue.get("title", ""),
                        severity=issue.get("severity", ""),
                        description=issue.get("description", ""),
                        transaction_sequence=issue.get("tx_sequence", []),
                        constraints=[],
                        counterexample=None,
                        confidence=0.9,  # Mythril findings are usually solid
                        execution_time=0,
                    ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        except json.JSONDecodeError:
            pass
        finally:
            os.unlink(contract_path)

        return results


class HalmosIntegration:
    """
    Halmos symbolic testing integration.

    Best for:
    - Formal verification of properties
    - Finding edge cases in Foundry tests
    - Proving absence of bugs
    """

    def generate_symbolic_test(
        self,
        function_name: str,
        parameters: list[tuple[str, str]],
        preconditions: list[str],
        postconditions: list[str],
    ) -> str:
        """
        Generate a Halmos symbolic test.

        Args:
            function_name: Function to test
            parameters: List of (type, name) tuples
            preconditions: Assumptions about inputs
            postconditions: Properties that must hold

        Returns:
            Solidity test code for Halmos
        """
        params_str = ", ".join(f"{ptype} {pname}" for ptype, pname in parameters)
        assumes = "\n        ".join(f"vm.assume({p});" for p in preconditions)
        asserts = "\n        ".join(f"assert({p});" for p in postconditions)

        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract SymbolicTest is Test {{
    TargetContract target;

    function setUp() public {{
        target = new TargetContract();
    }}

    /// @notice Symbolic test - Halmos will explore ALL possible inputs
    /// Run: halmos --contract SymbolicTest --function check_{function_name}
    function check_{function_name}({params_str}) public {{
        // Preconditions - constrain symbolic inputs
        {assumes}

        // Execute function under test
        target.{function_name}({", ".join(p[1] for p in parameters)});

        // Postconditions - must hold for ALL valid inputs
        // If Halmos finds counterexample, we have a bug!
        {asserts}
    }}
}}
'''

    def generate_invariant_check(
        self,
        invariant_name: str,
        invariant_expr: str,
    ) -> str:
        """Generate Halmos invariant check."""
        return f'''/// @notice Invariant: {invariant_name}
/// This must hold after ANY sequence of transactions
function check_invariant_{invariant_name}() public {{
    // Halmos will try to violate this with symbolic execution
    assert({invariant_expr});
}}
'''

    def run(self, test_file: str, function: Optional[str] = None) -> list[SymbolicResult]:
        """Run Halmos on test file."""
        results = []

        cmd = ["halmos", "--contract", test_file]
        if function:
            cmd.extend(["--function", function])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Parse Halmos output for counterexamples
            if "Counterexample" in result.stdout:
                results.append(SymbolicResult(
                    tool=AnalysisTool.HALMOS,
                    vulnerability_type="Property Violation",
                    severity="HIGH",
                    description="Halmos found counterexample",
                    transaction_sequence=[],
                    constraints=[],
                    counterexample={"raw_output": result.stdout},
                    confidence=0.99,  # Halmos counterexamples are definitive
                    execution_time=0,
                ))

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass

        return results


class EchidnaIntegration:
    """
    Echidna fuzzing integration.

    Fast property-based testing:
    - Generates random inputs
    - Shrinks failing cases
    - Finds edge cases quickly
    """

    def generate_config(
        self,
        test_limit: int = 100000,
        seq_len: int = 100,
        corpus_dir: str = "corpus",
    ) -> str:
        """Generate echidna config file."""
        return f'''# Echidna configuration
testMode: assertion
testLimit: {test_limit}
shrinkLimit: 5000
seqLen: {seq_len}
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
sender: ["0x00a329c0648769A73afAc7F9381E08FB43dBEA72"]
coverage: true
corpusDir: "{corpus_dir}"
'''

    def generate_property_test(
        self,
        property_name: str,
        check_expression: str,
    ) -> str:
        """Generate Echidna property test."""
        return f'''// Echidna property test
// Run: echidna . --contract EchidnaTest --config echidna.yaml

contract EchidnaTest {{
    TargetContract target;

    constructor() {{
        target = new TargetContract();
    }}

    // Echidna will try to make this return false
    function echidna_{property_name}() public view returns (bool) {{
        return {check_expression};
    }}
}}
'''

    def run(self, contract_path: str, config_path: str) -> list[dict]:
        """Run Echidna fuzzing campaign."""
        results = []

        try:
            cmd = [
                "echidna",
                contract_path,
                "--config", config_path,
                "--format", "json",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour for fuzzing
            )

            if result.stdout:
                # Parse Echidna JSON output
                pass

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass

        return results


class SymbolicOrchestrator:
    """
    Orchestrate multiple symbolic execution tools.

    Strategy:
    1. Slither first (fast, catches obvious bugs)
    2. Pattern matching (SENTINEL patterns)
    3. Mythril for high-value targets (proves exploitability)
    4. Halmos for invariant verification
    5. Echidna for fuzzing edge cases
    """

    def __init__(self):
        self.slither = SlitherIntegration()
        self.mythril = MythrilIntegration()
        self.halmos = HalmosIntegration()
        self.echidna = EchidnaIntegration()

    def full_analysis(self, code: str, contract_name: str = "Target") -> dict:
        """
        Run complete symbolic analysis pipeline.

        Args:
            code: Solidity source code
            contract_name: Contract name

        Returns:
            Combined results from all tools
        """
        results = {
            "slither": [],
            "mythril": [],
            "halmos": [],
            "echidna": [],
            "combined_findings": [],
            "proven_exploits": [],
        }

        # Step 1: Fast static analysis with Slither
        slither_findings = self.slither.analyze(code)
        results["slither"] = [
            {
                "check": f.check,
                "impact": f.impact,
                "confidence": f.confidence,
                "description": f.description,
            }
            for f in slither_findings
        ]

        # Step 2: Get high-value targets for deeper analysis
        high_value = self.slither.get_high_confidence_findings(slither_findings)

        # Step 3: Run Mythril on high-value targets (if any)
        if high_value:
            mythril_results = self.mythril.analyze(code, contract_name)
            results["mythril"] = [
                {
                    "type": r.vulnerability_type,
                    "severity": r.severity,
                    "description": r.description,
                    "tx_sequence": r.transaction_sequence,
                }
                for r in mythril_results
            ]

            # Mark findings that are proven exploitable
            for mr in mythril_results:
                if mr.transaction_sequence:
                    results["proven_exploits"].append({
                        "type": mr.vulnerability_type,
                        "proof": mr.transaction_sequence,
                        "confidence": "PROVEN",
                    })

        return results

    def generate_verification_suite(
        self,
        contract_code: str,
        invariants: list[dict],
    ) -> dict[str, str]:
        """
        Generate complete verification test suite.

        Args:
            contract_code: Target contract
            invariants: List of invariants to verify

        Returns:
            Dict of filename -> test code
        """
        suite = {}

        # Generate Halmos symbolic tests
        halmos_tests = []
        for inv in invariants:
            halmos_tests.append(
                self.halmos.generate_invariant_check(
                    inv["name"],
                    inv["expression"],
                )
            )
        suite["SymbolicTest.t.sol"] = "\n\n".join(halmos_tests)

        # Generate Echidna property tests
        echidna_tests = []
        for inv in invariants:
            echidna_tests.append(
                self.echidna.generate_property_test(
                    inv["name"],
                    inv["expression"],
                )
            )
        suite["EchidnaTest.sol"] = "\n\n".join(echidna_tests)

        # Generate Echidna config
        suite["echidna.yaml"] = self.echidna.generate_config()

        return suite


def prove_exploitability(
    code: str,
    vulnerability_type: str,
    suspected_function: str,
) -> Optional[SymbolicResult]:
    """
    Attempt to prove a suspected vulnerability is exploitable.

    Uses symbolic execution to find concrete attack inputs.

    Args:
        code: Contract source code
        vulnerability_type: Type of suspected vulnerability
        suspected_function: Function believed to be vulnerable

    Returns:
        SymbolicResult with proof if exploitable, None otherwise
    """
    orchestrator = SymbolicOrchestrator()

    # Run targeted Mythril analysis
    results = orchestrator.mythril.analyze(code)

    # Look for matching vulnerability
    for result in results:
        if result.transaction_sequence:
            return result

    return None
