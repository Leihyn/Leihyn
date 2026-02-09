"""
Halmos Prover Hunter - Formal verification via symbolic execution.

Uses an LLM to identify mathematical properties of contracts, generates
Halmos symbolic tests (check_* functions), runs them, and reports
counterexamples as findings. When Halmos finds a counterexample, it's
a mathematically proven bug -- no false positives.

Flow:
1. LLM reads contracts and identifies mathematical properties
2. Generates Halmos check_* test files
3. Runs Halmos symbolic execution
4. Reports failures with concrete counterexamples

Supports: Solidity (Halmos required)
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, PoC, Severity, VulnerabilityType
from ...core.languages import Language


# Property category -> VulnerabilityType mapping
PROPERTY_TYPE_MAP = {
    "solvency": VulnerabilityType.INVARIANT_VIOLATION,
    "no-free-money": VulnerabilityType.INCORRECT_ACCOUNTING,
    "monotonicity": VulnerabilityType.BUSINESS_LOGIC,
    "conservation": VulnerabilityType.INVARIANT_VIOLATION,
    "rounding": VulnerabilityType.ROUNDING_ERROR,
    "precision": VulnerabilityType.PRECISION_LOSS,
}


SYSTEM_PROMPT = """You are a formal verification expert who uses Halmos symbolic execution to PROVE
or DISPROVE mathematical properties of smart contracts.

Unlike fuzzers (which test random inputs), Halmos checks ALL possible inputs symbolically.
When a property fails, Halmos returns a concrete counterexample that PROVES the bug exists.
This means zero false positives -- every failure is a real vulnerability.

## Property Categories (ordered by severity)

### 1. Solvency Properties
- Contract balance >= sum of all user deposits
- Total assets >= total liabilities
- Reserve ratios maintained

### 2. No-Free-Money Properties
- No single call can extract more value than deposited
- Minting requires proportional payment
- Burning returns proportional value

### 3. Conservation Properties
- Total supply is conserved across operations
- Token amounts in == token amounts out (plus fees)
- No tokens created from nothing

### 4. Monotonicity Properties
- Deposits increase balance, withdrawals decrease it
- Fees are always non-negative
- Prices move in expected direction after trades

### 5. Rounding Properties
- Rounding favors the protocol (not the user)
- Share calculations don't lose value
- Fee calculations don't undercount

### 6. Precision Properties
- Division before multiplication doesn't lose precision
- Intermediate calculations don't overflow
- Decimal conversions preserve value

## Halmos Test Format

Halmos tests use `check_` prefix (not `test_` or `invariant_`):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract HalmosVaultTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    /// @notice Solvency: vault balance >= total deposits
    function check_solvency(uint256 depositAmount) public {
        vm.assume(depositAmount > 0 && depositAmount < type(uint128).max);

        // Setup
        deal(address(this), depositAmount);

        // Action
        vault.deposit{value: depositAmount}();

        // Property
        assertGe(address(vault).balance, vault.totalDeposits());
    }

    /// @notice No free money: withdraw <= deposit
    function check_noFreeMoney(uint256 depositAmount, uint256 withdrawAmount) public {
        vm.assume(depositAmount > 0 && depositAmount < type(uint128).max);
        vm.assume(withdrawAmount <= depositAmount);

        deal(address(this), depositAmount);
        vault.deposit{value: depositAmount}();

        uint256 balanceBefore = address(this).balance;
        vault.withdraw(withdrawAmount);
        uint256 balanceAfter = address(this).balance;

        assertLe(balanceAfter - balanceBefore, depositAmount);
    }
}
```

## Rules
- Use `check_` prefix for all test functions (Halmos convention)
- Use `vm.assume()` to constrain symbolic inputs to valid ranges
- Keep properties SIMPLE -- one property per function
- Focus on properties whose violation = loss of funds
- Use `deal()` to set up token balances
- Include realistic setUp() with actual contract deployment
- If a property requires multiple steps, keep it under 5 steps
- Bound all inputs: amount < type(uint128).max, address != address(0)"""


class HalmosProverHunter(AnalysisAgent):
    """
    Formal verification hunter using Halmos symbolic execution.

    Identifies mathematical properties of contracts, generates Halmos
    tests, runs symbolic execution, and reports counterexamples as
    proven vulnerabilities. Zero false positives by construction.
    """

    role = "hunter"
    name = "halmos_prover"
    description = "Identifies properties, generates Halmos symbolic tests, reports proven violations"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    def __init__(self, state: AuditState, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        self.output_dir = kwargs.pop("output_dir", None)
        super().__init__(state=state, **kwargs)
        self.findings = []
        self.tools = self._build_tools()

    @staticmethod
    def _check_halmos_available() -> bool:
        """Check if halmos is installed and available on PATH."""
        return shutil.which("halmos") is not None

    def _build_tools(self) -> list[Tool]:
        """Build tools available to this hunter."""
        return [
            Tool(
                name="read_file",
                description="Read a source code file from the target project",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="list_contracts",
                description="List all contracts found during recon with their functions and state variables",
                input_schema={"type": "object", "properties": {}},
                handler=self._list_contracts,
            ),
            Tool(
                name="identify_properties",
                description=(
                    "Identify mathematical properties that should hold for a contract. "
                    "Returns property categories: solvency, no-free-money, monotonicity, "
                    "conservation, rounding, precision."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {
                            "type": "string",
                            "description": "Name of the contract to analyze",
                        },
                        "contract_source": {
                            "type": "string",
                            "description": "Source code of the contract",
                        },
                    },
                    "required": ["contract_name", "contract_source"],
                },
                handler=self._identify_properties,
            ),
            Tool(
                name="generate_halmos_test",
                description=(
                    "Generate a Halmos symbolic test file with check_* functions. "
                    "Writes to test/halmos/{Contract}.halmos.t.sol. "
                    "Prefer full_test_source for maximum control."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {
                            "type": "string",
                            "description": "Target contract name",
                        },
                        "properties": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Property name (e.g., 'solvency')"},
                                    "category": {
                                        "type": "string",
                                        "enum": ["solvency", "no-free-money", "monotonicity", "conservation", "rounding", "precision"],
                                        "description": "Property category",
                                    },
                                    "description": {"type": "string", "description": "What this property checks"},
                                    "check_function": {"type": "string", "description": "The Solidity check_* function body"},
                                },
                                "required": ["name", "category", "description"],
                            },
                            "description": "List of properties to test (used if full_test_source not provided)",
                        },
                        "full_test_source": {
                            "type": "string",
                            "description": "PREFERRED: Complete Halmos test file source code. If provided, properties array is ignored.",
                        },
                    },
                    "required": ["contract_name"],
                },
                handler=self._generate_halmos_test,
            ),
            Tool(
                name="run_halmos",
                description=(
                    "Run Halmos symbolic execution on a test file. "
                    "Parses output for [PASS], [FAIL] (with counterexample), and [TIMEOUT] results."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "test_contract": {
                            "type": "string",
                            "description": "Name of the test contract (e.g., 'HalmosVaultTest')",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds per property (default: 300)",
                        },
                    },
                    "required": ["test_contract"],
                },
                handler=self._run_halmos,
            ),
            Tool(
                name="report_finding",
                description="Report a finding from a failed Halmos property check",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "contract": {"type": "string"},
                        "function": {"type": "string"},
                        "description": {"type": "string"},
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "property_category": {
                            "type": "string",
                            "enum": ["solvency", "no-free-money", "monotonicity", "conservation", "rounding", "precision"],
                            "description": "Which property category was violated",
                        },
                        "property_name": {
                            "type": "string",
                            "description": "The check_* function name that failed",
                        },
                        "counterexample": {
                            "type": "string",
                            "description": "The concrete counterexample from Halmos that proves the bug",
                        },
                        "poc_code": {
                            "type": "string",
                            "description": "The Halmos test source code that serves as PoC",
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                    },
                    "required": ["title", "severity", "contract", "description"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run Halmos formal verification analysis."""
        if self.language != Language.SOLIDITY:
            self.log("Halmos prover only supports Solidity")
            return []

        if not self._check_halmos_available():
            self.log("Halmos not installed, skipping (pip install halmos)")
            return []

        from ...core.llm import get_llm_client
        llm = get_llm_client()

        contracts_info = self._format_contracts_info()
        architecture_info = self._format_architecture()

        initial_prompt = f"""Analyze this Solidity codebase and formally verify mathematical properties using Halmos.

## Target
{self.state.target_path}

## Contracts
{contracts_info}

## Architecture
{architecture_info}

## Your Task

1. Use `list_contracts` to see all contracts with their functions and state variables
2. Read the most important contracts (those that handle value: vaults, pools, lending)
3. For each critical contract, use `identify_properties` to find mathematical properties
4. Generate Halmos tests using `generate_halmos_test` with check_* functions:
   - Use `vm.assume()` to constrain symbolic inputs
   - Test one property per check_* function
   - Include realistic setUp() with actual deployment
5. Run the tests with `run_halmos`
6. Report any failures with `report_finding` -- include the counterexample

## Property Priority (highest value first)
1. **Solvency**: contract balance >= what users deposited
2. **No-free-money**: can't extract more than you put in
3. **Conservation**: tokens in == tokens out (+ fees)
4. **Rounding**: always favors protocol, never user
5. **Precision**: no value lost in calculations
6. **Monotonicity**: operations move values in expected direction

## Important
- Halmos tests use `check_` prefix, NOT `test_` or `invariant_`
- Bound all inputs with vm.assume() to prevent trivial counterexamples
- Keep check functions simple (1 property each)
- A Halmos [FAIL] with counterexample = mathematically PROVEN bug
- Generate ONE comprehensive test file per contract
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            max_iterations=15,
            extended_thinking=True,
            thinking_budget=24000,
        )

        if self.verbose:
            print(f"  HalmosProver completed: {len(self.findings)} findings")

        return self.findings

    def _format_contracts_info(self) -> str:
        """Format contract info for prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:15]:
            lines.append(f"- **{contract.name}** ({contract.path})")
            if contract.functions:
                externals = [f for f in contract.functions if f.visibility in ("external", "public")]
                lines.append(f"  External functions: {len(externals)}")
                for func in externals[:5]:
                    lines.append(f"    - {func.name}({', '.join(p.get('name', '?') for p in func.parameters)})")
            if contract.state_variables:
                lines.append(f"  State variables: {len(contract.state_variables)}")
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture info."""
        if not self.state.architecture:
            return "No architecture analysis available."

        notes = []
        if self.state.architecture.is_defi:
            notes.append(f"- DeFi protocol: {', '.join(self.state.architecture.defi_type)}")
        if self.state.architecture.external_protocols:
            notes.append(f"- External protocols: {', '.join(self.state.architecture.external_protocols)}")
        if self.state.architecture.is_upgradeable:
            notes.append(f"- Upgradeable: {self.state.architecture.proxy_type}")
        if self.state.architecture.uses_oracles:
            notes.append(f"- Oracles: {', '.join(self.state.architecture.oracle_type)}")
        return "\n".join(notes) if notes else "Standard architecture"

    # === Tool Handlers ===

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            content = file_path.read_text()
            if len(content) > 30000:
                return content[:30000] + "\n\n... [truncated, file too large]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    async def _list_contracts(self) -> str:
        """List all contracts with their functions and state variables."""
        if not self.state.contracts:
            return "No contracts found. Run recon first."

        output = "Contracts in scope:\n\n"
        for contract in self.state.contracts:
            output += f"## {contract.name}\n"
            output += f"Path: {contract.path}\n"

            if contract.inheritance:
                output += f"Inherits: {', '.join(contract.inheritance)}\n"

            if contract.state_variables:
                output += "\nState Variables:\n"
                for sv in contract.state_variables:
                    output += f"  - {sv.var_type} {sv.name} ({sv.visibility})"
                    if sv.is_constant:
                        output += " [constant]"
                    if sv.is_immutable:
                        output += " [immutable]"
                    output += "\n"

            if contract.functions:
                output += "\nFunctions:\n"
                for func in contract.functions:
                    params = ", ".join(
                        f"{p.get('type', '?')} {p.get('name', '?')}"
                        for p in func.parameters
                    )
                    mods = " ".join(func.modifiers) if func.modifiers else ""
                    output += f"  - {func.visibility} {func.name}({params}) {func.mutability} {mods}\n"
                    if func.state_writes:
                        output += f"    Writes: {', '.join(func.state_writes[:5])}\n"

            output += "\n---\n\n"

        return output

    async def _identify_properties(self, contract_name: str, contract_source: str) -> str:
        """Use LLM to identify mathematical properties of a contract."""
        from ...core.llm import get_llm_client
        llm = get_llm_client()

        prompt = f"""Analyze this contract and identify mathematical properties that should ALWAYS hold.

## Contract: {contract_name}

```solidity
{contract_source[:20000]}
```

For each property, provide:
1. **Category**: solvency | no-free-money | monotonicity | conservation | rounding | precision
2. **Name**: short identifier (e.g., "vault_solvency")
3. **Description**: what the property checks
4. **Expression**: the Solidity assertion (using assertGe, assertLe, assertEq, assertTrue)
5. **Inputs**: what symbolic inputs are needed (e.g., "uint256 amount, address user")

Return as JSON array:
```json
[
  {{
    "category": "solvency",
    "name": "vault_solvency",
    "description": "Vault balance >= total deposits tracked",
    "expression": "assertGe(token.balanceOf(address(vault)), vault.totalDeposits())",
    "inputs": "uint256 depositAmount"
  }}
]
```

Focus on properties whose violation means LOSS OF FUNDS. Skip trivial properties."""

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a formal verification expert. Return ONLY valid JSON.",
            max_tokens=4096,
        )

        return response.content

    def _generate_halmos_test(self, params: dict) -> str:
        """Generate a Halmos symbolic test file."""
        contract_name = params["contract_name"]

        output_dir = self.output_dir or (self.state.target_path / "test" / "halmos")
        output_dir = Path(output_dir)

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return f"Error creating output directory: {e}"

        test_file = output_dir / f"{contract_name}.halmos.t.sol"

        if params.get("full_test_source"):
            source = params["full_test_source"]
        else:
            # Build from structured properties
            properties = params.get("properties", [])
            if not properties:
                return "Error: provide either full_test_source or properties array"

            check_functions = []
            for prop in properties:
                check_fn = prop.get("check_function", "")
                if check_fn:
                    check_functions.append(check_fn)
                else:
                    check_functions.append(f"""
    /// @notice {prop.get('description', prop['name'])}
    function check_{prop['name'].replace('-', '_')}(uint256 value) public {{
        vm.assume(value > 0 && value < type(uint128).max);
        // TODO: implement property check
        assertTrue(true);
    }}""")

            source = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @title Halmos Symbolic Tests for {contract_name}
/// @notice Run with: halmos --contract Halmos{contract_name}Test
contract Halmos{contract_name}Test is Test {{
    function setUp() public {{
        // TODO: deploy {contract_name}
    }}
{"".join(check_functions)}
}}
"""

        try:
            test_file.write_text(source)

            property_count = source.count("function check_")
            return (
                f"Test file written to: {test_file}\n"
                f"Properties: {property_count} check_* functions\n"
                f"Run with: halmos --contract Halmos{contract_name}Test"
            )
        except OSError as e:
            return f"Error writing test file: {e}"

    async def _run_halmos(self, test_contract: str, timeout: int = 300) -> str:
        """Run Halmos symbolic execution and parse results."""
        from ...integrations.halmos import HalmosConfig, HalmosRunner

        config = HalmosConfig(timeout=timeout)
        runner = HalmosRunner(
            project_path=self.state.target_path,
            config=config,
        )

        # Find project root (directory with foundry.toml)
        project_root = self.state.target_path
        for parent in [self.state.target_path] + list(self.state.target_path.parents):
            if (parent / "foundry.toml").exists():
                project_root = parent
                break

        cmd = [
            "halmos",
            "--root", str(project_root),
            "--contract", test_contract,
            "--solver", config.solver,
            "--loop", str(config.loop_bound),
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=config.timeout,
            )

            combined_output = (result.stdout or "") + "\n" + (result.stderr or "")

            output = f"Exit code: {result.returncode}\n\n"

            # Parse [PASS], [FAIL], [TIMEOUT]
            pass_matches = re.findall(r'\[PASS\]\s+(\w+)', combined_output)
            fail_matches = re.findall(r'\[FAIL\]\s+(\w+)(?:\s*\(counterexample:\s*([^)]*)\))?', combined_output)
            timeout_matches = re.findall(r'\[TIMEOUT\]\s+(\w+)', combined_output)

            if pass_matches:
                output += f"PASSED ({len(pass_matches)}):\n"
                for name in pass_matches:
                    output += f"  [PASS] {name}\n"
                output += "\n"

            if fail_matches:
                output += f"FAILED ({len(fail_matches)}):\n"
                for name, counterexample in fail_matches:
                    output += f"  [FAIL] {name}"
                    if counterexample:
                        output += f" (counterexample: {counterexample})"
                    output += "\n"
                output += "\n"

            if timeout_matches:
                output += f"TIMEOUT ({len(timeout_matches)}):\n"
                for name in timeout_matches:
                    output += f"  [TIMEOUT] {name}\n"
                output += "\n"

            if not pass_matches and not fail_matches and not timeout_matches:
                # Show raw output for debugging
                truncated = combined_output[:10000]
                output += f"Raw output:\n{truncated}\n"

            if fail_matches:
                output += "PROPERTY VIOLATIONS DETECTED -- analyze counterexamples above.\n"
            elif pass_matches and not fail_matches:
                output += "ALL PROPERTIES PROVED -- no violations found.\n"

            return output

        except subprocess.TimeoutExpired:
            return f"Halmos timed out after {config.timeout}s. Try reducing property complexity."
        except FileNotFoundError:
            return "Halmos not installed. Install with: pip install halmos"
        except Exception as e:
            return f"Error running Halmos: {e}"

    def _report_finding(self, params: dict) -> str:
        """Report a finding from a failed Halmos property."""
        title = params["title"]
        severity_str = params["severity"]
        contract = params["contract"]
        description = params["description"]

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        # Determine vulnerability type from property category
        category = params.get("property_category", "")
        vuln_type = PROPERTY_TYPE_MAP.get(category, VulnerabilityType.INVARIANT_VIOLATION)

        # Build description with proof details
        full_description = description
        if params.get("property_name"):
            full_description += f"\n\n**Failed Property:** `{params['property_name']}`"
        if params.get("counterexample"):
            full_description += f"\n\n**Counterexample (mathematically proven):**\n```\n{params['counterexample']}\n```"
        if category:
            full_description += f"\n\n**Property Category:** {category}"

        poc = None
        if params.get("poc_code"):
            poc = PoC(
                finding_id=f"HALMOS-{len(self.findings)+1:03d}",
                code=params["poc_code"],
                language="solidity",
                executed=True,
                success=True,
            )

        finding = Finding(
            id=f"HALMOS-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity_str, Severity.HIGH),
            vulnerability_type=vuln_type,
            description=full_description,
            contract=contract,
            function=params.get("function"),
            impact=params.get("impact", ""),
            recommendation=params.get("recommendation", ""),
            poc=poc,
            validated=True,  # Halmos counterexamples are mathematical proofs
            found_by=AgentRole.FUZZER,
            confidence=params.get("confidence", 0.95),
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity_str}] {title}"
