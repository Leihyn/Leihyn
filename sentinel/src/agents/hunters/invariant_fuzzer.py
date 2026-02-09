"""
Invariant Fuzzer Hunter - Generates and executes Foundry invariant tests.

The highest-ROI tool for finding real vulnerabilities in audit contests.
Unlike static analysis (which finds patterns), invariant fuzzing finds
actual STATE VIOLATIONS -- the kind that win $5K-$25K bounties.

Flow:
1. LLM reads contracts and infers protocol invariants
2. Generates Foundry invariant_* test files with handler contracts
3. Runs forge test --fuzz-runs to execute them
4. Reports broken invariants as findings with PoC

Supports: Solidity (Foundry required)
"""

import asyncio
import json
import subprocess
import re
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, PoC, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite smart contract security researcher who thinks in INVARIANTS.

Top auditors don't grep for patterns -- they ask "what MUST always be true?" and then
try to break it. You generate Foundry invariant tests that catch real vulnerabilities.

## Invariant Categories (ordered by payout likelihood)

### 1. Accounting Invariants (most likely to pay)
- totalSupply == sum(balances) for all holders
- sum(deposits) - sum(withdrawals) == contractBalance
- collateral * ratio >= debt (for every position)
- reserveA * reserveB >= k (AMM invariant)
- fee accruals never exceed principal

### 2. State Transition Invariants
- Initialized contracts cannot be re-initialized
- Paused contracts reject all state-changing calls
- Only valid state transitions occur (e.g., PENDING -> ACTIVE -> CLOSED)
- Ownership changes require proper authorization

### 3. Economic Invariants
- No single transaction can extract more value than deposited
- Price manipulation within a single block is bounded
- Flash loan attacks cannot profit (borrow == repay + fee)
- Liquidation always makes the protocol healthier

### 4. Access Control Invariants
- Critical functions only callable by authorized roles
- Role assignment requires proper authorization chain
- Self-destruct / upgrade only by owner

## Foundry Invariant Test Structure

```solidity
// Handler contract: calls protocol functions with random params
contract Handler is CommonBase, StdCheats, StdUtils {
    TargetContract public target;

    // Ghost variables track expected state
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;

    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1e24);  // Clamp inputs
        deal(address(token), address(this), amount);
        token.approve(address(target), amount);
        target.deposit(amount);
        ghost_totalDeposited += amount;
    }

    function withdraw(uint256 amount) public {
        amount = bound(amount, 0, target.balanceOf(address(this)));
        target.withdraw(amount);
        ghost_totalWithdrawn += amount;
    }
}

// Invariant test contract
contract InvariantTest is Test {
    Handler handler;

    function setUp() public {
        // Deploy protocol + handler
        handler = new Handler(...);
        targetContract(address(handler));
    }

    function invariant_solvency() public {
        // Protocol must always be solvent
        assertGe(
            token.balanceOf(address(target)),
            handler.ghost_totalDeposited() - handler.ghost_totalWithdrawn()
        );
    }
}
```

## Rules
- ALWAYS use `bound()` to clamp fuzzed inputs to valid ranges
- Use ghost variables to track cumulative state
- Test with multiple actors (at least 2)
- Include setup that puts the protocol in a realistic state
- Focus on invariants whose violation = loss of funds
- Each invariant_* function tests ONE property"""


class InvariantFuzzerHunter(AnalysisAgent):
    """
    Generates and executes Foundry invariant tests to find real vulnerabilities.

    This hunter is the highest-signal tool in Sentinel's arsenal. Unlike pattern
    matching (which produces false positives), broken invariants are ALWAYS real bugs.
    """

    role = "hunter"
    name = "invariant_fuzzer"
    description = "Generates Foundry invariant tests, runs them, reports broken invariants"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    def __init__(self, state: AuditState, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        self.fuzz_runs = kwargs.pop("fuzz_runs", 5000)
        self.output_dir = kwargs.pop("output_dir", None)
        self.suggested_invariants: list[dict] = kwargs.pop("suggested_invariants", [])
        super().__init__(state=state, **kwargs)
        self.findings = []
        self.tools = self._build_tools()

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
                name="generate_invariant_test",
                description="Generate a complete Foundry invariant test file. The test will be written to disk and optionally executed.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "test_name": {
                            "type": "string",
                            "description": "Name for the test file (e.g., 'Solvency', 'Accounting')",
                        },
                        "target_contracts": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Contract names being tested",
                        },
                        "invariants": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "Invariant function name (e.g., 'invariant_solvency')"},
                                    "description": {"type": "string", "description": "What this invariant checks"},
                                    "expression": {"type": "string", "description": "The Solidity assertion expression"},
                                },
                                "required": ["name", "description", "expression"],
                            },
                            "description": "List of invariants to test",
                        },
                        "handler_code": {
                            "type": "string",
                            "description": "Complete Solidity source for the Handler contract (with ghost variables, bound() calls, etc.)",
                        },
                        "setup_code": {
                            "type": "string",
                            "description": "Complete Solidity source for the setUp() function body",
                        },
                        "imports": {
                            "type": "string",
                            "description": "Import statements needed (forge-std, target contracts, etc.)",
                        },
                        "full_test_source": {
                            "type": "string",
                            "description": "PREFERRED: Complete test file source code. If provided, handler_code/setup_code/imports are ignored.",
                        },
                    },
                    "required": ["test_name", "target_contracts", "invariants"],
                },
                handler=self._generate_invariant_test,
            ),
            Tool(
                name="run_invariant_tests",
                description="Execute generated invariant tests with forge and return results",
                input_schema={
                    "type": "object",
                    "properties": {
                        "test_file": {
                            "type": "string",
                            "description": "Path to the test file to run (relative to project root)",
                        },
                        "fuzz_runs": {
                            "type": "integer",
                            "description": "Number of fuzz runs (default: 5000)",
                        },
                    },
                    "required": ["test_file"],
                },
                handler=self._run_invariant_tests,
            ),
            Tool(
                name="report_finding",
                description="Report a finding from a broken invariant",
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
                        "invariant_violated": {
                            "type": "string",
                            "description": "The invariant expression that was broken",
                        },
                        "counterexample": {
                            "type": "string",
                            "description": "The counterexample/call sequence from forge that broke it",
                        },
                        "poc_code": {
                            "type": "string",
                            "description": "The invariant test source code that serves as PoC",
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
        """Run invariant fuzzing analysis."""
        if self.language != Language.SOLIDITY:
            self.log("Invariant fuzzing currently only supports Solidity/Foundry")
            return []

        from ...core.llm import get_llm_client
        llm = get_llm_client()

        contracts_info = self._format_contracts_info()
        architecture_info = self._format_architecture()

        # Build suggested invariants from either explicit suggestions or state findings
        if not self.suggested_invariants:
            # Auto-detect from ReasoningHunter findings already in state
            self.suggested_invariants = [
                {
                    "invariant": f"Test for: {f.title}",
                    "description": f.impact or f.description[:100],
                    "contract": f.contract,
                    "severity": f.severity.value,
                    "foundry_test_concept": f.root_cause,
                }
                for f in self.state.findings
                if f.id.startswith("REASON-")
            ]

        suggested_section = ""
        if self.suggested_invariants:
            lines = ["## Suggested Invariants (from concrete execution tracing)",
                     "These were identified by the ReasoningHunter as likely-violated invariants.",
                     "PRIORITIZE testing these first:\n"]
            for s in self.suggested_invariants:
                lines.append(f"- **[{s.get('severity', 'Medium')}]** {s['invariant']}")
                lines.append(f"  Contract: {s['contract']} — {s['description']}")
                if s.get("foundry_test_concept"):
                    lines.append(f"  Test hint: {s['foundry_test_concept']}")
            suggested_section = "\n".join(lines)

        initial_prompt = f"""Analyze this Solidity codebase and generate Foundry invariant tests to find real vulnerabilities.

## Target
{self.state.target_path}

## Contracts
{contracts_info}

## Architecture
{architecture_info}

{suggested_section}

## Your Task

1. Use `list_contracts` to see all contracts with their functions and state variables
2. Read the most important contracts (the ones that hold funds, manage state, or perform swaps)
3. Identify 5-15 critical invariants that MUST always hold
4. Generate Foundry invariant tests using `generate_invariant_test`:
   - Create Handler contracts that call protocol functions with bounded random inputs
   - Use ghost variables to track cumulative state
   - Write invariant_* functions that assert the properties
   - Include realistic setUp() that deploys the full protocol
5. Run the tests with `run_invariant_tests`
6. Report any broken invariants as findings with `report_finding`

## Priority Order
Focus on invariants whose violation = loss of funds:
1. Solvency: protocol balance >= sum of user deposits
2. Accounting: internal tracking matches actual token balances
3. Economic: no single-tx profit extraction (arbitrage, flash loans)
4. Access: critical functions properly gated
5. State: valid transitions only

## Important
- Use `bound()` to clamp ALL fuzzed inputs
- Use `deal()` to give actors tokens
- Target real contract addresses (not mocks)
- If forge fails to compile, read the error and fix the test
- Generate ONE comprehensive test file, not many small ones
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            max_iterations=15,
        )

        if self.verbose:
            print(f"  InvariantFuzzer completed: {len(self.findings)} findings")

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
            # Truncate very large files
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
            if contract.is_upgradeable:
                output += "Upgradeable: YES\n"

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
                    if func.external_calls:
                        output += f"    Calls: {', '.join(c.target + '.' + c.function for c in func.external_calls[:3])}\n"

            output += "\n---\n\n"

        return output

    def _generate_invariant_test(self, params: dict) -> str:
        """Generate a Foundry invariant test file."""
        test_name = params["test_name"]
        target_contracts = params["target_contracts"]
        invariants = params["invariants"]

        # Determine output path
        output_dir = self.output_dir or (self.state.target_path / "test" / "invariants")
        output_dir = Path(output_dir)

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return f"Error creating output directory: {e}"

        test_file = output_dir / f"{test_name}.invariant.t.sol"

        # Use full_test_source if provided (preferred)
        if params.get("full_test_source"):
            source = params["full_test_source"]
        else:
            # Build from components
            imports = params.get("imports", 'import "forge-std/Test.sol";')
            handler_code = params.get("handler_code", "// No handler provided")
            setup_code = params.get("setup_code", "// No setup provided")

            invariant_functions = ""
            for inv in invariants:
                invariant_functions += f"""
    /// @notice {inv['description']}
    function {inv['name']}() public view {{
        {inv['expression']}
    }}
"""

            source = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

{imports}

{handler_code}

contract {test_name}InvariantTest is Test {{
    function setUp() public {{
        {setup_code}
    }}
{invariant_functions}
}}
"""

        # Write test file
        try:
            test_file.write_text(source)
            return f"Test file written to: {test_file}\n\nInvariants:\n" + "\n".join(
                f"  - {inv['name']}: {inv['description']}"
                for inv in invariants
            )
        except OSError as e:
            return f"Error writing test file: {e}"

    async def _run_invariant_tests(self, test_file: str, fuzz_runs: int = None) -> str:
        """Execute invariant tests with forge."""
        runs = fuzz_runs or self.fuzz_runs

        # Resolve test file path
        test_path = Path(test_file)
        if not test_path.is_absolute():
            test_path = self.state.target_path / test_file

        if not test_path.exists():
            return f"Test file not found: {test_path}"

        # Find project root (directory with foundry.toml)
        project_root = self.state.target_path
        for parent in [self.state.target_path] + list(self.state.target_path.parents):
            if (parent / "foundry.toml").exists():
                project_root = parent
                break

        # Run forge test
        cmd = [
            "forge", "test",
            "--match-path", str(test_path),
            "--fuzz-runs", str(runs),
            "-vvv",  # Verbose enough to see counterexamples
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            output = f"Exit code: {result.returncode}\n\n"

            if result.stdout:
                # Truncate if too long
                stdout = result.stdout
                if len(stdout) > 15000:
                    stdout = stdout[:15000] + "\n\n... [truncated]"
                output += f"STDOUT:\n{stdout}\n\n"

            if result.stderr:
                stderr = result.stderr
                if len(stderr) > 5000:
                    stderr = stderr[:5000] + "\n\n... [truncated]"
                output += f"STDERR:\n{stderr}\n\n"

            # Parse results
            if result.returncode == 0:
                output += "ALL INVARIANTS HELD -- no violations found.\n"
            else:
                # Check for compilation errors vs invariant failures
                if "Compiler run failed" in (result.stderr or ""):
                    output += "COMPILATION FAILED -- fix the test and try again.\n"
                else:
                    output += "INVARIANT VIOLATION DETECTED -- analyze the counterexample above.\n"

            return output

        except subprocess.TimeoutExpired:
            return "Forge test timed out after 5 minutes. Try reducing fuzz_runs."
        except FileNotFoundError:
            return "Foundry (forge) not installed. Install from https://getfoundry.sh"
        except Exception as e:
            return f"Error running forge: {e}"

    def _report_finding(self, params: dict) -> str:
        """Report a finding from a broken invariant."""
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

        # Build description with invariant details
        full_description = description
        if params.get("invariant_violated"):
            full_description += f"\n\n**Invariant Violated:** `{params['invariant_violated']}`"
        if params.get("counterexample"):
            full_description += f"\n\n**Counterexample (from forge):**\n```\n{params['counterexample']}\n```"

        # Create PoC if test code provided
        poc = None
        if params.get("poc_code"):
            poc = PoC(
                finding_id=f"INVARIANT-{len(self.findings)+1:03d}",
                code=params["poc_code"],
                language="solidity",
                executed=True,
                success=True,
            )

        finding = Finding(
            id=f"INVARIANT-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity_str, Severity.HIGH),
            vulnerability_type=VulnerabilityType.INVARIANT_VIOLATION,
            description=full_description,
            contract=contract,
            function=params.get("function"),
            impact=params.get("impact", ""),
            recommendation=params.get("recommendation", ""),
            poc=poc,
            validated=True,  # Broken invariants from fuzzing are validated by definition
            found_by=AgentRole.FUZZER,
            confidence=params.get("confidence", 0.95),
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity_str}] {title}"
