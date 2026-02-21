"""
Sequence Explorer Hunter - Finds multi-step attack sequences.

Most critical/high findings in audit contests are NOT single-function bugs.
They're multi-step sequences: deposit -> borrow -> manipulate oracle -> liquidate.

This hunter:
1. Identifies all state-changing functions in the protocol
2. Generates multi-step attack sequences
3. Tests same-block/same-tx scenarios (flash loan attacks)
4. Generates Foundry tests that execute the sequences
5. Reports profitable sequences as findings

The key insight: ORDER MATTERS. The same functions called in different orders
produce different outcomes. A deposit() followed by withdraw() is normal.
A flashLoan() -> deposit() -> borrow() -> withdraw() -> repay() might be
an exploit.

Supports: Solidity (Foundry required)
"""

import subprocess
import re
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, PoC, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite smart contract exploiter who thinks in ATTACK SEQUENCES.

You don't look for single-function bugs. You find multi-step exploits where
the ORDER of operations creates the vulnerability. This is how the biggest
DeFi hacks work.

## Attack Sequence Patterns

### 1. Flash Loan Attacks
```
flashLoan(huge_amount)
  -> deposit(huge_amount) as collateral
  -> borrow(target_amount) against inflated collateral
  -> withdraw(huge_amount) original deposit
  -> repay(huge_amount) flash loan
  -> keep borrowed target_amount as profit
```

### 2. Oracle Manipulation
```
swap(huge_amount) to move spot price
  -> call protocol function that reads manipulated price
  -> swap back to restore price
  -> profit from mispriced action
```

### 3. Reentrancy Sequences
```
withdraw(amount)
  -> during callback: deposit(small_amount)
  -> during callback: withdraw(amount + small_amount)
  -> repeat until drained
```

### 4. Governance Attacks
```
flashLoan(governance_tokens)
  -> delegate(self)
  -> propose(malicious_action)
  -> vote(proposal)
  -> return flash loan
```

### 5. First-Depositor / Donation
```
deposit(1 wei) to become first depositor
  -> donate(huge_amount) directly to contract
  -> victim deposits normal amount
  -> withdraw() getting victim's funds via rounding
```

### 6. Liquidation Manipulation
```
deposit(collateral)
  -> borrow(max_amount)
  -> manipulate oracle to make position unhealthy
  -> liquidate own position from another account at profit
  -> restore oracle
```

### 7. Cross-Function State Corruption
```
initializePool(params)
  -> addLiquidity(normal)
  -> removeLiquidity(all) -- leaves pool in bad state
  -> addLiquidity(1 wei) -- gets disproportionate shares
```

## Foundry Test Structure for Sequences

```solidity
function test_attackSequence() public {
    // Setup: deploy protocol, fund actors
    vm.startPrank(attacker);

    // Step 1: Flash loan
    uint256 borrowed = 1000 ether;

    // Step 2: Deposit as collateral
    token.approve(address(protocol), borrowed);
    protocol.deposit(borrowed);

    // Step 3: Borrow against inflated collateral
    protocol.borrow(target, maxBorrow);

    // Step 4: Withdraw original deposit
    protocol.withdraw(borrowed);

    // Step 5: Repay flash loan
    // ...

    // Assert: attacker has profit
    assertGt(target.balanceOf(attacker), 0, "Attack should be profitable");
}
```

## Rules
- Focus on sequences that PROFIT the attacker
- Consider same-block execution (no time passing between steps)
- Consider multi-block sequences (with time manipulation via vm.warp)
- Always quantify: how much can the attacker extract?
- Consider gas costs vs profit
- Use real contract functions, not imaginary ones
- Sequences of 2-7 steps are most realistic"""


class SequenceExplorerHunter(AnalysisAgent):
    """
    Explores multi-step attack sequences to find exploits.

    Generates Foundry tests that execute specific operation sequences
    against the target protocol, looking for profitable outcomes.
    """

    role = "hunter"
    name = "sequence_explorer"
    description = "Finds multi-step attack sequences by fuzzing operation ORDER"

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

    def _build_tools(self) -> list[Tool]:
        """Build tools for sequence exploration."""
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
                name="map_attack_surface",
                description="Map all state-changing functions, their effects, and entry points. Returns a structured attack surface.",
                input_schema={"type": "object", "properties": {}},
                handler=self._map_attack_surface,
            ),
            Tool(
                name="identify_value_flows",
                description="Identify how value (tokens, ETH) flows through the protocol. Returns deposit/withdraw/swap/transfer points.",
                input_schema={"type": "object", "properties": {}},
                handler=self._identify_value_flows,
            ),
            Tool(
                name="generate_sequence_test",
                description="Generate a Foundry test for a specific attack sequence",
                input_schema={
                    "type": "object",
                    "properties": {
                        "test_name": {
                            "type": "string",
                            "description": "Name for the test (e.g., 'FlashLoanArbitrage')",
                        },
                        "sequence_description": {
                            "type": "string",
                            "description": "Human-readable description of the attack sequence",
                        },
                        "steps": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Ordered list of attack steps",
                        },
                        "full_test_source": {
                            "type": "string",
                            "description": "Complete Foundry test file source code",
                        },
                        "expected_profit": {
                            "type": "string",
                            "description": "Expected profit from the attack (e.g., '100 ETH')",
                        },
                    },
                    "required": ["test_name", "sequence_description", "steps", "full_test_source"],
                },
                handler=self._generate_sequence_test,
            ),
            Tool(
                name="run_sequence_test",
                description="Execute a generated sequence test with forge",
                input_schema={
                    "type": "object",
                    "properties": {
                        "test_file": {
                            "type": "string",
                            "description": "Path to the test file to run",
                        },
                    },
                    "required": ["test_file"],
                },
                handler=self._run_sequence_test,
            ),
            Tool(
                name="report_finding",
                description="Report a finding from a successful attack sequence",
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
                        "attack_sequence": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Ordered list of attack steps",
                        },
                        "profit": {
                            "type": "string",
                            "description": "Estimated profit from the attack",
                        },
                        "poc_code": {
                            "type": "string",
                            "description": "The Foundry test source code that demonstrates the attack",
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
        """Run sequence exploration analysis."""
        if self.language != Language.SOLIDITY:
            self.log("Sequence exploration currently only supports Solidity/Foundry")
            return []

        from ...core.llm import get_llm_client
        llm = get_llm_client()

        contracts_info = self._format_contracts_info()
        cross_contract_info = self._format_cross_contract_flows()

        initial_prompt = f"""Analyze this Solidity codebase for multi-step attack sequences.

## Target
{self.state.target_path}

## Contracts
{contracts_info}

## Cross-Contract Flows
{cross_contract_info}

## Your Task

1. Use `map_attack_surface` to identify all state-changing functions
2. Use `identify_value_flows` to understand how tokens/ETH move through the protocol
3. Read the most important contracts to understand their logic
4. Design 3-5 multi-step attack sequences that could extract value:
   - Flash loan attacks (borrow -> manipulate -> profit -> repay)
   - First-depositor / donation attacks
   - Oracle manipulation sequences
   - Cross-function state corruption
   - Liquidation manipulation
   - Reentrancy-based sequences
5. Generate Foundry tests for each sequence using `generate_sequence_test`
6. Run the tests with `run_sequence_test`
7. Report successful attacks with `report_finding`

## Key Questions to Answer
- Can an attacker profit from a flash loan within one transaction?
- Can calling functions in a specific order corrupt protocol state?
- Can the first user/depositor extract value from subsequent users?
- Can oracle prices be manipulated to create arbitrage?
- Can withdrawal/liquidation be gamed with specific sequences?

## Important
- Each sequence should be 2-7 steps
- Consider same-block execution (flash loan context)
- Consider multi-block with vm.warp() for time-dependent attacks
- Quantify the profit in each attack
- Use real contract functions from the target codebase
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            max_iterations=15,
        )

        if self.verbose:
            print(f"  SequenceExplorer completed: {len(self.findings)} findings")

        return self.findings

    def _format_contracts_info(self) -> str:
        """Format contract info for prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:15]:
            lines.append(f"- **{contract.name}** ({contract.path})")
            if contract.functions:
                externals = [
                    f for f in contract.functions
                    if f.visibility in ("external", "public") and f.mutability not in ("pure", "view")
                ]
                if externals:
                    lines.append(f"  State-changing externals: {len(externals)}")
                    for func in externals[:8]:
                        writes = f" [writes: {', '.join(func.state_writes[:3])}]" if func.state_writes else ""
                        lines.append(f"    - {func.name}(){writes}")
        return "\n".join(lines)

    def _format_cross_contract_flows(self) -> str:
        """Format cross-contract dependency info."""
        if not self.state.dependency_graph:
            return "No cross-contract analysis available."

        graph = self.state.dependency_graph
        lines = [f"Contracts: {len(graph.nodes)}, Edges: {len(graph.edges)}"]

        if graph.critical_flows:
            lines.append("\nCritical Flows:")
            for flow in graph.critical_flows:
                lines.append(f"  [{flow.risk_level.upper()}] {flow.flow_type}: {flow.description}")
                for call in flow.calls[:3]:
                    lines.append(f"    {call.source_contract}.{call.source_function} -> {call.target_contract}.{call.target_function}")

        return "\n".join(lines)

    # === Tool Handlers ===

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            content = file_path.read_text()
            if len(content) > 30000:
                return content[:30000] + "\n\n... [truncated]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    async def _map_attack_surface(self) -> str:
        """Map all state-changing functions and their effects."""
        if not self.state.contracts:
            return "No contracts found."

        output = "# Attack Surface Map\n\n"

        for contract in self.state.contracts:
            state_changing = [
                f for f in contract.functions
                if f.visibility in ("external", "public") and f.mutability not in ("pure", "view")
            ]

            if not state_changing:
                continue

            output += f"## {contract.name}\n"

            # Categorize functions
            categories = {
                "deposit/stake": [],
                "withdraw/unstake": [],
                "swap/exchange": [],
                "borrow/repay": [],
                "liquidate": [],
                "admin/owner": [],
                "approve/transfer": [],
                "other": [],
            }

            for func in state_changing:
                name_lower = func.name.lower()
                categorized = False

                keyword_map = {
                    "deposit/stake": ["deposit", "stake", "supply", "mint", "addliquidity", "add_liquidity"],
                    "withdraw/unstake": ["withdraw", "unstake", "redeem", "burn", "removeliquidity", "remove_liquidity"],
                    "swap/exchange": ["swap", "exchange", "trade", "buy", "sell"],
                    "borrow/repay": ["borrow", "repay", "loan", "flash"],
                    "liquidate": ["liquidat", "seize"],
                    "admin/owner": ["set", "change", "update", "pause", "unpause", "initialize", "init"],
                    "approve/transfer": ["approve", "transfer", "permit"],
                }

                for category, keywords in keyword_map.items():
                    if any(kw in name_lower for kw in keywords):
                        categories[category].append(func)
                        categorized = True
                        break

                if not categorized:
                    categories["other"].append(func)

            for category, funcs in categories.items():
                if funcs:
                    output += f"\n### {category}\n"
                    for func in funcs:
                        params = ", ".join(
                            f"{p.get('type', '?')} {p.get('name', '?')}"
                            for p in func.parameters
                        )
                        output += f"  - `{func.name}({params})`\n"
                        if func.state_writes:
                            output += f"    Writes: {', '.join(func.state_writes[:5])}\n"
                        if func.external_calls:
                            calls = [f"{c.target}.{c.function}" for c in func.external_calls[:3]]
                            output += f"    External calls: {', '.join(calls)}\n"

            output += "\n"

        return output

    async def _identify_value_flows(self) -> str:
        """Identify how value flows through the protocol."""
        if not self.state.contracts:
            return "No contracts found."

        output = "# Value Flow Analysis\n\n"

        # Scan for token transfer patterns
        value_patterns = {
            "token_in": [
                r"transferFrom\s*\(",
                r"safeTransferFrom\s*\(",
                r"\.deposit\s*\(",
            ],
            "token_out": [
                r"\.transfer\s*\(",
                r"\.safeTransfer\s*\(",
                r"\.withdraw\s*\(",
            ],
            "eth_in": [
                r"msg\.value",
                r"receive\s*\(\s*\)",
            ],
            "eth_out": [
                r"\.call\{value:",
                r"\.transfer\s*\(",
                r"payable\s*\([^)]*\)\.transfer",
            ],
            "flash_loan": [
                r"flashLoan",
                r"flash\s*\(",
                r"IFlash",
            ],
        }

        for contract in self.state.contracts:
            found_flows = {}
            for flow_type, patterns in value_patterns.items():
                matches = []
                for pattern in patterns:
                    for match in re.finditer(pattern, contract.source):
                        line_num = contract.source[:match.start()].count("\n") + 1
                        context_start = max(0, match.start() - 50)
                        context_end = min(len(contract.source), match.end() + 50)
                        context = contract.source[context_start:context_end].strip()
                        matches.append({"line": line_num, "context": context[:100]})

                if matches:
                    found_flows[flow_type] = matches

            if found_flows:
                output += f"## {contract.name}\n"
                for flow_type, matches in found_flows.items():
                    output += f"\n### {flow_type}\n"
                    for m in matches[:5]:
                        output += f"  Line {m['line']}: `{m['context']}`\n"
                output += "\n"

        if output == "# Value Flow Analysis\n\n":
            output += "No value flows detected.\n"

        return output

    def _generate_sequence_test(self, params: dict) -> str:
        """Generate a Foundry test for an attack sequence."""
        test_name = params["test_name"]
        source = params["full_test_source"]

        output_dir = self.output_dir or (self.state.target_path / "test" / "sequences")
        output_dir = Path(output_dir)

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return f"Error creating output directory: {e}"

        test_file = output_dir / f"{test_name}.sequence.t.sol"

        try:
            test_file.write_text(source)

            steps = params.get("steps", [])
            step_list = "\n".join(f"  {i+1}. {step}" for i, step in enumerate(steps))
            profit = params.get("expected_profit", "unknown")

            return f"""Test file written to: {test_file}

Sequence: {params['sequence_description']}
Expected profit: {profit}

Steps:
{step_list}
"""
        except OSError as e:
            return f"Error writing test file: {e}"

    async def _run_sequence_test(self, test_file: str) -> str:
        """Execute a sequence test with forge."""
        test_path = Path(test_file)
        if not test_path.is_absolute():
            test_path = self.state.target_path / test_file

        if not test_path.exists():
            return f"Test file not found: {test_path}"

        # Find project root
        project_root = self.state.target_path
        for parent in [self.state.target_path] + list(self.state.target_path.parents):
            if (parent / "foundry.toml").exists():
                project_root = parent
                break

        cmd = [
            "forge", "test",
            "--match-path", str(test_path),
            "-vvv",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=180,
            )

            output = f"Exit code: {result.returncode}\n\n"

            if result.stdout:
                stdout = result.stdout
                if len(stdout) > 15000:
                    stdout = stdout[:15000] + "\n\n... [truncated]"
                output += f"STDOUT:\n{stdout}\n\n"

            if result.stderr:
                stderr = result.stderr
                if len(stderr) > 5000:
                    stderr = stderr[:5000] + "\n\n... [truncated]"
                output += f"STDERR:\n{stderr}\n\n"

            if result.returncode == 0:
                output += "ALL TESTS PASSED -- attack sequence was profitable.\n"
            elif "Compiler run failed" in (result.stderr or ""):
                output += "COMPILATION FAILED -- fix the test and try again.\n"
            else:
                output += "TESTS FAILED -- attack sequence may not be profitable, or assertions need adjustment.\n"

            return output

        except subprocess.TimeoutExpired:
            return "Test timed out after 3 minutes."
        except FileNotFoundError:
            return "Foundry (forge) not installed."
        except Exception as e:
            return f"Error running forge: {e}"

    def _report_finding(self, params: dict) -> str:
        """Report a finding from a successful attack sequence."""
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

        # Build description with sequence details
        full_description = description
        if params.get("attack_sequence"):
            steps = "\n".join(f"{i+1}. {step}" for i, step in enumerate(params["attack_sequence"]))
            full_description += f"\n\n**Attack Sequence:**\n{steps}"
        if params.get("profit"):
            full_description += f"\n\n**Estimated Profit:** {params['profit']}"

        poc = None
        if params.get("poc_code"):
            poc = PoC(
                finding_id=f"SEQ-{len(self.findings)+1:03d}",
                code=params["poc_code"],
                language="solidity",
                executed=True,
                success=True,
            )

        finding = Finding(
            id=f"SEQ-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity_str, Severity.HIGH),
            vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
            description=full_description,
            contract=contract,
            function=params.get("function"),
            impact=params.get("impact", ""),
            recommendation=params.get("recommendation", ""),
            poc=poc,
            validated=True,
            found_by=AgentRole.ATTACKER,
            confidence=params.get("confidence", 0.9),
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity_str}] {title}"
