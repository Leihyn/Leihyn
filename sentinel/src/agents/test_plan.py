"""
Test Plan Agent - Generates testing-diagram.md and test-setup.md for a protocol.

Produces two standalone markdown files:
1. testing-diagram.md - every function, actor, state transition, cross-contract dependency
2. test-setup.md - complete Foundry setUp() with contracts, oracles, accounts, approvals

Static analysis is free (no API calls). Two LLM calls (~$0.10 total with Sonnet)
infer semantic information that regex can't extract: user flows, state machines,
and deployment-ordered setUp() code.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from ..core.agent import AnalysisAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, ContractInfo, FunctionInfo

console = Console()


class TestPlanAgent(AnalysisAgent):
    """
    Generates a complete testing reference for a protocol.

    Outputs two files:
    - testing-diagram.md: contract map, call graph, access control, value flows,
      actors, state transitions
    - test-setup.md: Foundry setUp(), deployment order, constructor args,
      cheatcode reference
    """

    role = AgentRole.RECON
    name = "TestPlanAgent"
    description = "Generates testing diagram and test setup for a protocol"

    def __init__(
        self,
        state: AuditState,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)

    @property
    def system_prompt(self) -> str:
        return """You are a senior smart contract test engineer creating a comprehensive
testing reference for a Solidity protocol.

Your output should be:
- PRECISE: exact function signatures, correct types, real contract names
- COMPLETE: cover every contract, every external/public function
- PRACTICAL: a developer should be able to write tests directly from your output
- STRUCTURED: easy to navigate and reference

Think like you're onboarding a new engineer who needs to write 100% test coverage."""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> tuple[str, str]:
        """Generate testing-diagram.md and test-setup.md."""
        self.log("Generating test plan...", style="bold magenta")

        diagram_only = kwargs.get("diagram_only", False)
        setup_only = kwargs.get("setup_only", False)

        # --- Static analysis (free) ---
        self.log("Building static analysis sections...", style="cyan")

        function_tables = self._build_function_tables()
        state_var_tables = self._build_state_variable_tables()
        call_graph = self._build_call_graph_section()
        cross_contract_deps = self._build_cross_contract_deps()
        access_control = self._build_access_control_map()
        value_flows = self._build_value_flow_map()
        modifier_index = self._build_modifier_index()
        event_map = self._build_event_map()
        constructor_args = self._build_constructor_args_table()
        import_map = self._build_import_map()

        static_context = "\n\n".join([
            function_tables,
            state_var_tables,
            call_graph,
            cross_contract_deps,
            access_control,
            value_flows,
            modifier_index,
        ])

        # --- LLM calls (~$0.05 each) ---
        diagram_md = ""
        setup_md = ""

        if not setup_only:
            self.log("Inferring user flows and state transitions (LLM call 1/2)...", style="cyan")
            user_flows = self._infer_user_flows_and_state_transitions(static_context)

            diagram_md = self._assemble_testing_diagram(
                function_tables=function_tables,
                state_var_tables=state_var_tables,
                call_graph=call_graph,
                cross_contract_deps=cross_contract_deps,
                access_control=access_control,
                value_flows=value_flows,
                modifier_index=modifier_index,
                event_map=event_map,
                user_flows=user_flows,
            )

        if not diagram_only:
            self.log("Generating setUp() code (LLM call 2/2)...", style="cyan")
            setup_code = self._generate_setup_code(static_context, constructor_args)

            setup_md = self._assemble_test_setup(
                setup_code=setup_code,
                constructor_args=constructor_args,
                import_map=import_map,
            )

        return diagram_md, setup_md

    # =========================================================================
    # Static analysis methods (free, no API calls)
    # =========================================================================

    def _build_function_tables(self) -> str:
        """Build function tables per contract."""
        if not self.state.contracts:
            return "## Contract Map\n\nNo contracts found."

        lines = ["## Contract Map"]

        for contract in self.state.contracts:
            lines.append(f"\n### {contract.name}")
            lines.append(f"`{contract.path}`")

            if contract.inheritance:
                lines.append(f"Inherits: {', '.join(contract.inheritance)}")

            lines.append("")

            externals = [f for f in contract.functions
                         if f.visibility in ("external", "public")]

            if not externals:
                lines.append("No external/public functions.")
                continue

            lines.append("| Function | Vis | Mut | Params | Returns | Modifiers | State Reads | State Writes | External Calls |")
            lines.append("|----------|-----|-----|--------|---------|-----------|-------------|--------------|----------------|")

            for func in externals:
                params = ", ".join(
                    f"{p.get('type', '?')} {p.get('name', '?')}"
                    for p in func.parameters
                ) or "-"
                returns = ", ".join(
                    f"{r.get('type', '?')}"
                    for r in func.returns
                ) or "-"
                mods = ", ".join(func.modifiers) or "-"
                reads = ", ".join(func.state_reads[:3]) or "-"
                if len(func.state_reads) > 3:
                    reads += f" (+{len(func.state_reads) - 3})"
                writes = ", ".join(func.state_writes[:3]) or "-"
                if len(func.state_writes) > 3:
                    writes += f" (+{len(func.state_writes) - 3})"
                ext_calls = ", ".join(
                    f"{c.target}.{c.function}" for c in func.external_calls[:3]
                ) or "-"
                if len(func.external_calls) > 3:
                    ext_calls += f" (+{len(func.external_calls) - 3})"

                lines.append(
                    f"| `{func.name}` | {func.visibility} | {func.mutability} "
                    f"| {params} | {returns} | {mods} | {reads} | {writes} | {ext_calls} |"
                )

            lines.append("")

        return "\n".join(lines)

    def _build_state_variable_tables(self) -> str:
        """Build state variable tables per contract."""
        if not self.state.contracts:
            return "## State Variables\n\nNo contracts found."

        lines = ["## State Variables"]

        for contract in self.state.contracts:
            if not contract.state_variables:
                continue

            lines.append(f"\n### {contract.name}")
            lines.append("")
            lines.append("| Variable | Type | Visibility | Constant | Immutable |")
            lines.append("|----------|------|------------|----------|-----------|")

            for sv in contract.state_variables:
                lines.append(
                    f"| `{sv.name}` | `{sv.var_type}` | {sv.visibility} "
                    f"| {'yes' if sv.is_constant else 'no'} "
                    f"| {'yes' if sv.is_immutable else 'no'} |"
                )

            lines.append("")

        return "\n".join(lines)

    def _build_call_graph_section(self) -> str:
        """Build call graph from code_reader."""
        from ..tools.code_reader import get_call_graph

        if not self.state.contracts:
            return "## Call Graph\n\nNo contracts found."

        graph = get_call_graph(self.state.contracts)

        lines = ["## Call Graph", ""]

        if not graph:
            lines.append("No function calls detected.")
            return "\n".join(lines)

        # Group by contract
        by_contract: dict[str, list[tuple[str, list[str]]]] = {}
        for caller, callees in graph.items():
            if not callees:
                continue
            contract_name = caller.split(".")[0]
            by_contract.setdefault(contract_name, []).append((caller, callees))

        for contract_name, entries in by_contract.items():
            lines.append(f"### {contract_name}")
            lines.append("```")
            for caller, callees in entries:
                func_name = caller.split(".", 1)[1] if "." in caller else caller
                for callee in callees:
                    lines.append(f"{func_name} -> {callee}")
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def _build_cross_contract_deps(self) -> str:
        """Build cross-contract dependency section from dependency graph."""
        lines = ["## Cross-Contract Dependencies", ""]

        graph = self.state.dependency_graph
        if not graph or not graph.edges:
            lines.append("No cross-contract dependencies detected.")
            return "\n".join(lines)

        # Mermaid diagram
        lines.append("```mermaid")
        lines.append("graph LR")

        seen_edges = set()
        for edge in graph.edges:
            key = f"{edge.source_contract}-->{edge.target_contract}"
            if key not in seen_edges:
                seen_edges.add(key)
                lines.append(f"    {edge.source_contract} --> {edge.target_contract}")

        lines.append("```")
        lines.append("")

        # Detailed edges
        lines.append("### Detailed Calls")
        lines.append("")
        lines.append("| Source | Function | Target | Function |")
        lines.append("|--------|----------|--------|----------|")

        for edge in graph.edges:
            lines.append(
                f"| {edge.source_contract} | {edge.source_function} "
                f"| {edge.target_contract} | {edge.target_function} |"
            )

        lines.append("")

        # Critical flows
        if graph.critical_flows:
            lines.append("### Critical Data Flows")
            lines.append("")
            for flow in graph.critical_flows:
                lines.append(
                    f"- **{flow.flow_type}** [{flow.risk_level.upper()}]: "
                    f"{flow.description}"
                )
            lines.append("")

        return "\n".join(lines)

    def _build_access_control_map(self) -> str:
        """Build access control map classifying functions by permission level."""
        lines = [
            "## Access Control Map",
            "",
        ]

        admin_functions = []
        user_functions = []
        permissionless = []

        for contract in self.state.contracts:
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue
                if func.mutability in ("pure", "view"):
                    continue

                mods_lower = [m.lower() for m in func.modifiers]
                has_access = any(
                    kw in mod
                    for mod in mods_lower
                    for kw in ["onlyowner", "onlyadmin", "onlyrole", "auth",
                               "onlygovernance", "onlyguardian", "onlykeeper"]
                )

                label = f"`{contract.name}.{func.name}()`"
                if func.modifiers:
                    label += f" [{', '.join(func.modifiers)}]"

                if has_access:
                    admin_functions.append(label)
                else:
                    # Check inline access control
                    func_source = contract.source[
                        func.source_lines[0]:func.source_lines[1]
                    ] if func.source_lines != (0, 0) else ""

                    if "msg.sender" in func_source and ("require" in func_source or "revert" in func_source):
                        user_functions.append(f"{label} (inline auth)")
                    else:
                        permissionless.append(label)

        if admin_functions:
            lines.append("### Admin / Privileged")
            for f in admin_functions:
                lines.append(f"- {f}")
            lines.append("")

        if user_functions:
            lines.append("### User (with auth check)")
            for f in user_functions:
                lines.append(f"- {f}")
            lines.append("")

        if permissionless:
            lines.append("### Permissionless")
            for f in permissionless:
                lines.append(f"- {f}")
            lines.append("")

        if not admin_functions and not user_functions and not permissionless:
            lines.append("No state-changing external/public functions found.")
            lines.append("")

        return "\n".join(lines)

    def _build_value_flow_map(self) -> str:
        """Build value flow map showing token/ETH entry, exit, transform points."""
        lines = [
            "## Value Flows",
            "",
        ]

        entry_points = []
        exit_points = []
        transforms = []

        for contract in self.state.contracts:
            source = contract.source

            # Entry: tokens coming IN
            for match in re.finditer(r'transferFrom\s*\(', source):
                line = source[:match.start()].count("\n") + 1
                entry_points.append(f"`{contract.name}` L{line}: `transferFrom` (tokens in)")

            if "msg.value" in source:
                entry_points.append(f"`{contract.name}`: accepts ETH via `msg.value`")

            if re.search(r'receive\s*\(\s*\)\s*external\s+payable', source):
                entry_points.append(f"`{contract.name}`: `receive()` fallback")

            if re.search(r'fallback\s*\(\s*\)\s*external\s+payable', source):
                entry_points.append(f"`{contract.name}`: `fallback()` payable")

            # Exit: tokens going OUT
            for pattern, desc in [
                (r'\.transfer\s*\(', "`transfer` (ETH out)"),
                (r'\.safeTransfer\s*\(', "`safeTransfer` (tokens out)"),
                (r'\.safeTransferFrom\s*\(', "`safeTransferFrom` (tokens out)"),
                (r'\.call\{value:', "low-level ETH send"),
            ]:
                for match in re.finditer(pattern, source):
                    line = source[:match.start()].count("\n") + 1
                    exit_points.append(f"`{contract.name}` L{line}: {desc}")

            # Transforms: minting, burning, swapping
            for pattern, desc in [
                (r'_mint\s*\(', "minting"),
                (r'_burn\s*\(', "burning"),
                (r'swap\w*\s*\(', "swap"),
                (r'addLiquidity\w*\s*\(', "add liquidity"),
                (r'removeLiquidity\w*\s*\(', "remove liquidity"),
            ]:
                if re.search(pattern, source):
                    transforms.append(f"`{contract.name}`: {desc}")

        if entry_points:
            lines.append("### Entry Points (value in)")
            for p in entry_points:
                lines.append(f"- {p}")
            lines.append("")

        if exit_points:
            lines.append("### Exit Points (value out)")
            for p in exit_points:
                lines.append(f"- {p}")
            lines.append("")

        if transforms:
            lines.append("### Transformations")
            for t in transforms:
                lines.append(f"- {t}")
            lines.append("")

        if not entry_points and not exit_points and not transforms:
            lines.append("No value flow patterns detected.")
            lines.append("")

        return "\n".join(lines)

    def _build_modifier_index(self) -> str:
        """Build modifier -> functions mapping."""
        lines = ["## Modifier Index", ""]

        modifier_map: dict[str, list[str]] = {}

        for contract in self.state.contracts:
            for func in contract.functions:
                for mod in func.modifiers:
                    modifier_map.setdefault(mod, []).append(
                        f"`{contract.name}.{func.name}()`"
                    )

        if not modifier_map:
            lines.append("No modifiers found.")
            return "\n".join(lines)

        for mod, funcs in sorted(modifier_map.items()):
            lines.append(f"### `{mod}`")
            for f in funcs:
                lines.append(f"- {f}")
            lines.append("")

        return "\n".join(lines)

    def _build_event_map(self) -> str:
        """Build event map per contract."""
        lines = ["## Event Map", ""]

        has_events = False
        for contract in self.state.contracts:
            if not contract.events:
                continue
            has_events = True
            lines.append(f"### {contract.name}")
            for event in contract.events:
                lines.append(f"- `{event}`")
            lines.append("")

        if not has_events:
            lines.append("No events found.")
            lines.append("")

        return "\n".join(lines)

    def _build_constructor_args_table(self) -> str:
        """Build constructor args reference from ContractInfo."""
        lines = ["## Constructor Args Reference", ""]

        has_constructors = False
        for contract in self.state.contracts:
            constructors = [f for f in contract.functions if f.name == "constructor"]
            if not constructors:
                continue

            has_constructors = True
            ctor = constructors[0]
            lines.append(f"### {contract.name}")

            if not ctor.parameters:
                lines.append("No constructor parameters.")
            else:
                lines.append("| Parameter | Type |")
                lines.append("|-----------|------|")
                for p in ctor.parameters:
                    lines.append(f"| `{p.get('name', '?')}` | `{p.get('type', '?')}` |")

            lines.append("")

        if not has_constructors:
            lines.append("No constructors with parameters found.")
            lines.append("")

        return "\n".join(lines)

    def _build_import_map(self) -> str:
        """Build import map per contract."""
        lines = ["## Import Map", ""]

        for contract in self.state.contracts:
            lines.append(f"### {contract.name}")
            lines.append(f"**File:** `{contract.path}`")

            if contract.imports:
                for imp in contract.imports:
                    lines.append(f"- `{imp}`")
            else:
                lines.append("- No imports")

            lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # LLM calls (~$0.05 each)
    # =========================================================================

    def _infer_user_flows_and_state_transitions(self, static_context: str) -> str:
        """Use LLM to infer actors, user journeys, and state machines.

        This is semantic -- regex can't determine that a series of functions
        represents a deposit->borrow->repay flow or that an entity transitions
        through ACTIVE->PAUSED->ACTIVE states.
        """
        prompt = f"""Analyze this protocol's static analysis and infer:

1. **Actors**: Who interacts with this protocol? (e.g., depositor, borrower, liquidator, admin, keeper)
   For each actor, list which functions they would call and in what order.

2. **User Flows**: What are the main user journeys? (e.g., deposit -> borrow -> repay -> withdraw)
   Write each flow as a numbered sequence of function calls.

3. **State Transitions**: What state machines exist? (e.g., Loan: ACTIVE -> LIQUIDATABLE -> LIQUIDATED)
   For each state machine, draw it as a text diagram showing transitions and what triggers them.

Be specific to THIS protocol. Use actual contract and function names from the analysis below.

---

{static_context}"""

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
                max_tokens=4096,
            )
            return response.content
        except Exception as e:
            self.log(f"LLM call failed for user flows: {e}", style="red")
            return (
                "**[LLM call failed -- fill in manually]**\n\n"
                "Identify the actors, user flows (function call sequences), "
                "and state machines for this protocol."
            )

    def _generate_setup_code(self, static_context: str, constructor_args: str) -> str:
        """Use LLM to generate complete Foundry setUp() code.

        Given constructors, state vars, and architecture, generates the deployment
        order, oracle configs, token funding, and approvals.
        """
        prompt = f"""Generate a complete Foundry test setUp() function for this protocol.

Requirements:
- Use `forge-std/Test.sol` as the base
- Deploy ALL contracts in the correct dependency order
- Configure mock oracles with realistic prices
- Create labeled test accounts (alice, bob, admin, attacker) using `makeAddr()`
- Fund accounts with tokens using `deal()`
- Set up all necessary `approve()` calls
- Add `vm.label()` for every deployed contract
- Include inline comments explaining WHY each step is needed
- Use `vm.startPrank(admin)` / `vm.stopPrank()` where needed for deployment

Return ONLY:
1. The complete setUp() function inside a test contract
2. A numbered deployment order list explaining the sequence

---

## Static Analysis

{static_context}

---

{constructor_args}"""

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
                max_tokens=8192,
            )
            return response.content
        except Exception as e:
            self.log(f"LLM call failed for setUp(): {e}", style="red")
            return (
                "**[LLM call failed -- fill in manually]**\n\n"
                "Write a Foundry setUp() that deploys all contracts in dependency order, "
                "configures oracles, creates test accounts, and sets up approvals."
            )

    # =========================================================================
    # Assembly
    # =========================================================================

    def _assemble_testing_diagram(
        self,
        function_tables: str,
        state_var_tables: str,
        call_graph: str,
        cross_contract_deps: str,
        access_control: str,
        value_flows: str,
        modifier_index: str,
        event_map: str,
        user_flows: str,
    ) -> str:
        """Assemble all sections into testing-diagram.md."""
        name = self.state.target_name

        overview_lines = ["## Protocol Overview", ""]
        if self.state.architecture:
            arch = self.state.architecture
            overview_lines.append(f"**Target:** `{self.state.target_path}`")
            overview_lines.append(f"**Contracts:** {len(self.state.contracts)}")
            if arch.is_defi:
                overview_lines.append(f"**Type:** DeFi ({', '.join(arch.defi_type)})")
            if arch.is_upgradeable:
                overview_lines.append(f"**Upgradeable:** Yes ({arch.proxy_type})")
            if arch.uses_oracles:
                overview_lines.append(f"**Oracles:** {', '.join(arch.oracle_type)}")
            if arch.external_protocols:
                overview_lines.append(f"**Integrations:** {', '.join(arch.external_protocols)}")
            if arch.access_control_type:
                overview_lines.append(f"**Access Control:** {arch.access_control_type}")
        else:
            overview_lines.append(f"**Target:** `{self.state.target_path}`")
            overview_lines.append(f"**Contracts:** {len(self.state.contracts)}")

        overview_lines.append("")
        overview = "\n".join(overview_lines)

        sections = [
            f"# Testing Diagram: {name}",
            "",
            f"Generated by Sentinel on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            overview,
            function_tables,
            state_var_tables,
            cross_contract_deps,
            call_graph,
            access_control,
            value_flows,
            "## Actors & User Flows",
            "",
            user_flows,
            "",
            event_map,
            modifier_index,
            "---",
            "",
            "*Generated by Sentinel. Review and correct before using as a test reference.*",
        ]

        return "\n".join(sections)

    def _assemble_test_setup(
        self,
        setup_code: str,
        constructor_args: str,
        import_map: str,
    ) -> str:
        """Assemble all sections into test-setup.md."""
        name = self.state.target_name

        cheatcode_ref = self._cheatcode_reference()

        sections = [
            f"# Test Setup: {name}",
            "",
            f"Generated by Sentinel on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "---",
            "",
            "## Prerequisites",
            "",
            "```bash",
            "# Foundry",
            "curl -L https://foundry.paradigm.xyz | bash",
            "foundryup",
            "",
            "# Verify",
            "forge --version",
            "forge build",
            "```",
            "",
            import_map,
            "## setUp() Code",
            "",
            setup_code,
            "",
            constructor_args,
            cheatcode_ref,
            "---",
            "",
            "*Generated by Sentinel. Review setUp() for correctness before running tests.*",
        ]

        return "\n".join(sections)

    def _cheatcode_reference(self) -> str:
        """Static cheatcode reference for Foundry tests."""
        return """## Cheatcode Reference

Common Foundry cheatcodes for test setup and assertions:

| Cheatcode | Usage | Purpose |
|-----------|-------|---------|
| `vm.prank(addr)` | `vm.prank(alice)` | Next call comes from `addr` |
| `vm.startPrank(addr)` | `vm.startPrank(admin)` | All calls from `addr` until `stopPrank()` |
| `vm.stopPrank()` | `vm.stopPrank()` | Stop pranking |
| `vm.deal(addr, amt)` | `vm.deal(alice, 100 ether)` | Set ETH balance |
| `deal(token, addr, amt)` | `deal(address(usdc), alice, 1e6)` | Set ERC20 balance |
| `vm.warp(ts)` | `vm.warp(block.timestamp + 1 days)` | Set `block.timestamp` |
| `vm.roll(num)` | `vm.roll(block.number + 100)` | Set `block.number` |
| `vm.expectRevert()` | `vm.expectRevert("Unauthorized")` | Next call must revert |
| `vm.expectEmit()` | `vm.expectEmit(true, true, false, true)` | Check event emission |
| `vm.label(addr, name)` | `vm.label(address(vault), "Vault")` | Label address in traces |
| `makeAddr(name)` | `address alice = makeAddr("alice")` | Create labeled address |
| `vm.snapshot()` | `uint256 id = vm.snapshot()` | Snapshot state |
| `vm.revertTo(id)` | `vm.revertTo(id)` | Restore snapshot |
| `vm.mockCall(...)` | `vm.mockCall(oracle, abi.encodeWith...` | Mock external call |
| `vm.createFork(url)` | `vm.createFork("mainnet")` | Fork mainnet state |

"""
