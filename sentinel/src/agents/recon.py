"""
Reconnaissance Agent - Maps codebase, identifies architecture, entry points, and trust boundaries.
"""

from pathlib import Path
from typing import Any

from ..core.agent import AnalysisAgent
from ..core.llm import Tool
from ..core.types import (
    AgentRole,
    ArchitectureAnalysis,
    AuditState,
    ContractInfo,
)
from ..tools.code_reader import (
    extract_contract_info,
    find_solidity_files,
    get_call_graph,
    read_solidity_file,
    summarize_contract,
)


class ReconAgent(AnalysisAgent):
    """
    Reconnaissance agent that performs initial codebase analysis.

    Responsibilities:
    - Find and parse all Solidity files
    - Identify architecture patterns (proxy, upgradeable, etc.)
    - Map external dependencies and protocols
    - Identify entry points and trust boundaries
    - Create a high-level overview for other agents
    """

    role = AgentRole.RECON
    name = "Recon"
    description = "Performs initial codebase reconnaissance and architecture analysis"

    @property
    def system_prompt(self) -> str:
        return """You are a smart contract security reconnaissance agent. Your job is to analyze a codebase and create a comprehensive overview that will guide the security audit.

## Your Responsibilities

1. **Architecture Analysis**
   - Identify if the protocol uses proxy patterns (transparent, UUPS, beacon)
   - Detect upgrade mechanisms
   - Identify access control patterns (Ownable, AccessControl, custom)
   - Recognize DeFi patterns (AMM, lending, vault, staking, etc.)

2. **Dependency Mapping**
   - Identify external protocol integrations (Aave, Uniswap, Chainlink, etc.)
   - Map oracle dependencies
   - List imported libraries (OpenZeppelin, Solmate, etc.)

3. **Trust Boundary Analysis**
   - Identify admin/privileged functions
   - Map user-callable entry points
   - Identify trust assumptions

4. **Attack Surface Mapping**
   - List functions that handle user funds
   - Identify functions with external calls
   - Note functions that modify critical state

## Output Format

Provide a structured analysis that includes:
- Overall architecture summary
- Key contracts and their roles
- Critical functions to focus on
- Initial security concerns
- Recommended focus areas for deep analysis

Be thorough but concise. Your analysis guides the entire audit."""

    def get_tools(self) -> list[Tool]:
        """Tools available to the Recon agent."""
        return [
            Tool(
                name="read_file",
                description="Read a Solidity source file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file"}
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="list_contracts",
                description="List all contracts found in the target",
                input_schema={"type": "object", "properties": {}},
                handler=self._list_contracts,
            ),
            Tool(
                name="get_contract_summary",
                description="Get a summary of a specific contract",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {"type": "string", "description": "Name of the contract"}
                    },
                    "required": ["contract_name"],
                },
                handler=self._get_contract_summary,
            ),
            Tool(
                name="get_call_graph",
                description="Get the function call graph showing dependencies",
                input_schema={"type": "object", "properties": {}},
                handler=self._get_call_graph,
            ),
            Tool(
                name="search_pattern",
                description="Search for a pattern in the codebase",
                input_schema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Pattern to search for"}
                    },
                    "required": ["pattern"],
                },
                handler=self._search_pattern,
            ),
            Tool(
                name="submit_analysis",
                description="Submit the final architecture analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "is_upgradeable": {"type": "boolean"},
                        "proxy_type": {"type": "string"},
                        "uses_access_control": {"type": "boolean"},
                        "access_control_type": {"type": "string"},
                        "is_defi": {"type": "boolean"},
                        "defi_type": {"type": "array", "items": {"type": "string"}},
                        "uses_oracles": {"type": "boolean"},
                        "oracle_type": {"type": "array", "items": {"type": "string"}},
                        "external_protocols": {"type": "array", "items": {"type": "string"}},
                        "entry_points": {"type": "array", "items": {"type": "string"}},
                        "admin_functions": {"type": "array", "items": {"type": "string"}},
                        "notes": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["is_defi", "uses_access_control"],
                },
                handler=self._submit_analysis,
            ),
        ]

    def _read_file(self, params: dict) -> str:
        """Read a Solidity file."""
        path = Path(params["path"])
        if not path.is_absolute():
            path = self.state.target_path / path

        if not path.exists():
            return f"File not found: {path}"

        return read_solidity_file(path)

    def _list_contracts(self, params: dict) -> str:
        """List all parsed contracts."""
        if not self.state.contracts:
            return "No contracts parsed yet. Run parse_codebase first."

        lines = ["# Contracts Found\n"]
        for contract in self.state.contracts:
            lines.append(f"## {contract.name}")
            lines.append(f"   Path: {contract.path}")
            lines.append(f"   Functions: {len(contract.functions)}")
            lines.append(f"   State Variables: {len(contract.state_variables)}")
            if contract.inheritance:
                lines.append(f"   Inherits: {', '.join(contract.inheritance)}")
            lines.append("")

        return "\n".join(lines)

    def _get_contract_summary(self, params: dict) -> str:
        """Get detailed summary of a contract."""
        name = params["contract_name"]

        for contract in self.state.contracts:
            if contract.name == name:
                return summarize_contract(contract)

        return f"Contract not found: {name}"

    def _get_call_graph(self, params: dict) -> str:
        """Get the function call graph."""
        if not self.state.contracts:
            return "No contracts parsed yet."

        graph = get_call_graph(self.state.contracts)

        lines = ["# Call Graph\n"]
        for func, calls in graph.items():
            if calls:
                lines.append(f"{func}")
                for call in calls:
                    lines.append(f"  -> {call}")
                lines.append("")

        return "\n".join(lines) if len(lines) > 1 else "No external calls found."

    def _search_pattern(self, params: dict) -> str:
        """Search for a pattern in all contracts."""
        import re
        pattern = params["pattern"]

        results = []
        for contract in self.state.contracts:
            matches = list(re.finditer(pattern, contract.source, re.IGNORECASE))
            if matches:
                results.append(f"\n## {contract.name} ({len(matches)} matches)")
                for match in matches[:5]:  # Limit to 5 matches per contract
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(contract.source), match.end() + 50)
                    context = contract.source[start:end].replace("\n", " ")
                    results.append(f"  ...{context}...")

        return "\n".join(results) if results else f"No matches for pattern: {pattern}"

    def _submit_analysis(self, params: dict) -> str:
        """Submit the final architecture analysis."""
        self.state.architecture = ArchitectureAnalysis(
            is_upgradeable=params.get("is_upgradeable", False),
            proxy_type=params.get("proxy_type"),
            uses_access_control=params.get("uses_access_control", False),
            access_control_type=params.get("access_control_type"),
            is_defi=params.get("is_defi", False),
            defi_type=params.get("defi_type", []),
            uses_oracles=params.get("uses_oracles", False),
            oracle_type=params.get("oracle_type", []),
            external_protocols=params.get("external_protocols", []),
            entry_points=params.get("entry_points", []),
            admin_functions=params.get("admin_functions", []),
            notes=params.get("notes", []),
        )
        return "Architecture analysis submitted successfully."

    async def run(self, **kwargs) -> ArchitectureAnalysis:
        """
        Execute reconnaissance on the target codebase.

        Returns:
            ArchitectureAnalysis with findings
        """
        self.log("Starting reconnaissance...", style="bold cyan")

        # Step 1: Find and parse all Solidity files
        self.log("Scanning for Solidity files...")
        sol_files = find_solidity_files(self.state.target_path)
        self.log(f"Found {len(sol_files)} Solidity files")

        # Step 2: Parse contracts
        self.log("Parsing contracts...")
        for sol_file in sol_files:
            try:
                source = read_solidity_file(sol_file)
                contracts = extract_contract_info(source, sol_file)
                self.state.contracts.extend(contracts)
            except Exception as e:
                self.log(f"Error parsing {sol_file}: {e}", style="red")

        self.log(f"Parsed {len(self.state.contracts)} contracts")

        # Step 3: Run LLM analysis for architecture understanding
        self.log("Analyzing architecture with LLM...")

        # Prepare contract summaries for LLM
        summaries = []
        for contract in self.state.contracts[:20]:  # Limit to avoid context overflow
            summaries.append(summarize_contract(contract))

        prompt = f"""Analyze the following smart contract codebase and provide a comprehensive security-focused reconnaissance report.

## Contracts Found

{chr(10).join(summaries)}

## Instructions

1. Analyze the architecture and identify patterns
2. Map external dependencies and integrations
3. Identify trust boundaries and admin functions
4. List key entry points for user interaction
5. Note any immediate security concerns

Use the available tools to explore further if needed, then submit your analysis using the submit_analysis tool."""

        response = self.run_with_tools(prompt)

        self.log("Reconnaissance complete", style="bold green")

        # Return the analysis (should have been set by submit_analysis tool)
        if self.state.architecture:
            return self.state.architecture

        # Fallback if LLM didn't call submit_analysis
        return ArchitectureAnalysis(
            notes=["Reconnaissance completed but no structured analysis submitted"],
        )


def run_recon(target_path: Path, verbose: bool = True) -> tuple[AuditState, ArchitectureAnalysis]:
    """
    Convenience function to run reconnaissance on a target.

    Args:
        target_path: Path to the target codebase
        verbose: Whether to print progress

    Returns:
        Tuple of (audit state, architecture analysis)
    """
    import asyncio

    state = AuditState(
        target_path=target_path,
        target_name=target_path.name,
    )

    agent = ReconAgent(state=state, verbose=verbose)
    analysis = asyncio.run(agent.run())

    return state, analysis
