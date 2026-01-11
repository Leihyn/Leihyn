"""
Multi-Language Reconnaissance Agent.

Supports: Solidity, Rust/Solana, Move, Cairo
"""

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from ..core.agent import AnalysisAgent
from ..core.languages import (
    Language,
    Blockchain,
    analyze_project,
    ProjectInfo,
    LANGUAGE_CONFIGS,
)
from ..core.llm import Tool
from ..core.types import AgentRole, AuditState, ArchitectureAnalysis

# Import language-specific parsers
from ..tools.code_reader import extract_contract_info as extract_solidity
from ..tools.rust_analyzer import RustParser, analyze_solana_patterns
from ..tools.move_analyzer import MoveParser, analyze_move_patterns
from ..tools.cairo_analyzer import CairoParser, analyze_cairo_patterns

console = Console()


class MultiLanguageReconAgent(AnalysisAgent):
    """
    Reconnaissance agent that handles multiple smart contract languages.

    Automatically detects language and blockchain, then runs
    appropriate analysis.
    """

    role = AgentRole.RECON
    name = "MultiLangRecon"
    description = "Multi-language codebase reconnaissance"

    def __init__(self, state: AuditState, **kwargs):
        super().__init__(state, **kwargs)
        self.project_info: Optional[ProjectInfo] = None
        self.parsers = {
            Language.RUST: RustParser(),
            Language.MOVE: MoveParser(),
            Language.CAIRO: CairoParser(),
        }

    @property
    def system_prompt(self) -> str:
        lang_name = self.project_info.language.value if self.project_info else "unknown"
        blockchain = self.project_info.blockchain.value if self.project_info else "unknown"

        return f"""You are a smart contract security reconnaissance agent specializing in {lang_name} on {blockchain}.

## Your Mission

Analyze the codebase and create a comprehensive security-focused overview:

1. **Architecture Analysis**
   - Identify contract/program structure
   - Detect patterns (proxy, upgradeable, modular)
   - Map trust relationships

2. **Entry Point Mapping**
   - Public/external functions
   - Privileged operations
   - Cross-contract/CPI calls

3. **Security Surface**
   - Areas handling value/tokens
   - State-changing operations
   - External dependencies

## Language-Specific Focus

{"### Solidity/EVM" if lang_name == "solidity" else ""}
{"- Check for proxy patterns, upgradeability" if lang_name == "solidity" else ""}
{"- Identify DeFi integrations (Uniswap, Aave, etc.)" if lang_name == "solidity" else ""}

{"### Rust/Solana" if lang_name == "rust" else ""}
{"- Identify Anchor vs native Solana" if lang_name == "rust" else ""}
{"- Map account structures and constraints" if lang_name == "rust" else ""}
{"- Note CPI patterns" if lang_name == "rust" else ""}

{"### Move (Aptos/Sui)" if lang_name == "move" else ""}
{"- Identify resource types and abilities" if lang_name == "move" else ""}
{"- Map module dependencies" if lang_name == "move" else ""}
{"- Check for capability patterns" if lang_name == "move" else ""}

{"### Cairo/StarkNet" if lang_name == "cairo" else ""}
{"- Identify L1-L2 messaging" if lang_name == "cairo" else ""}
{"- Check storage patterns" if lang_name == "cairo" else ""}
{"- Note account abstraction usage" if lang_name == "cairo" else ""}

Be thorough but focused on security-relevant aspects."""

    def get_tools(self) -> list[Tool]:
        return [
            Tool(
                name="list_files",
                description="List all source files found in the project",
                input_schema={"type": "object", "properties": {}},
                handler=self._list_files,
            ),
            Tool(
                name="read_file",
                description="Read a source file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="get_project_summary",
                description="Get a summary of parsed project structure",
                input_schema={"type": "object", "properties": {}},
                handler=self._get_project_summary,
            ),
            Tool(
                name="analyze_file",
                description="Get detailed analysis of a specific file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                },
                handler=self._analyze_file,
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
                },
                handler=self._submit_analysis,
            ),
        ]

    def _list_files(self, params: dict) -> str:
        if not self.project_info:
            return "Project not analyzed yet"

        lines = [
            f"# {self.project_info.language.value.upper()} Project",
            f"Blockchain: {self.project_info.blockchain.value}",
            f"Framework: {self.project_info.framework or 'unknown'}",
            "",
            "## Source Files",
        ]

        for f in self.project_info.source_files[:30]:
            lines.append(f"  - {f.relative_to(self.project_info.path)}")

        if len(self.project_info.source_files) > 30:
            lines.append(f"  ... and {len(self.project_info.source_files) - 30} more")

        lines.append("")
        lines.append("## Test Files")
        for f in self.project_info.test_files[:10]:
            lines.append(f"  - {f.relative_to(self.project_info.path)}")

        return "\n".join(lines)

    def _read_file(self, params: dict) -> str:
        path = Path(params["path"])
        if not path.is_absolute():
            path = self.state.target_path / path

        if not path.exists():
            return f"File not found: {path}"

        return path.read_text()

    def _get_project_summary(self, params: dict) -> str:
        if not self.project_info:
            return "Project not analyzed yet"

        lines = [
            f"# Project Summary: {self.project_info.path.name}",
            "",
            f"**Language:** {self.project_info.language.value}",
            f"**Blockchain:** {self.project_info.blockchain.value}",
            f"**Framework:** {self.project_info.framework or 'native'}",
            "",
            f"**Source Files:** {len(self.project_info.source_files)}",
            f"**Test Files:** {len(self.project_info.test_files)}",
            "",
        ]

        # Language-specific summary
        if self.project_info.language == Language.SOLIDITY:
            lines.append("## Contracts")
            for contract in self.state.contracts[:20]:
                lines.append(f"  - {contract.name} ({len(contract.functions)} functions)")

        elif self.project_info.language == Language.RUST:
            lines.append("## Programs/Modules")
            # Summarize parsed Rust data
            lines.append("  (Use analyze_file for detailed per-file analysis)")

        elif self.project_info.language == Language.MOVE:
            lines.append("## Move Modules")
            lines.append("  (Use analyze_file for detailed per-file analysis)")

        elif self.project_info.language == Language.CAIRO:
            lines.append("## Cairo Contracts")
            lines.append("  (Use analyze_file for detailed per-file analysis)")

        return "\n".join(lines)

    def _analyze_file(self, params: dict) -> str:
        path = Path(params["path"])
        if not path.is_absolute():
            path = self.state.target_path / path

        if not path.exists():
            return f"File not found: {path}"

        source = path.read_text()

        # Use appropriate parser
        lang = self.project_info.language if self.project_info else Language.UNKNOWN

        if lang == Language.SOLIDITY:
            contracts = extract_solidity(source, path)
            return self._format_solidity_analysis(contracts)

        elif lang == Language.RUST:
            parser = self.parsers[Language.RUST]
            analysis = parser.parse_file(path)
            patterns = analyze_solana_patterns(source)
            return self._format_rust_analysis(analysis, patterns)

        elif lang == Language.MOVE:
            parser = self.parsers[Language.MOVE]
            analysis = parser.parse_file(path)
            is_sui = analysis.get("is_sui", False)
            patterns = analyze_move_patterns(source, is_sui)
            return self._format_move_analysis(analysis, patterns)

        elif lang == Language.CAIRO:
            parser = self.parsers[Language.CAIRO]
            analysis = parser.parse_file(path)
            patterns = analyze_cairo_patterns(source)
            return self._format_cairo_analysis(analysis, patterns)

        return f"Unsupported language: {lang}"

    def _format_solidity_analysis(self, contracts: list) -> str:
        lines = ["# Solidity Analysis", ""]

        for contract in contracts:
            lines.append(f"## Contract: {contract.name}")
            if contract.inheritance:
                lines.append(f"Inherits: {', '.join(contract.inheritance)}")
            lines.append(f"Functions: {len(contract.functions)}")
            lines.append(f"State Variables: {len(contract.state_variables)}")

            if contract.is_upgradeable:
                lines.append("**UPGRADEABLE**")
            if contract.is_proxy:
                lines.append("**PROXY PATTERN**")

            lines.append("")

        return "\n".join(lines)

    def _format_rust_analysis(self, analysis: dict, patterns: list) -> str:
        lines = [
            "# Rust/Solana Analysis",
            "",
            f"Is Anchor: {analysis.get('is_anchor', False)}",
            "",
            "## Functions",
        ]

        for func in analysis.get("functions", [])[:20]:
            attrs = ", ".join(func.get("attributes", []))
            lines.append(f"  - {func['name']} ({func['visibility']}) [{attrs}]")
            if func.get("is_instruction"):
                lines.append("    **INSTRUCTION**")

        lines.append("")
        lines.append("## Account Structs")
        for struct in analysis.get("structs", []):
            if struct.get("is_anchor_account"):
                lines.append(f"  - {struct['name']} (Anchor Account)")

        if patterns:
            lines.append("")
            lines.append("## Potential Vulnerabilities")
            for p in patterns:
                lines.append(f"  - [{p['severity']}] {p['vulnerability']}: {p['description']}")

        return "\n".join(lines)

    def _format_move_analysis(self, analysis: dict, patterns: list) -> str:
        lines = [
            "# Move Analysis",
            "",
            f"Is Aptos: {analysis.get('is_aptos', False)}",
            f"Is Sui: {analysis.get('is_sui', False)}",
            "",
            "## Modules",
        ]

        for module in analysis.get("modules", []):
            lines.append(f"  - {module.get('address', '_')}::{module['name']}")

        lines.append("")
        lines.append("## Functions")
        for func in analysis.get("functions", [])[:20]:
            entry = " [ENTRY]" if func.get("is_entry") else ""
            lines.append(f"  - {func['name']} ({func['visibility']}){entry}")

        lines.append("")
        lines.append("## Resources")
        for struct in analysis.get("structs", []):
            if struct.get("is_resource"):
                abilities = ", ".join(struct.get("abilities", []))
                lines.append(f"  - {struct['name']} ({abilities})")

        if patterns:
            lines.append("")
            lines.append("## Potential Vulnerabilities")
            for p in patterns:
                lines.append(f"  - [{p['severity']}] {p['vulnerability']}")

        return "\n".join(lines)

    def _format_cairo_analysis(self, analysis: dict, patterns: list) -> str:
        lines = [
            "# Cairo/StarkNet Analysis",
            "",
            f"Cairo Version: {analysis.get('cairo_version', 'unknown')}",
            "",
            "## Contracts",
        ]

        for contract in analysis.get("contracts", []):
            lines.append(f"  - {contract['name']} ({contract['type']})")

        lines.append("")
        lines.append("## External Functions")
        for func in analysis.get("functions", []):
            if func.get("is_external"):
                l1 = " [L1_HANDLER]" if func.get("is_l1_handler") else ""
                lines.append(f"  - {func['name']}{l1}")

        lines.append("")
        lines.append("## Storage")
        for storage in analysis.get("storage", []):
            mapping = " (mapping)" if storage.get("is_mapping") else ""
            lines.append(f"  - {storage['name']}: {storage['type']}{mapping}")

        if patterns:
            lines.append("")
            lines.append("## Potential Vulnerabilities")
            for p in patterns:
                lines.append(f"  - [{p['severity']}] {p['vulnerability']}")

        return "\n".join(lines)

    def _submit_analysis(self, params: dict) -> str:
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
        return "Analysis submitted successfully"

    async def run(self, **kwargs) -> ArchitectureAnalysis:
        """Execute multi-language reconnaissance."""
        self.log("Starting multi-language reconnaissance...", style="bold cyan")

        # Step 1: Detect language and framework
        self.log("Detecting language and framework...")
        self.project_info = analyze_project(self.state.target_path)

        # Print detection results
        table = Table(title="Project Detection")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("Language", self.project_info.language.value)
        table.add_row("Blockchain", self.project_info.blockchain.value)
        table.add_row("Framework", self.project_info.framework or "native")
        table.add_row("Source Files", str(len(self.project_info.source_files)))
        console.print(table)

        # Step 2: Parse files based on language
        self.log(f"Parsing {self.project_info.language.value} files...")

        if self.project_info.language == Language.SOLIDITY:
            await self._parse_solidity()
        elif self.project_info.language == Language.RUST:
            await self._parse_rust()
        elif self.project_info.language == Language.MOVE:
            await self._parse_move()
        elif self.project_info.language == Language.CAIRO:
            await self._parse_cairo()

        # Step 3: Run LLM analysis
        self.log("Running LLM analysis...")

        prompt = f"""Analyze this {self.project_info.language.value} smart contract project.

Use the available tools to explore the codebase, then submit your analysis.

Focus on:
1. Overall architecture
2. Security-critical components
3. External dependencies
4. Entry points and privileged functions
"""

        response = self.run_with_tools(prompt, max_iterations=15)

        self.log("Reconnaissance complete", style="bold green")

        return self.state.architecture or ArchitectureAnalysis()

    async def _parse_solidity(self):
        """Parse Solidity files."""
        from ..tools.code_reader import read_solidity_file, extract_contract_info

        for sol_file in self.project_info.source_files:
            try:
                source = read_solidity_file(sol_file)
                contracts = extract_contract_info(source, sol_file)
                self.state.contracts.extend(contracts)
            except Exception as e:
                self.log(f"Error parsing {sol_file}: {e}", style="red")

        self.log(f"Parsed {len(self.state.contracts)} Solidity contracts")

    async def _parse_rust(self):
        """Parse Rust/Solana files."""
        parser = self.parsers[Language.RUST]

        for rs_file in self.project_info.source_files:
            try:
                analysis = parser.parse_file(rs_file)
                # Store in state (could create a RustModule type)
                self.state.add_log(f"Parsed: {rs_file.name}")
            except Exception as e:
                self.log(f"Error parsing {rs_file}: {e}", style="red")

        self.log(f"Parsed {len(self.project_info.source_files)} Rust files")

    async def _parse_move(self):
        """Parse Move files."""
        parser = self.parsers[Language.MOVE]

        for move_file in self.project_info.source_files:
            try:
                analysis = parser.parse_file(move_file)
                self.state.add_log(f"Parsed: {move_file.name}")
            except Exception as e:
                self.log(f"Error parsing {move_file}: {e}", style="red")

        self.log(f"Parsed {len(self.project_info.source_files)} Move files")

    async def _parse_cairo(self):
        """Parse Cairo files."""
        parser = self.parsers[Language.CAIRO]

        for cairo_file in self.project_info.source_files:
            try:
                analysis = parser.parse_file(cairo_file)
                self.state.add_log(f"Parsed: {cairo_file.name}")
            except Exception as e:
                self.log(f"Error parsing {cairo_file}: {e}", style="red")

        self.log(f"Parsed {len(self.project_info.source_files)} Cairo files")
