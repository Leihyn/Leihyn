"""
Protocol Intent Agent - Understands what the protocol is SUPPOSED to do.

buOLAS is a non-transferable voting escrow token. transfer() intentionally
reverts. Sentinel reported "unprotected token transfers" as High because it
doesn't understand the design.

This agent:
1. Reads all contract source + documentation (if any)
2. Makes one ultrathink call to understand the protocol's design intent
3. Produces a ProtocolIntent dataclass stored in state
4. Hunters read state.protocol_intent to avoid false positives

Runs BEFORE hunters so they can check intent before reporting.

Cost: ~$0.05-0.10 for one ultrathink call. Runs once per audit.
"""

import json
import re
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from ..core.agent import AnalysisAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, ProtocolIntent

console = Console()


@dataclass
class ProtocolIntentConfig:
    """Configuration for protocol intent analysis."""
    ultrathink: bool = True
    thinking_budget: int = 16000
    max_source_chars: int = 80000  # Max total source to send to LLM


class ProtocolIntentAgent(AnalysisAgent):
    """
    Builds structured understanding of protocol design intent.

    Runs once before hunters to populate state.protocol_intent. Hunters
    can then check intent before reporting (e.g., "is this transfer()
    revert intentional?").
    """

    role = AgentRole.RECON
    name = "ProtocolIntent"
    description = "Analyzes protocol design intent to distinguish bugs from features"

    def __init__(
        self,
        state: AuditState,
        config: Optional[ProtocolIntentConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or ProtocolIntentConfig()

    @property
    def system_prompt(self) -> str:
        return """You are analyzing smart contract architecture to understand DESIGN INTENT.

Your job is NOT to find bugs. Your job is to determine what the protocol is
SUPPOSED to do — so that later analysis can distinguish "intentional design"
from "actual bug."

Focus on:
1. **Protocol type** — What kind of protocol is this? (DEX, lending, governance, staking, bridge, etc.)
2. **Core invariants** — What mathematical/logical properties MUST always hold?
3. **Fund flows** — How do tokens/ETH enter, move through, and exit the system?
4. **Trust model** — Who can do what? Which roles are trusted? What can permissionless users do?
5. **Intentional restrictions** — What is deliberately limited/disabled? (e.g., non-transferable tokens)
6. **Critical state transitions** — What state changes are most dangerous if wrong?
7. **Admin capabilities** — What can privileged roles change? What's behind timelocks?
8. **External dependencies** — What external protocols/oracles does this depend on?

Be SPECIFIC to this protocol. Don't give generic DeFi answers."""

    def get_tools(self) -> list[Tool]:
        """Tools for the intent agent (used in agentic mode if needed)."""
        return [
            Tool(
                name="read_file",
                description="Read a contract's full source code",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {
                            "type": "string",
                            "description": "Name of the contract to read",
                        }
                    },
                    "required": ["contract_name"],
                },
                handler=self._tool_read_file,
            ),
            Tool(
                name="list_contracts",
                description="List all contracts with summaries",
                input_schema={"type": "object", "properties": {}},
                handler=self._tool_list_contracts,
            ),
            Tool(
                name="read_documentation",
                description="Read project documentation (if provided)",
                input_schema={"type": "object", "properties": {}},
                handler=self._tool_read_docs,
            ),
            Tool(
                name="report_intent",
                description="Save the protocol intent analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "protocol_type": {"type": "string"},
                        "core_invariants": {"type": "array", "items": {"type": "string"}},
                        "fund_flows": {"type": "array", "items": {"type": "string"}},
                        "trust_model": {"type": "object"},
                        "intentional_restrictions": {"type": "array", "items": {"type": "string"}},
                        "critical_state_transitions": {"type": "array", "items": {"type": "string"}},
                        "admin_capabilities": {"type": "array", "items": {"type": "string"}},
                        "external_dependencies": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["protocol_type"],
                },
                handler=self._tool_report_intent,
            ),
        ]

    def _tool_read_file(self, contract_name: str = "", **kwargs) -> str:
        """Tool handler: read contract source."""
        for contract in self.state.contracts:
            if contract.name == contract_name or contract_name in contract.name:
                source = contract.source
                if len(source) > 15000:
                    return source[:15000] + "\n// ... [truncated]"
                return source
        return f"Contract '{contract_name}' not found."

    def _tool_list_contracts(self, **kwargs) -> str:
        """Tool handler: list all contracts."""
        lines = []
        for c in self.state.contracts:
            funcs = len(c.functions)
            inherits = f" inherits {', '.join(c.inheritance)}" if c.inheritance else ""
            mods = f" [{', '.join(c.modifiers[:3])}]" if c.modifiers else ""
            lines.append(f"- {c.name}{inherits}{mods} ({funcs} functions, {len(c.source)} chars)")
        return "\n".join(lines) if lines else "No contracts found."

    def _tool_read_docs(self, **kwargs) -> str:
        """Tool handler: read documentation."""
        if self.state.documentation:
            return self.state.documentation[:10000]
        return "No documentation provided."

    def _tool_report_intent(self, **kwargs) -> str:
        """Tool handler: save protocol intent."""
        intent = ProtocolIntent(
            protocol_type=kwargs.get("protocol_type", ""),
            core_invariants=kwargs.get("core_invariants", []),
            fund_flows=kwargs.get("fund_flows", []),
            trust_model=kwargs.get("trust_model", {}),
            intentional_restrictions=kwargs.get("intentional_restrictions", []),
            critical_state_transitions=kwargs.get("critical_state_transitions", []),
            admin_capabilities=kwargs.get("admin_capabilities", []),
            external_dependencies=kwargs.get("external_dependencies", []),
        )
        self.state.protocol_intent = intent
        return "Protocol intent saved."

    async def run(self, **kwargs) -> ProtocolIntent:
        """Analyze protocol design intent."""
        self.log("Analyzing protocol design intent...", style="bold magenta")

        context = self._build_context()

        prompt = f"""Analyze this protocol's design intent. Determine what it's SUPPOSED to do,
not what might be wrong.

{context}

---

Respond in this EXACT format (JSON):

```json
{{
    "protocol_type": "...",
    "core_invariants": ["invariant 1", "invariant 2", ...],
    "fund_flows": ["flow 1", "flow 2", ...],
    "trust_model": {{
        "owner": ["capability 1", "capability 2"],
        "anyone": ["capability 1"]
    }},
    "intentional_restrictions": ["restriction 1", ...],
    "critical_state_transitions": ["transition 1", ...],
    "admin_capabilities": ["capability 1", ...],
    "external_dependencies": ["dependency 1", ...]
}}
```

Be SPECIFIC to this protocol. Every field should reference actual contract names, functions, and patterns you see in the source."""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=self.config.thinking_budget,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        intent = self._parse_intent(response.content)
        self.state.protocol_intent = intent

        self._print_intent(intent)
        return intent

    def _build_context(self) -> str:
        """Build context from recon + architecture + contracts."""
        parts = []

        # Architecture summary
        if self.state.architecture:
            arch = self.state.architecture
            arch_lines = ["## Architecture"]
            if arch.is_defi:
                arch_lines.append(f"DeFi type: {', '.join(arch.defi_type)}")
            if arch.is_upgradeable:
                arch_lines.append(f"Upgradeable: {arch.proxy_type}")
            if arch.uses_oracles:
                arch_lines.append(f"Oracles: {', '.join(arch.oracle_type)}")
            if arch.external_protocols:
                arch_lines.append(f"External: {', '.join(arch.external_protocols)}")
            if arch.admin_functions:
                arch_lines.append(f"Admin functions: {', '.join(arch.admin_functions[:10])}")
            parts.append("\n".join(arch_lines))

        # Documentation
        if self.state.documentation:
            doc_text = self.state.documentation[:5000]
            parts.append(f"## Documentation\n{doc_text}")

        # Contract sources (fit within budget)
        remaining_chars = self.config.max_source_chars - sum(len(p) for p in parts)
        parts.append("## Contract Sources")

        for contract in self.state.contracts:
            source = contract.source
            header = f"\n### {contract.name}"
            if contract.inheritance:
                header += f" (inherits {', '.join(contract.inheritance)})"

            if len(source) + len(header) + 20 > remaining_chars:
                # Truncate to fit
                if remaining_chars > 500:
                    truncated = source[:remaining_chars - 100]
                    parts.append(f"{header}\n```solidity\n{truncated}\n// ... [truncated]\n```")
                    remaining_chars = 0
                break

            parts.append(f"{header}\n```solidity\n{source}\n```")
            remaining_chars -= len(source) + len(header) + 20

        return "\n\n".join(parts)

    def _parse_intent(self, response: str) -> ProtocolIntent:
        """Parse ProtocolIntent from LLM response."""
        # Try to extract JSON block
        json_match = re.search(r'```json\s*\n(.*?)\n\s*```', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                return ProtocolIntent(
                    protocol_type=data.get("protocol_type", ""),
                    core_invariants=data.get("core_invariants", []),
                    fund_flows=data.get("fund_flows", []),
                    trust_model=data.get("trust_model", {}),
                    intentional_restrictions=data.get("intentional_restrictions", []),
                    critical_state_transitions=data.get("critical_state_transitions", []),
                    admin_capabilities=data.get("admin_capabilities", []),
                    external_dependencies=data.get("external_dependencies", []),
                )
            except json.JSONDecodeError:
                pass

        # Fallback: try to parse raw JSON from response
        try:
            # Find any JSON object in the response
            brace_start = response.index("{")
            # Find matching closing brace
            depth = 0
            for i, ch in enumerate(response[brace_start:], brace_start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        json_str = response[brace_start:i + 1]
                        data = json.loads(json_str)
                        return ProtocolIntent(
                            protocol_type=data.get("protocol_type", ""),
                            core_invariants=data.get("core_invariants", []),
                            fund_flows=data.get("fund_flows", []),
                            trust_model=data.get("trust_model", {}),
                            intentional_restrictions=data.get("intentional_restrictions", []),
                            critical_state_transitions=data.get("critical_state_transitions", []),
                            admin_capabilities=data.get("admin_capabilities", []),
                            external_dependencies=data.get("external_dependencies", []),
                        )
        except (ValueError, json.JSONDecodeError):
            pass

        # Last resort: empty intent with protocol type extracted from text
        self.log("Could not parse structured intent, extracting best-effort", style="yellow")
        return ProtocolIntent(
            protocol_type=self._extract_protocol_type(response),
        )

    def _extract_protocol_type(self, text: str) -> str:
        """Best-effort extraction of protocol type from free text."""
        text_lower = text.lower()
        for ptype in ["DEX", "AMM", "Lending", "Governance", "Staking", "Bridge", "Vault", "Oracle", "NFT"]:
            if ptype.lower() in text_lower:
                return ptype
        return "Unknown"

    def _print_intent(self, intent: ProtocolIntent) -> None:
        """Print protocol intent summary."""
        lines = [
            f"[bold]Protocol Type:[/bold] {intent.protocol_type}",
        ]
        if intent.core_invariants:
            lines.append(f"[bold]Invariants:[/bold] {len(intent.core_invariants)}")
            for inv in intent.core_invariants[:3]:
                lines.append(f"  - {inv[:80]}")
        if intent.intentional_restrictions:
            lines.append(f"[bold]Intentional Restrictions:[/bold] {len(intent.intentional_restrictions)}")
            for r in intent.intentional_restrictions[:3]:
                lines.append(f"  - {r[:80]}")
        if intent.trust_model:
            roles = list(intent.trust_model.keys())
            lines.append(f"[bold]Trust Model:[/bold] {len(roles)} roles ({', '.join(roles[:5])})")
        if intent.admin_capabilities:
            lines.append(f"[bold]Admin Capabilities:[/bold] {len(intent.admin_capabilities)}")
        if intent.external_dependencies:
            lines.append(f"[bold]External Dependencies:[/bold] {', '.join(intent.external_dependencies[:3])}")

        console.print(Panel(
            "\n".join(lines),
            title="[bold magenta]Protocol Intent[/bold magenta]",
            border_style="magenta",
        ))
