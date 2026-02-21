"""
Orientation Agent - Day-1 codebase orientation for manual auditors.

The hybrid audit strategy: run Sentinel on day 1 to get a comprehensive
orientation report, then spend days 2-7 doing focused manual review on
the areas Sentinel flags as highest risk.

This agent produces:
1. Contract map with inheritance and dependency graph
2. Trust boundary analysis (who can do what)
3. Value flow diagram (where do tokens/ETH enter, exit, transform)
4. Invariant candidates (what MUST always be true)
5. Attack surface ranking (which functions to audit first)
6. Known-issue patterns (what Sentinel already found)
7. Prioritized manual review checklist

Output: A markdown report optimized for a human auditor starting the codebase.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from ..core.agent import AnalysisAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, Finding, Severity

console = Console()


@dataclass
class OrientationConfig:
    """Configuration for orientation report generation."""
    ultrathink: bool = True
    thinking_budget: int = 16000
    include_invariants: bool = True
    include_attack_surface: bool = True
    include_value_flows: bool = True
    include_trust_boundaries: bool = True
    max_contracts: int = 30  # Don't try to cover huge codebases in one pass


class OrientationAgent(AnalysisAgent):
    """
    Generates a day-1 orientation report for manual auditors.

    Run this before starting a manual audit to:
    - Understand the codebase in 15 minutes instead of 3 hours
    - Know which contracts to focus on first
    - Have a ready list of invariants to check
    - See the attack surface ranked by risk
    """

    role = AgentRole.RECON
    name = "OrientationAgent"
    description = "Generates day-1 orientation reports for manual auditing"

    def __init__(
        self,
        state: AuditState,
        config: Optional[OrientationConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or OrientationConfig()

    @property
    def system_prompt(self) -> str:
        return """You are a senior smart contract auditor creating an orientation brief
for a junior auditor about to start reviewing a codebase.

Your brief should be:
- ACTIONABLE: Tell them exactly what to look at first
- HONEST: Don't overstate risks, don't hide complexity
- STRUCTURED: Easy to skim, easy to reference during the audit
- COMPLETE: Cover all major risk areas

Think like you're writing a $2000/day auditor's day-1 notes."""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> str:
        """Generate orientation report."""
        self.log("Generating orientation report...", style="bold magenta")

        # Gather all available data
        report_sections = []

        # Section 1: Protocol Overview
        report_sections.append(self._generate_overview())

        # Section 2: Contract Map
        report_sections.append(self._generate_contract_map())

        # Section 3: Trust Boundaries
        if self.config.include_trust_boundaries:
            report_sections.append(self._generate_trust_boundaries())

        # Section 4: Value Flows
        if self.config.include_value_flows:
            report_sections.append(self._generate_value_flows())

        # Section 5: Attack Surface Ranking
        if self.config.include_attack_surface:
            report_sections.append(self._generate_attack_surface())

        # Section 6: Invariant Candidates
        if self.config.include_invariants:
            report_sections.append(await self._generate_invariant_candidates())

        # Section 7: Sentinel Findings Summary (if any)
        if self.state.findings:
            report_sections.append(self._generate_findings_summary())

        # Section 8: Manual Review Checklist
        report_sections.append(await self._generate_review_checklist())

        # Combine into final report
        report = self._assemble_report(report_sections)

        # Write report
        report_path = self.state.target_path / "sentinel_orientation.md"
        try:
            report_path.write_text(report)
            self.log(f"Orientation report saved to: {report_path}", style="bold green")
        except OSError:
            report_path = Path.cwd() / f"sentinel_orientation_{self.state.target_name}.md"
            try:
                report_path.write_text(report)
                self.log(f"Orientation report saved to: {report_path}", style="bold yellow")
            except OSError as e:
                self.log(f"Could not write report: {e}", style="red")

        return report

    def _generate_overview(self) -> str:
        """Generate protocol overview section."""
        lines = [
            "## Protocol Overview",
            "",
        ]

        lines.append(f"**Target:** `{self.state.target_path}`")
        lines.append(f"**Contracts:** {len(self.state.contracts)}")

        if self.state.architecture:
            arch = self.state.architecture
            if arch.is_defi:
                lines.append(f"**Type:** DeFi ({', '.join(arch.defi_type)})")
            if arch.is_upgradeable:
                lines.append(f"**Upgradeable:** Yes ({arch.proxy_type})")
            if arch.uses_oracles:
                lines.append(f"**Oracles:** {', '.join(arch.oracle_type)}")
            if arch.external_protocols:
                lines.append(f"**Integrations:** {', '.join(arch.external_protocols)}")
            if arch.access_control_type:
                lines.append(f"**Access Control:** {arch.access_control_type}")

        lines.append("")
        return "\n".join(lines)

    def _generate_contract_map(self) -> str:
        """Generate contract map with inheritance and dependencies."""
        lines = [
            "## Contract Map",
            "",
        ]

        if not self.state.contracts:
            lines.append("No contracts found.")
            return "\n".join(lines)

        # Sort by importance (more external calls = more interesting)
        sorted_contracts = sorted(
            self.state.contracts,
            key=lambda c: len(c.functions),
            reverse=True,
        )

        for contract in sorted_contracts[:self.config.max_contracts]:
            marker = ""
            if contract.is_proxy:
                marker = " [PROXY]"
            elif contract.is_upgradeable:
                marker = " [UPGRADEABLE]"
            elif contract.uses_delegatecall:
                marker = " [DELEGATECALL]"

            lines.append(f"### {contract.name}{marker}")
            lines.append(f"`{contract.path}`")

            if contract.inheritance:
                lines.append(f"Inherits: {', '.join(contract.inheritance)}")

            # Summarize functions
            externals = [f for f in contract.functions if f.visibility in ("external", "public")]
            state_changing = [f for f in externals if f.mutability not in ("pure", "view")]
            view_funcs = [f for f in externals if f.mutability in ("pure", "view")]

            lines.append(f"Functions: {len(state_changing)} state-changing, {len(view_funcs)} view/pure")

            # List key state-changing functions
            if state_changing:
                for func in state_changing[:10]:
                    params = ", ".join(
                        f"{p.get('type', '?')} {p.get('name', '?')}"
                        for p in func.parameters
                    )
                    mods = f" [{', '.join(func.modifiers)}]" if func.modifiers else ""
                    lines.append(f"  - `{func.name}({params})`{mods}")

            lines.append("")

        # Dependency graph
        if self.state.dependency_graph:
            graph = self.state.dependency_graph
            if graph.edges:
                lines.append("### Dependencies")
                lines.append("")
                # Show unique edges
                seen = set()
                for edge in graph.edges:
                    key = f"{edge.source_contract} -> {edge.target_contract}"
                    if key not in seen:
                        seen.add(key)
                        lines.append(f"- {edge.source_contract} -> {edge.target_contract}")
                lines.append("")

        return "\n".join(lines)

    def _generate_trust_boundaries(self) -> str:
        """Generate trust boundary analysis."""
        lines = [
            "## Trust Boundaries",
            "",
            "Who can do what? Focus your review on transitions ACROSS these boundaries.",
            "",
        ]

        # Identify roles from source code
        admin_functions = []
        user_functions = []
        permissionless = []

        for contract in self.state.contracts:
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue
                if func.mutability in ("pure", "view"):
                    continue

                # Check modifiers for access control
                mods_lower = [m.lower() for m in func.modifiers]
                has_access = any(
                    kw in mod
                    for mod in mods_lower
                    for kw in ["onlyowner", "onlyadmin", "onlyrole", "auth", "onlygovernance"]
                )

                if has_access:
                    admin_functions.append(f"`{contract.name}.{func.name}()` [{', '.join(func.modifiers)}]")
                else:
                    # Check inline access control
                    func_lines = contract.source[
                        func.source_lines[0]:func.source_lines[1]
                    ] if func.source_lines != (0, 0) else ""

                    if "msg.sender" in func_lines and ("require" in func_lines or "revert" in func_lines):
                        user_functions.append(f"`{contract.name}.{func.name}()` (inline auth check)")
                    else:
                        permissionless.append(f"`{contract.name}.{func.name}()`")

        if admin_functions:
            lines.append("### Admin/Owner Functions")
            lines.append("These require elevated privileges. Centralization risk if compromised.")
            lines.append("")
            for f in admin_functions[:20]:
                lines.append(f"- {f}")
            lines.append("")

        if user_functions:
            lines.append("### User Functions (with auth)")
            lines.append("Callable by specific users, check authorization logic.")
            lines.append("")
            for f in user_functions[:20]:
                lines.append(f"- {f}")
            lines.append("")

        if permissionless:
            lines.append("### Permissionless Functions")
            lines.append("**HIGHEST PRIORITY.** Anyone can call these. Check for abuse vectors.")
            lines.append("")
            for f in permissionless[:20]:
                lines.append(f"- {f}")
            lines.append("")

        return "\n".join(lines)

    def _generate_value_flows(self) -> str:
        """Generate value flow analysis."""
        lines = [
            "## Value Flows",
            "",
            "Where do tokens/ETH enter, exit, and transform?",
            "",
        ]

        import re

        entry_points = []
        exit_points = []
        transforms = []

        for contract in self.state.contracts:
            source = contract.source

            # Entry: tokens coming IN
            for match in re.finditer(r'transferFrom\s*\(', source):
                line = source[:match.start()].count("\n") + 1
                entry_points.append(f"`{contract.name}` line {line}: transferFrom (tokens in)")

            if "msg.value" in source:
                entry_points.append(f"`{contract.name}`: accepts ETH via msg.value")

            if re.search(r'receive\s*\(\s*\)\s*external\s+payable', source):
                entry_points.append(f"`{contract.name}`: has receive() function")

            # Exit: tokens going OUT
            for pattern, desc in [
                (r'\.transfer\s*\(', "transfer (tokens/ETH out)"),
                (r'\.safeTransfer\s*\(', "safeTransfer (tokens out)"),
                (r'\.call\{value:', "low-level ETH transfer"),
            ]:
                for match in re.finditer(pattern, source):
                    line = source[:match.start()].count("\n") + 1
                    exit_points.append(f"`{contract.name}` line {line}: {desc}")

            # Transforms: minting, burning, swapping
            for pattern, desc in [
                (r'_mint\s*\(', "minting tokens"),
                (r'_burn\s*\(', "burning tokens"),
                (r'swap\w*\s*\(', "swap operation"),
            ]:
                if re.search(pattern, source):
                    transforms.append(f"`{contract.name}`: {desc}")

        if entry_points:
            lines.append("### Value Entry Points")
            for p in entry_points[:15]:
                lines.append(f"- {p}")
            lines.append("")

        if exit_points:
            lines.append("### Value Exit Points")
            for p in exit_points[:15]:
                lines.append(f"- {p}")
            lines.append("")

        if transforms:
            lines.append("### Value Transformations")
            for t in transforms[:15]:
                lines.append(f"- {t}")
            lines.append("")

        return "\n".join(lines)

    def _generate_attack_surface(self) -> str:
        """Generate attack surface ranking."""
        lines = [
            "## Attack Surface (Ranked by Risk)",
            "",
            "Functions ranked by how dangerous they are if buggy.",
            "",
        ]

        ranked = []
        for contract in self.state.contracts:
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue
                if func.mutability in ("pure", "view"):
                    continue

                risk_score = 0
                risk_factors = []

                # External calls increase risk
                if func.external_calls:
                    risk_score += 3
                    risk_factors.append(f"{len(func.external_calls)} external calls")

                # State writes increase risk
                if func.state_writes:
                    risk_score += len(func.state_writes)
                    risk_factors.append(f"writes {len(func.state_writes)} vars")

                # Token transfers are high risk
                name_lower = func.name.lower()
                if any(kw in name_lower for kw in ["transfer", "withdraw", "swap", "liquidat", "flash"]):
                    risk_score += 5
                    risk_factors.append("handles value transfer")

                # No access control is higher risk
                if not func.modifiers:
                    risk_score += 2
                    risk_factors.append("no modifiers")

                if risk_score > 0:
                    ranked.append((
                        risk_score,
                        contract.name,
                        func.name,
                        risk_factors,
                    ))

        # Sort by risk score descending
        ranked.sort(key=lambda x: x[0], reverse=True)

        for score, contract_name, func_name, factors in ranked[:25]:
            factor_str = ", ".join(factors)
            risk_level = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            lines.append(f"- **[{risk_level}]** `{contract_name}.{func_name}()` -- {factor_str}")

        lines.append("")
        return "\n".join(lines)

    async def _generate_invariant_candidates(self) -> str:
        """Generate invariant candidates using LLM."""
        lines = [
            "## Invariant Candidates",
            "",
            "Properties that MUST always hold. Check these during your review.",
            "",
        ]

        # Get contract summaries
        contract_summaries = []
        for contract in self.state.contracts[:10]:
            summary = f"- {contract.name}"
            if contract.state_variables:
                key_vars = [sv.name for sv in contract.state_variables if not sv.is_constant][:5]
                summary += f" (state: {', '.join(key_vars)})"
            contract_summaries.append(summary)

        if not contract_summaries:
            lines.append("No contracts to generate invariants for.")
            return "\n".join(lines)

        prompt = f"""Given these contracts, list 10-15 critical invariants that a manual auditor should verify.

Contracts:
{chr(10).join(contract_summaries)}

Architecture: {'DeFi - ' + ', '.join(self.state.architecture.defi_type) if self.state.architecture and self.state.architecture.is_defi else 'General'}

For each invariant:
1. One-line description
2. Which contract(s) it applies to
3. Priority: P0 (loss of funds if broken), P1 (significant impact), P2 (nice to verify)

Format as a numbered list. Be specific to THIS protocol, not generic."""

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=self.system_prompt,
        )

        lines.append(response.content)
        lines.append("")
        return "\n".join(lines)

    def _generate_findings_summary(self) -> str:
        """Summarize Sentinel's automated findings."""
        lines = [
            "## Sentinel Automated Findings",
            "",
            "Sentinel found these issues automatically. Verify manually before including in your report.",
            "",
        ]

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

        for sev in severity_order:
            sev_findings = [f for f in self.state.findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"### {sev.value} ({len(sev_findings)})")
            for f in sev_findings:
                validated = " [VERIFIED]" if f.validated else ""
                lines.append(f"- **{f.id}**: {f.title}{validated}")
                lines.append(f"  Contract: `{f.contract}`")
                lines.append(f"  {f.description[:150]}...")
                lines.append("")

        return "\n".join(lines)

    async def _generate_review_checklist(self) -> str:
        """Generate prioritized manual review checklist."""
        lines = [
            "## Manual Review Checklist",
            "",
            "Prioritized areas for your manual review, based on architecture and findings.",
            "",
        ]

        # Build context for LLM
        context_parts = []

        if self.state.architecture:
            arch = self.state.architecture
            if arch.is_defi:
                context_parts.append(f"DeFi protocol: {', '.join(arch.defi_type)}")
            if arch.is_upgradeable:
                context_parts.append(f"Upgradeable: {arch.proxy_type}")
            if arch.uses_oracles:
                context_parts.append(f"Uses oracles: {', '.join(arch.oracle_type)}")
            if arch.external_protocols:
                context_parts.append(f"Integrates: {', '.join(arch.external_protocols)}")

        if self.state.findings:
            context_parts.append(f"Sentinel found {len(self.state.findings)} issues")
            vuln_types = set(f.vulnerability_type.value for f in self.state.findings)
            context_parts.append(f"Types: {', '.join(vuln_types)}")

        context = "\n".join(context_parts) if context_parts else "General smart contract project"

        prompt = f"""Generate a prioritized manual review checklist for this protocol.

Protocol context:
{context}

Contracts: {len(self.state.contracts)}

Create a checklist with:
- P0 items (check FIRST, highest risk of loss of funds)
- P1 items (check on day 2-3, significant impact)
- P2 items (check if time permits, nice to have)

Each item should be a SPECIFIC check, not generic. Reference specific contract areas when possible.
Format as markdown checkboxes: - [ ] Check description"""

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=self.system_prompt,
        )

        lines.append(response.content)
        lines.append("")
        return "\n".join(lines)

    def _assemble_report(self, sections: list[str]) -> str:
        """Assemble sections into final report."""
        from datetime import datetime

        header = f"""# Orientation Report: {self.state.target_name}

**Generated by Sentinel (Hybrid Audit Mode)**
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Purpose:** Day-1 codebase orientation for manual auditing

---

"""
        footer = """
---

*This orientation report was generated by Sentinel to accelerate manual auditing.*
*All findings should be independently verified. Use this as a starting point, not a final report.*
"""

        return header + "\n".join(sections) + footer
