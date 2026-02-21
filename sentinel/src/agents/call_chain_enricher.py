"""
Call-Chain Enricher - Traces callers of vulnerable functions to add context.

Sentinel reported BuyBackBurnerUniswap._performSwap() with amountOutMin=0 as
Critical. But one call frame up, BuyBackBurner._buyOLAS() has oracle-based
slippage protection. The hunter never checked.

This enricher:
1. For each finding, locates the vulnerable function in state.contracts
2. Searches for ALL callers (internal, inherited, cross-contract)
3. Extracts source snippets around each call site
4. Appends caller context to finding.description

Runs BEFORE DevilsAdvocate so DA can see protections in calling functions.

Cost: Zero LLM calls. Pure code analysis on already-parsed state.
"""

import re
from dataclasses import dataclass
from typing import Optional

from rich.console import Console

from ..core.types import AuditState, Finding, ContractInfo

console = Console()

# How many characters of source to extract around a call site
CALLER_SNIPPET_CHARS = 600


@dataclass
class CallerInfo:
    """Information about a caller of a vulnerable function."""
    contract_name: str
    function_name: str
    call_type: str  # "internal", "inherited", "external"
    source_snippet: str = ""


class CallChainEnricher:
    """
    Traces call chains for each finding and enriches with caller context.

    No LLM calls - pure code analysis on state.contracts and state.dependency_graph.
    """

    def __init__(self, state: AuditState, verbose: bool = True):
        self.state = state
        self.verbose = verbose

    def log(self, message: str, style: str = "white") -> None:
        if self.verbose:
            console.print(f"[{style}][CallChainEnricher][/{style}] {message}")
        self.state.add_log(f"[CallChainEnricher] {message}")

    def enrich(self, findings: list[Finding], state: AuditState) -> list[Finding]:
        """Add call-chain context to each finding."""
        if not findings:
            return findings

        self.log(f"Enriching {len(findings)} findings with call-chain context...", style="bold magenta")

        enriched_count = 0
        for finding in findings:
            callers = self._find_callers(finding, state)
            if callers:
                context = self._format_caller_context(callers)
                finding.description += f"\n\n### Call Chain Context\n{context}"
                enriched_count += 1
                self.log(
                    f"  [{finding.id}] Found {len(callers)} caller(s): "
                    + ", ".join(f"{c.contract_name}.{c.function_name}" for c in callers[:3]),
                    style="cyan",
                )

        self.log(f"Enriched {enriched_count}/{len(findings)} findings with caller context", style="green")
        return findings

    def _find_callers(self, finding: Finding, state: AuditState) -> list[CallerInfo]:
        """Find all callers of the finding's vulnerable function."""
        func_name = finding.function
        if not func_name:
            return []

        contract_name = finding.contract.split(",")[0].strip()
        callers = []

        # 1. Same-contract callers (internal calls)
        contract = self._find_contract(contract_name, state)
        if contract:
            callers.extend(self._find_internal_callers(contract, func_name))

            # 2. Parent contract callers (inheritance)
            if contract.inheritance:
                callers.extend(
                    self._find_inherited_callers(contract, func_name, state)
                )

        # 3. Cross-contract callers (dependency graph)
        if state.dependency_graph:
            callers.extend(
                self._find_external_callers(func_name, contract_name, state)
            )

        return callers

    def _find_contract(self, name: str, state: AuditState) -> Optional[ContractInfo]:
        """Find a contract by name in state."""
        for contract in state.contracts:
            if contract.name == name or name in contract.name:
                return contract
        return None

    def _find_internal_callers(
        self, contract: ContractInfo, func_name: str
    ) -> list[CallerInfo]:
        """Find functions within the same contract that call func_name."""
        callers = []
        source = contract.source

        for func in contract.functions:
            if func.name == func_name:
                continue

            # Get function source
            func_source = self._get_function_source(contract, func)
            if not func_source:
                continue

            # Check if this function calls the target
            # Match: funcName( or funcName (
            if re.search(rf'\b{re.escape(func_name)}\s*\(', func_source):
                snippet = self._extract_snippet(source, func_name, func)
                callers.append(CallerInfo(
                    contract_name=contract.name,
                    function_name=func.name,
                    call_type="internal",
                    source_snippet=snippet,
                ))

        return callers

    def _find_inherited_callers(
        self, contract: ContractInfo, func_name: str, state: AuditState
    ) -> list[CallerInfo]:
        """Find callers in parent contracts via inheritance."""
        callers = []

        for parent_name in contract.inheritance:
            parent = self._find_contract(parent_name, state)
            if not parent:
                continue

            for func in parent.functions:
                func_source = self._get_function_source(parent, func)
                if not func_source:
                    continue

                if re.search(rf'\b{re.escape(func_name)}\s*\(', func_source):
                    snippet = self._extract_snippet(parent.source, func_name, func)
                    callers.append(CallerInfo(
                        contract_name=parent.name,
                        function_name=func.name,
                        call_type="inherited",
                        source_snippet=snippet,
                    ))

        return callers

    def _find_external_callers(
        self, func_name: str, contract_name: str, state: AuditState
    ) -> list[CallerInfo]:
        """Find cross-contract callers via dependency graph."""
        callers = []

        if not state.dependency_graph:
            return callers

        for edge in state.dependency_graph.edges:
            if edge.target_function != func_name:
                continue
            # Also match if target contract matches
            if contract_name and edge.target_contract != contract_name:
                # Allow partial match (e.g., "BuyBackBurnerUniswap" in edge.target)
                if contract_name not in edge.target_contract:
                    continue

            caller_contract = self._find_contract(edge.source_contract, state)
            if not caller_contract:
                continue

            # Find the calling function's source
            snippet = ""
            for func in caller_contract.functions:
                if func.name == edge.source_function:
                    snippet = self._extract_snippet(
                        caller_contract.source, func_name, func
                    )
                    break

            callers.append(CallerInfo(
                contract_name=edge.source_contract,
                function_name=edge.source_function,
                call_type="external",
                source_snippet=snippet,
            ))

        return callers

    def _get_function_source(self, contract: ContractInfo, func) -> str:
        """Extract function source code from contract."""
        if func.source_lines != (0, 0):
            return contract.source[func.source_lines[0]:func.source_lines[1]]

        # Fallback: regex search for function definition
        pattern = rf'function\s+{re.escape(func.name)}\s*\('
        match = re.search(pattern, contract.source)
        if match:
            # Get ~2000 chars from function start (approximate function body)
            return contract.source[match.start():match.start() + 2000]
        return ""

    def _extract_snippet(self, source: str, target_func: str, caller_func) -> str:
        """Extract source snippet around where caller_func calls target_func."""
        # Find the call site within the source
        func_source_start = 0
        if caller_func.source_lines != (0, 0):
            func_source_start = caller_func.source_lines[0]
        else:
            match = re.search(
                rf'function\s+{re.escape(caller_func.name)}\s*\(',
                source,
            )
            if match:
                func_source_start = match.start()

        # Search for the call to target_func starting from the caller function
        search_region = source[func_source_start:]
        call_match = re.search(rf'\b{re.escape(target_func)}\s*\(', search_region)

        if call_match:
            # Center the snippet around the call site
            abs_pos = func_source_start + call_match.start()
            half = CALLER_SNIPPET_CHARS // 2
            start = max(0, abs_pos - half)
            end = min(len(source), abs_pos + half)
            return source[start:end]

        # Fallback: return first CALLER_SNIPPET_CHARS of the calling function
        return source[func_source_start:func_source_start + CALLER_SNIPPET_CHARS]

    def _format_caller_context(self, callers: list[CallerInfo]) -> str:
        """Format caller information into markdown for finding description."""
        lines = []
        for caller in callers[:5]:  # Limit to 5 callers
            lines.append(
                f"**Caller:** `{caller.contract_name}.{caller.function_name}()` "
                f"({caller.call_type} call)"
            )
            if caller.source_snippet:
                # Clean up and truncate
                snippet = caller.source_snippet.strip()
                if len(snippet) > CALLER_SNIPPET_CHARS:
                    snippet = snippet[:CALLER_SNIPPET_CHARS] + "..."
                lines.append(f"```solidity\n{snippet}\n```")
            lines.append("")
        return "\n".join(lines)
