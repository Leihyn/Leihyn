"""
Reasoning Hunter — finds M/H bugs through concrete execution tracing.

Instead of pattern-matching known vulnerability signatures, this hunter forces
the LLM to COMPUTE actual values through actual code paths. Three passes:

1. Triage (Haiku): rank functions by risk, pick top targets
2. State-Trace (Sonnet ultrathink): execute each function with edge-case values
3. Cross-Function (Sonnet ultrathink): check symmetric pairs for inconsistencies

Budget: ~$0.25-0.40 per audit.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import (
    AgentRole,
    AuditState,
    ContractInfo,
    Finding,
    Severity,
    VulnerabilityType,
)
from ...core.languages import Language
from .reasoning_prompts import (
    TRIAGE_SYSTEM,
    TRIAGE_PROMPT,
    STATE_TRACE_SYSTEM,
    STATE_TRACE_PROMPT,
    CROSS_FUNCTION_SYSTEM,
    CROSS_FUNCTION_PROMPT,
)


# Vulnerability type mapping from string to enum
VULN_TYPE_MAP = {
    "precision_loss": VulnerabilityType.PRECISION_LOSS,
    "rounding_error": VulnerabilityType.ROUNDING_ERROR,
    "first_depositor": VulnerabilityType.FIRST_DEPOSITOR,
    "donation_attack": VulnerabilityType.DONATION_ATTACK,
    "incorrect_accounting": VulnerabilityType.INCORRECT_ACCOUNTING,
    "invariant_violation": VulnerabilityType.INVARIANT_VIOLATION,
    "business_logic": VulnerabilityType.BUSINESS_LOGIC,
    "reentrancy": VulnerabilityType.REENTRANCY,
    "arithmetic": VulnerabilityType.ARITHMETIC,
    "integer_overflow": VulnerabilityType.INTEGER_OVERFLOW,
    "integer_underflow": VulnerabilityType.INTEGER_UNDERFLOW,
    "off_by_one": VulnerabilityType.OFF_BY_ONE,
    "unsafe_casting": VulnerabilityType.UNSAFE_CASTING,
    "oracle_manipulation": VulnerabilityType.ORACLE_MANIPULATION,
    "flash_loan": VulnerabilityType.FLASH_LOAN,
    "access_control": VulnerabilityType.ACCESS_CONTROL,
    "fee_on_transfer": VulnerabilityType.FEE_ON_TRANSFER,
    "erc20_return_value": VulnerabilityType.ERC20_RETURN_VALUE,
    "time_manipulation": VulnerabilityType.TIME_MANIPULATION,
    "race_condition": VulnerabilityType.RACE_CONDITION,
}


@dataclass
class ReasoningHunterConfig:
    """Configuration for the Reasoning Hunter."""
    max_contracts: int = 2
    max_functions_per_contract: int = 5
    triage_thinking_budget: int = 0       # Haiku, no ultrathink
    trace_thinking_budget: int = 24000    # Deep reasoning for state trace
    cross_function_thinking_budget: int = 16000


# Minimal system prompt — the real prompts are per-pass
SYSTEM_PROMPT = """You are a smart contract security auditor that finds bugs through \
concrete execution tracing. You compute actual values, not classify patterns."""


class ReasoningHunter(AnalysisAgent):
    """Finds M/H bugs by forcing concrete execution traces with specific values.

    Three-pass analysis:
    1. Triage (Haiku): rank functions by risk score
    2. State-Trace (Sonnet ultrathink): trace execution with edge values
    3. Cross-Function (Sonnet ultrathink): check symmetric pair consistency
    """

    role = "hunter"
    name = "reasoning_hunter"
    description = "Finds bugs through concrete execution tracing with specific values"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    def __init__(self, state: AuditState, config: Optional[ReasoningHunterConfig] = None, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        super().__init__(state=state, **kwargs)
        self.config = config or ReasoningHunterConfig()
        self.findings: list[Finding] = []
        self.tools = self._build_tools()

    def _build_tools(self) -> list[Tool]:
        return [
            Tool(
                name="report_finding",
                description=(
                    "Report a confirmed vulnerability found through concrete execution tracing. "
                    "MUST include a '### Concrete Attack' section with specific function calls, "
                    "computed intermediate values, and quantified attacker profit or user loss."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Concise title describing the bug (e.g., 'First depositor can steal funds via share inflation')",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                            "description": "Severity based on impact and likelihood",
                        },
                        "vulnerability_type": {
                            "type": "string",
                            "description": "Type: precision_loss, rounding_error, first_depositor, donation_attack, incorrect_accounting, invariant_violation, business_logic, reentrancy, arithmetic, etc.",
                        },
                        "contract": {
                            "type": "string",
                            "description": "Contract name where the bug exists",
                        },
                        "function": {
                            "type": "string",
                            "description": "Function name(s) involved",
                        },
                        "description": {
                            "type": "string",
                            "description": "Full description including the '### Concrete Attack' section with specific values and computed results",
                        },
                        "impact": {
                            "type": "string",
                            "description": "Quantified impact (e.g., 'Attacker profits $5000 per victim deposit')",
                        },
                        "recommendation": {
                            "type": "string",
                            "description": "How to fix the bug",
                        },
                        "foundry_test_concept": {
                            "type": "string",
                            "description": "Optional: Foundry test outline for PoC generator",
                        },
                    },
                    "required": ["title", "severity", "vulnerability_type", "contract", "function", "description", "impact"],
                },
                handler=self._report_finding,
            ),
        ]

    def _report_finding(self, params: dict) -> str:
        """Handle a finding reported by the LLM. Rejects findings without concrete values."""
        title = params["title"]
        severity_str = params["severity"]
        description = params["description"]
        contract = params["contract"]

        # Quality gate: reject findings without numeric values
        if not self._has_concrete_values(description):
            return (
                f"REJECTED: '{title}' — finding must include concrete numeric values "
                "in the description (specific amounts, computed results, profit/loss). "
                "Pattern-match findings without computed values are not accepted."
            )

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        vuln_type_str = params.get("vulnerability_type", "business_logic")
        vuln_type = VULN_TYPE_MAP.get(vuln_type_str, VulnerabilityType.BUSINESS_LOGIC)

        # Build root_cause from foundry test concept if available
        root_cause = params.get("foundry_test_concept", "")

        finding = Finding(
            id=f"REASON-{len(self.findings) + 1:03d}",
            title=title,
            severity=severity_map.get(severity_str, Severity.MEDIUM),
            vulnerability_type=vuln_type,
            description=description,
            contract=contract,
            function=params.get("function"),
            impact=params.get("impact", ""),
            root_cause=root_cause,
            recommendation=params.get("recommendation", ""),
            confidence=0.85,
            found_by=AgentRole.VULNERABILITY_HUNTER,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity_str}] {title}"

    @staticmethod
    def _has_concrete_values(text: str) -> bool:
        """Check that the finding contains concrete numeric values, not just pattern descriptions."""
        # Must contain at least one number that looks like a concrete value
        # (not just "step 1", "phase 2", etc.)
        concrete_patterns = [
            r"\d{4,}",           # Numbers with 4+ digits (amounts like 1000, 1e18)
            r"\de\d+",           # Scientific notation (1e6, 1e18)
            r"0x[0-9a-fA-F]+",  # Hex values
            r"\$[\d,]+",        # Dollar amounts
            r"=\s*\d+",         # Computed results (= 1000)
        ]
        return any(re.search(p, text) for p in concrete_patterns)

    def _score_contract(self, contract: ContractInfo) -> int:
        """Score a contract for deep analysis priority."""
        score = 0
        for func in contract.functions:
            if func.visibility not in ("external", "public"):
                continue
            if func.mutability in ("pure", "view"):
                continue
            # Has external calls
            if func.external_calls:
                score += 3
            # Handles transfers (state writes to balance-like vars)
            for write in func.state_writes:
                if any(kw in write.lower() for kw in ["balance", "total", "supply", "shares", "amount", "reserve"]):
                    score += 5
                    break
            # Has swap/liquidate/deposit/withdraw
            name_lower = func.name.lower()
            if any(kw in name_lower for kw in ["swap", "liquidat", "deposit", "withdraw", "mint", "redeem", "borrow", "repay", "stake", "unstake"]):
                score += 5
            # No access control
            if not func.modifiers:
                score += 2
        return score

    def _select_contracts(self, contracts: list[ContractInfo]) -> list[ContractInfo]:
        """Select top contracts for deep analysis based on risk score."""
        scored = [(self._score_contract(c), c) for c in contracts]
        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [c for score, c in scored[:self.config.max_contracts] if score > 0]
        return selected

    def _get_protocol_context(self) -> dict:
        """Extract protocol intent context for prompts."""
        intent = self.state.protocol_intent
        if not intent:
            return {
                "protocol_type": "Unknown",
                "core_invariants": "No invariants documented",
                "intentional_restrictions": "None documented",
                "trust_model": "",
                "fund_flows": "",
            }
        return {
            "protocol_type": intent.protocol_type or "Unknown",
            "core_invariants": "\n".join(f"- {inv}" for inv in intent.core_invariants) or "No invariants documented",
            "intentional_restrictions": "\n".join(f"- {r}" for r in intent.intentional_restrictions) or "None documented",
            "trust_model": "\n".join(
                f"- {role}: {', '.join(caps)}" for role, caps in intent.trust_model.items()
            ) if intent.trust_model else "",
            "fund_flows": "\n".join(f"- {f}" for f in intent.fund_flows) if intent.fund_flows else "",
        }

    def _build_state_model(self, contract: ContractInfo) -> str:
        """Build a state variable model showing writers and readers for each variable."""
        lines = []
        for var in contract.state_variables:
            if var.is_constant or var.is_immutable:
                continue
            writers = []
            readers = []
            for func in contract.functions:
                if var.name in func.state_writes:
                    writers.append(func.name)
                if var.name in func.state_reads:
                    readers.append(func.name)
            if writers or readers:
                lines.append(
                    f"- `{var.name}` ({var.var_type}): "
                    f"written by [{', '.join(writers) or 'none'}], "
                    f"read by [{', '.join(readers) or 'none'}]"
                )
        return "\n".join(lines) or "No mutable state variables detected"

    async def _run_triage(self, llm, contract: ContractInfo, context: dict) -> list[dict]:
        """Pass 1: Triage — rank functions by risk using Haiku."""
        from ...core.llm import HAIKU_MODEL

        trust_model_ctx = ""
        if context["trust_model"]:
            trust_model_ctx = f"## Trust Model (admin functions are lower priority):\n{context['trust_model']}"

        fund_flow_ctx = ""
        if context["fund_flows"]:
            fund_flow_ctx = f"## Fund Flows:\n{context['fund_flows']}"

        prompt = TRIAGE_PROMPT.format(
            contract_name=contract.name,
            contract_path=str(contract.path),
            trust_model_context=trust_model_ctx,
            fund_flow_context=fund_flow_ctx,
            source=contract.source,
        )

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=TRIAGE_SYSTEM,
            max_tokens=2048,
            model_override=HAIKU_MODEL,
        )

        # Parse JSON from response
        try:
            # Try to extract JSON array from response
            text = response.content.strip()
            # Handle markdown fences
            if "```" in text:
                match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
                if match:
                    text = match.group(1).strip()
            ranked = json.loads(text)
            if isinstance(ranked, list):
                return ranked[:self.config.max_functions_per_contract]
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: return all public state-changing functions
        return [
            {"function": f.name, "score": 10, "reasons": ["fallback: triage parse failed"]}
            for f in contract.functions
            if f.visibility in ("external", "public") and f.mutability not in ("pure", "view")
        ][:self.config.max_functions_per_contract]

    async def _run_state_trace(
        self, llm, contract: ContractInfo, ranked_functions: list[dict], context: dict,
    ) -> tuple[str, list[dict]]:
        """Pass 2: State-Trace — concrete execution with edge values. Returns (response, tool_results)."""
        ranked_str = "\n".join(
            f"{i+1}. `{f['function']}` (score: {f['score']}) — {', '.join(f.get('reasons', []))}"
            for i, f in enumerate(ranked_functions)
        )

        prompt = STATE_TRACE_PROMPT.format(
            contract_name=contract.name,
            protocol_type=context["protocol_type"],
            core_invariants=context["core_invariants"],
            intentional_restrictions=context["intentional_restrictions"],
            ranked_functions=ranked_str,
            source=contract.source,
        )

        response, tool_results, _thinking = llm.run_agent_loop(
            initial_message=prompt,
            system=STATE_TRACE_SYSTEM,
            tools=self.tools,
            max_iterations=10,
            extended_thinking=True,
            thinking_budget=self.config.trace_thinking_budget,
            use_routing_model=False,  # Always use primary model for deep reasoning
        )

        return response, tool_results

    async def _run_cross_function(
        self, llm, contract: ContractInfo, context: dict, trace_anomalies: str,
    ) -> None:
        """Pass 3: Cross-Function consistency check."""
        state_model = self._build_state_model(contract)

        prompt = CROSS_FUNCTION_PROMPT.format(
            contract_name=contract.name,
            protocol_type=context["protocol_type"],
            core_invariants=context["core_invariants"],
            state_model=state_model,
            trace_anomalies=trace_anomalies or "No anomalies found in state-trace pass.",
            source=contract.source,
        )

        llm.run_agent_loop(
            initial_message=prompt,
            system=CROSS_FUNCTION_SYSTEM,
            tools=self.tools,
            max_iterations=10,
            extended_thinking=True,
            thinking_budget=self.config.cross_function_thinking_budget,
            use_routing_model=False,
        )

    async def run(self) -> list[Finding]:
        """Execute the three-pass reasoning analysis."""
        from ...core.llm import get_llm_client
        llm = get_llm_client()

        if not self.state.contracts:
            if self.verbose:
                print(f"  {self.name}: no contracts to analyze")
            return self.findings

        # Select top contracts for deep analysis
        selected = self._select_contracts(self.state.contracts)
        if not selected:
            if self.verbose:
                print(f"  {self.name}: no high-risk contracts found")
            return self.findings

        context = self._get_protocol_context()

        if self.verbose:
            print(f"  {self.name}: analyzing {len(selected)} contracts "
                  f"(depth={self.state.depth}, budget={self.config.trace_thinking_budget})")

        for contract in selected:
            if self.verbose:
                print(f"  {self.name}: [Pass 1] Triage — {contract.name}")

            # Pass 1: Triage
            ranked = await self._run_triage(llm, contract, context)
            if not ranked:
                continue

            if self.verbose:
                top_funcs = ", ".join(f["function"] for f in ranked[:3])
                print(f"  {self.name}: top functions: {top_funcs}")

            # Pass 2: State-Trace
            if self.verbose:
                print(f"  {self.name}: [Pass 2] State-Trace — {contract.name} "
                      f"({len(ranked)} functions, thinking={self.config.trace_thinking_budget})")

            findings_before = len(self.findings)
            response, tool_results = await self._run_state_trace(llm, contract, ranked, context)
            findings_after = len(self.findings)
            trace_finding_count = findings_after - findings_before

            # Collect anomalies summary for cross-function pass
            trace_anomalies = ""
            if trace_finding_count > 0:
                anomaly_lines = []
                for f in self.findings[findings_before:findings_after]:
                    anomaly_lines.append(f"- [{f.severity.value}] {f.title} in {f.function or 'unknown'}")
                trace_anomalies = "\n".join(anomaly_lines)

            if self.verbose:
                print(f"  {self.name}: state-trace found {trace_finding_count} findings")

            # Pass 3: Cross-Function
            if self.verbose:
                print(f"  {self.name}: [Pass 3] Cross-Function — {contract.name}")

            await self._run_cross_function(llm, contract, context, trace_anomalies)

        if self.verbose:
            print(f"  {self.name} completed: {len(self.findings)} findings")

        return self.findings
