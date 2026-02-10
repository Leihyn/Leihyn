"""
Reasoning Hunter — finds M/H bugs through concrete execution tracing.

Instead of pattern-matching known vulnerability signatures, this hunter forces
the LLM to COMPUTE actual values through actual code paths. Five passes:

1. Triage (Haiku): rank functions by risk, boosted by Slither results
2. State-Trace (Sonnet ultrathink): execute each function with edge-case values
2.5 Amplification (Sonnet): deepen near-miss findings via looping/flash loans
3. Cross-Function (Sonnet ultrathink): check symmetric pairs for inconsistencies
4. Multi-Contract (Sonnet ultrathink): trace data flows across contract boundaries

Budget: ~$0.25-0.50 per audit.
"""

import asyncio
import hashlib
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
    AMPLIFICATION_SYSTEM,
    AMPLIFICATION_PROMPT,
    CROSS_FUNCTION_SYSTEM,
    CROSS_FUNCTION_PROMPT,
    MULTI_CONTRACT_SYSTEM,
    MULTI_CONTRACT_PROMPT,
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

# Near-miss keywords that trigger the amplification pass
NEAR_MISS_KEYWORDS = [
    "rounds to 0", "rounds down", "rounds up", "1 wei",
    "truncat", "precision", "dust", "rounding",
    "off by one", "off-by-one", "loses 1",
    "small loss", "negligible", "minor", "edge case",
]


@dataclass
class ReasoningHunterConfig:
    """Configuration for the Reasoning Hunter."""
    max_contracts: int = 2
    max_functions_per_contract: int = 5
    triage_thinking_budget: int = 0       # Haiku, no ultrathink
    trace_thinking_budget: int = 24000    # Deep reasoning for state trace
    cross_function_thinking_budget: int = 16000
    multi_contract_thinking_budget: int = 16000
    amplification_thinking_budget: int = 10000
    enable_amplification: bool = True     # Run Pass 2.5 on near-misses
    enable_multi_contract: bool = True    # Run Pass 4 if dependency graph exists
    enable_triage_cache: bool = True      # Cache triage results to disk
    parallel_contracts: bool = True       # Analyze contracts in parallel
    # Cost-aware budget allocation: distribute thinking tokens proportionally
    total_thinking_budget: int = 48000    # Total budget across all contracts
    min_thinking_per_contract: int = 8000  # Floor: don't go below this


# Minimal system prompt — the real prompts are per-pass
SYSTEM_PROMPT = """You are a smart contract security auditor that finds bugs through \
concrete execution tracing. You compute actual values, not classify patterns."""


class ReasoningHunter(AnalysisAgent):
    """Finds M/H bugs by forcing concrete execution traces with specific values.

    Five-pass analysis:
    1. Triage (Haiku): rank functions by risk score, boosted by Slither
    2. State-Trace (Sonnet ultrathink): trace execution with edge values
    2.5 Amplification (Sonnet): deepen near-misses via flash loans/looping
    3. Cross-Function (Sonnet ultrathink): check symmetric pair consistency
    4. Multi-Contract (Sonnet ultrathink): trace cross-contract data flows
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
        # Triage cache: contract source hash → ranked functions
        self._triage_cache: dict[str, list[dict]] = {}

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

        # Quality gate: reject findings without concrete attack section and numeric values
        rejection = self._validate_finding_quality(title, description)
        if rejection:
            return rejection

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
    def _validate_finding_quality(title: str, description: str) -> Optional[str]:
        """Validate finding has concrete attack section and numeric values.

        Returns rejection message string if invalid, None if valid.
        """
        # Must contain '### Concrete Attack' or similar section header
        has_attack_section = bool(re.search(
            r"###?\s*(Concrete Attack|Attack Scenario|Attack Steps|Exploit)",
            description, re.IGNORECASE,
        ))

        if not has_attack_section:
            return (
                f"REJECTED: '{title}' — finding must include a '### Concrete Attack' "
                "section with specific function calls and computed values. "
                "Add this section and resubmit."
            )

        # Must contain at least 3 distinct numeric values (not just "step 1", "step 2")
        # Filter out small numbers that are just list markers
        numbers = re.findall(r"\b\d+(?:\.\d+)?(?:e\d+)?\b", description)
        concrete_numbers = [n for n in numbers if len(n) >= 3 or "e" in n]
        # Also count dollar amounts and hex values
        concrete_numbers += re.findall(r"\$[\d,]+", description)
        concrete_numbers += re.findall(r"0x[0-9a-fA-F]{4,}", description)

        if len(concrete_numbers) < 3:
            return (
                f"REJECTED: '{title}' — finding must include at least 3 concrete "
                "numeric values (specific amounts, computed results, profit/loss). "
                "Pattern-match findings without computed values are not accepted. "
                f"Found only {len(concrete_numbers)} values."
            )

        return None

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

    def _select_contracts(self, contracts: list[ContractInfo]) -> list[tuple[ContractInfo, int]]:
        """Select top contracts for deep analysis and allocate thinking budget proportionally.

        High-risk contracts get more thinking tokens, lower-risk ones get less.
        Total budget is capped at config.total_thinking_budget.
        """
        scored = [(self._score_contract(c), c) for c in contracts]
        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [(c, s) for s, c in scored[:self.config.max_contracts] if s > 0]

        if not selected:
            return []

        total_score = sum(s for _, s in selected)
        result = []
        for contract, score in selected:
            share = score / total_score if total_score > 0 else 1.0 / len(selected)
            budget = max(
                self.config.min_thinking_per_contract,
                int(self.config.total_thinking_budget * share),
            )
            result.append((contract, budget))
        return result

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

    def _get_token_context(self) -> str:
        """Extract token information from architecture/recon for decimal-aware tracing."""
        tokens = []

        # Extract from architecture analysis
        if self.state.architecture and self.state.architecture.token_interactions:
            for token in self.state.architecture.token_interactions:
                token_lower = token.lower()
                if "usdc" in token_lower or "usdt" in token_lower:
                    tokens.append(f"- {token}: 6 decimals (1 token = 1e6)")
                elif "wbtc" in token_lower:
                    tokens.append(f"- {token}: 8 decimals (1 token = 1e8)")
                elif "dai" in token_lower or "weth" in token_lower or "eth" in token_lower:
                    tokens.append(f"- {token}: 18 decimals (1 token = 1e18)")
                else:
                    tokens.append(f"- {token}: decimals unknown (test with both 6 and 18)")

        # Scan contract source for common token patterns
        if not tokens:
            for contract in self.state.contracts:
                source_lower = contract.source.lower()
                if "usdc" in source_lower or "6" in [sv.var_type for sv in contract.state_variables if "decimal" in sv.name.lower()]:
                    tokens.append("- Protocol handles 6-decimal tokens (USDC/USDT pattern detected)")
                if "1e18" in contract.source or "10**18" in contract.source:
                    tokens.append("- Protocol handles 18-decimal tokens (WETH/DAI pattern detected)")
                if tokens:
                    break

        if tokens:
            return "## Token Information (use these EXACT decimals in traces):\n" + "\n".join(tokens)
        return "## Token Information:\nNo specific tokens detected. Test with USDC (6 decimals) AND WETH (18 decimals)."

    def _get_slither_context(self, contract: ContractInfo) -> str:
        """Extract Slither findings relevant to this contract for triage boosting."""
        if not self.state.slither_results:
            return ""

        relevant = []
        for result in self.state.slither_results:
            if result.contract == contract.name or contract.name.lower() in result.description.lower():
                relevant.append(
                    f"- [{result.severity}] {result.detector}: {result.description[:120]}"
                    + (f" (function: {result.function})" if result.function else "")
                )

        if not relevant:
            return ""

        return (
            "## Slither Findings (boost score +3 for flagged functions):\n"
            + "\n".join(relevant[:10])
        )

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

    def _get_triage_cache_key(self, contract: ContractInfo) -> str:
        """Generate cache key from contract source hash."""
        return hashlib.sha256(contract.source.encode()).hexdigest()[:16]

    def _load_triage_cache(self, cache_key: str) -> Optional[list[dict]]:
        """Load cached triage results from disk."""
        if not self.config.enable_triage_cache:
            return None
        cache_dir = Path(".cache") / "reasoning_triage"
        cache_file = cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                return json.loads(cache_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def _save_triage_cache(self, cache_key: str, ranked: list[dict]) -> None:
        """Save triage results to disk cache."""
        if not self.config.enable_triage_cache:
            return
        cache_dir = Path(".cache") / "reasoning_triage"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / f"{cache_key}.json"
            cache_file.write_text(json.dumps(ranked))
        except OSError:
            pass  # Non-critical, skip silently

    def _detect_near_misses(self, response_text: str) -> list[str]:
        """Detect near-miss conditions in the state-trace response for amplification."""
        near_misses = []
        lines = response_text.split("\n")
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(kw in line_lower for kw in NEAR_MISS_KEYWORDS):
                # Grab context: 2 lines before and after
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context = "\n".join(lines[start:end])
                near_misses.append(context)
        # Deduplicate overlapping contexts
        unique = []
        for nm in near_misses:
            if not any(nm in existing for existing in unique):
                unique.append(nm)
        return unique[:5]  # Cap at 5 to control cost

    def get_invariant_suggestions(self) -> list[dict]:
        """Extract testable invariant suggestions from findings for the InvariantFuzzer.

        Returns a list of dicts with 'invariant', 'description', and 'contract' keys
        that the InvariantFuzzerHunter can use to prioritize which invariants to test.
        """
        suggestions = []
        for finding in self.findings:
            # Extract invariant from the finding's vulnerability type and description
            invariant = ""
            if finding.vulnerability_type == VulnerabilityType.ROUNDING_ERROR:
                invariant = f"After deposit(X) then withdraw(all_shares), user gets back >= X - 1"
            elif finding.vulnerability_type == VulnerabilityType.FIRST_DEPOSITOR:
                invariant = "First depositor cannot steal subsequent deposits via share inflation"
            elif finding.vulnerability_type == VulnerabilityType.INCORRECT_ACCOUNTING:
                invariant = "sum(all_user_balances) == total_contract_balance"
            elif finding.vulnerability_type == VulnerabilityType.INVARIANT_VIOLATION:
                invariant = finding.root_cause or f"Invariant violated in {finding.function}"
            elif finding.vulnerability_type == VulnerabilityType.PRECISION_LOSS:
                invariant = f"No precision loss exceeding 1 wei per operation in {finding.function}"
            else:
                invariant = f"assert no value extraction via {finding.function}"

            suggestions.append({
                "invariant": invariant,
                "description": f"From REASON finding: {finding.title}",
                "contract": finding.contract,
                "severity": finding.severity.value,
                "foundry_test_concept": finding.root_cause,
            })
        return suggestions

    # ------------------------------------------------------------------
    # Pass methods
    # ------------------------------------------------------------------

    async def _run_triage(self, llm, contract: ContractInfo, context: dict) -> list[dict]:
        """Pass 1: Triage — rank functions by risk using Haiku. Cached."""
        from ...core.llm import HAIKU_MODEL

        # Check cache first
        cache_key = self._get_triage_cache_key(contract)
        cached = self._load_triage_cache(cache_key)
        if cached is not None:
            if self.verbose:
                print(f"  {self.name}: triage cache hit for {contract.name}")
            return cached

        trust_model_ctx = ""
        if context["trust_model"]:
            trust_model_ctx = f"## Trust Model (admin functions are lower priority):\n{context['trust_model']}"

        fund_flow_ctx = ""
        if context["fund_flows"]:
            fund_flow_ctx = f"## Fund Flows:\n{context['fund_flows']}"

        slither_ctx = self._get_slither_context(contract)

        prompt = TRIAGE_PROMPT.format(
            contract_name=contract.name,
            contract_path=str(contract.path),
            trust_model_context=trust_model_ctx,
            fund_flow_context=fund_flow_ctx,
            slither_context=slither_ctx,
            source=contract.source,
        )

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=TRIAGE_SYSTEM,
            max_tokens=2048,
            model_override=HAIKU_MODEL,
        )

        # Parse JSON from response
        ranked = None
        try:
            text = response.content.strip()
            if "```" in text:
                match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
                if match:
                    text = match.group(1).strip()
            parsed = json.loads(text)
            if isinstance(parsed, list):
                ranked = parsed[:self.config.max_functions_per_contract]
        except (json.JSONDecodeError, ValueError):
            pass

        if ranked is None:
            # Fallback: return all public state-changing functions
            ranked = [
                {"function": f.name, "score": 10, "reasons": ["fallback: triage parse failed"]}
                for f in contract.functions
                if f.visibility in ("external", "public") and f.mutability not in ("pure", "view")
            ][:self.config.max_functions_per_contract]

        # Save to cache
        self._save_triage_cache(cache_key, ranked)
        return ranked

    async def _run_state_trace(
        self, llm, contract: ContractInfo, ranked_functions: list[dict], context: dict,
        thinking_budget: Optional[int] = None,
    ) -> tuple[str, list[dict]]:
        """Pass 2: State-Trace — concrete execution with edge values."""
        ranked_str = "\n".join(
            f"{i+1}. `{f['function']}` (score: {f['score']}) — {', '.join(f.get('reasons', []))}"
            for i, f in enumerate(ranked_functions)
        )

        token_ctx = self._get_token_context()

        prompt = STATE_TRACE_PROMPT.format(
            contract_name=contract.name,
            protocol_type=context["protocol_type"],
            core_invariants=context["core_invariants"],
            intentional_restrictions=context["intentional_restrictions"],
            token_context=token_ctx,
            ranked_functions=ranked_str,
            source=contract.source,
        )

        budget = thinking_budget or self.config.trace_thinking_budget
        response, tool_results, _thinking = llm.run_agent_loop(
            initial_message=prompt,
            system=STATE_TRACE_SYSTEM,
            tools=self.tools,
            max_iterations=10,
            extended_thinking=True,
            thinking_budget=budget,
            use_routing_model=False,
        )

        return response, tool_results

    async def _run_amplification(
        self, llm, contract: ContractInfo, context: dict, near_misses: list[str],
    ) -> None:
        """Pass 2.5: Amplification — deepen near-miss findings."""
        if not near_misses:
            return

        near_miss_str = "\n\n---\n\n".join(
            f"**Near-miss {i+1}:**\n{nm}" for i, nm in enumerate(near_misses)
        )

        prompt = AMPLIFICATION_PROMPT.format(
            contract_name=contract.name,
            protocol_type=context["protocol_type"],
            near_misses=near_miss_str,
            source=contract.source,
        )

        llm.run_agent_loop(
            initial_message=prompt,
            system=AMPLIFICATION_SYSTEM,
            tools=self.tools,
            max_iterations=8,
            extended_thinking=True,
            thinking_budget=self.config.amplification_thinking_budget,
            use_routing_model=False,
        )

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

    async def _run_multi_contract(self, llm, context: dict) -> None:
        """Pass 4: Multi-Contract trace — data flows across contract boundaries."""
        graph = self.state.dependency_graph
        if not graph or not graph.critical_flows:
            if self.verbose:
                print(f"  {self.name}: [Pass 4] skipped — no cross-contract flows")
            return

        # Build critical flows description
        flows_str = ""
        for flow in graph.critical_flows:
            flows_str += f"\n### {flow.flow_type} [{flow.risk_level.upper()}]\n"
            flows_str += f"{flow.description}\n"
            flows_str += f"Contracts: {', '.join(flow.contracts_involved)}\n"
            for call in flow.calls[:5]:
                flows_str += f"  - {call.source_contract}.{call.source_function} → {call.target_contract}.{call.target_function}\n"

        # Collect source of involved contracts
        involved_names = set()
        for flow in graph.critical_flows:
            involved_names.update(flow.contracts_involved)

        contracts_source = ""
        for contract in self.state.contracts:
            if contract.name in involved_names:
                # Truncate very long sources
                source = contract.source
                if len(source) > 15000:
                    source = source[:15000] + "\n\n// ... [truncated]"
                contracts_source += f"\n### {contract.name}\n```solidity\n{source}\n```\n"

        if not contracts_source:
            return

        # Summarize existing findings for context
        existing_str = ""
        if self.findings:
            existing_str = "\n".join(
                f"- [{f.severity.value}] {f.title} in {f.contract}.{f.function or 'N/A'}"
                for f in self.findings
            )
        else:
            existing_str = "No single-contract findings yet."

        prompt = MULTI_CONTRACT_PROMPT.format(
            protocol_type=context["protocol_type"],
            critical_flows=flows_str,
            contracts_source=contracts_source,
            core_invariants=context["core_invariants"],
            existing_findings=existing_str,
        )

        if self.verbose:
            print(f"  {self.name}: [Pass 4] Multi-Contract — "
                  f"{len(graph.critical_flows)} flows, {len(involved_names)} contracts")

        llm.run_agent_loop(
            initial_message=prompt,
            system=MULTI_CONTRACT_SYSTEM,
            tools=self.tools,
            max_iterations=10,
            extended_thinking=True,
            thinking_budget=self.config.multi_contract_thinking_budget,
            use_routing_model=False,
        )

    # ------------------------------------------------------------------
    # Per-contract analysis (runs Passes 1-3 for a single contract)
    # ------------------------------------------------------------------

    async def _analyze_contract(
        self, llm, contract: ContractInfo, context: dict,
        thinking_budget: Optional[int] = None,
    ) -> tuple[int, str]:
        """Run Passes 1-3 for a single contract. Returns (finding_count, trace_response).

        Args:
            thinking_budget: Per-contract thinking budget allocated by _select_contracts().
                             Falls back to config.trace_thinking_budget if not provided.
        """
        trace_budget = thinking_budget or self.config.trace_thinking_budget

        if self.verbose:
            print(f"  {self.name}: [Pass 1] Triage — {contract.name}")

        # Pass 1: Triage
        ranked = await self._run_triage(llm, contract, context)
        if not ranked:
            return 0, ""

        if self.verbose:
            top_funcs = ", ".join(f["function"] for f in ranked[:3])
            print(f"  {self.name}: top functions: {top_funcs}")

        # Pass 2: State-Trace
        if self.verbose:
            print(f"  {self.name}: [Pass 2] State-Trace — {contract.name} "
                  f"({len(ranked)} functions, thinking={trace_budget})")

        findings_before = len(self.findings)
        response, tool_results = await self._run_state_trace(
            llm, contract, ranked, context, thinking_budget=trace_budget,
        )
        findings_after = len(self.findings)
        trace_finding_count = findings_after - findings_before

        if self.verbose:
            print(f"  {self.name}: state-trace found {trace_finding_count} findings")

        # Pass 2.5: Amplification (if near-misses detected)
        if self.config.enable_amplification and response:
            near_misses = self._detect_near_misses(response)
            if near_misses:
                if self.verbose:
                    print(f"  {self.name}: [Pass 2.5] Amplification — "
                          f"{len(near_misses)} near-misses detected")
                amp_before = len(self.findings)
                await self._run_amplification(llm, contract, context, near_misses)
                amp_count = len(self.findings) - amp_before
                if self.verbose:
                    print(f"  {self.name}: amplification found {amp_count} additional findings")

        # Collect anomalies summary for cross-function pass
        trace_anomalies = ""
        total_new = len(self.findings) - findings_before
        if total_new > 0:
            anomaly_lines = []
            for f in self.findings[findings_before:]:
                anomaly_lines.append(f"- [{f.severity.value}] {f.title} in {f.function or 'unknown'}")
            trace_anomalies = "\n".join(anomaly_lines)

        # Pass 3: Cross-Function
        if self.verbose:
            print(f"  {self.name}: [Pass 3] Cross-Function — {contract.name}")

        await self._run_cross_function(llm, contract, context, trace_anomalies)

        total_findings = len(self.findings) - findings_before
        return total_findings, response

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    async def run(self) -> list[Finding]:
        """Execute the multi-pass reasoning analysis."""
        from ...core.llm import get_llm_client
        llm = get_llm_client()

        if not self.state.contracts:
            if self.verbose:
                print(f"  {self.name}: no contracts to analyze")
            return self.findings

        # Select top contracts and allocate thinking budget proportionally
        selected = self._select_contracts(self.state.contracts)
        if not selected:
            if self.verbose:
                print(f"  {self.name}: no high-risk contracts found")
            return self.findings

        context = self._get_protocol_context()

        if self.verbose:
            budget_info = ", ".join(
                f"{c.name}={b}" for c, b in selected
            )
            print(f"  {self.name}: analyzing {len(selected)} contracts "
                  f"(depth={self.state.depth}, budgets=[{budget_info}])")

        # Analyze contracts — parallel if enabled and multiple contracts
        if self.config.parallel_contracts and len(selected) > 1:
            tasks = [
                self._analyze_contract(llm, contract, context, thinking_budget=budget)
                for contract, budget in selected
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for (contract, _budget), result in zip(selected, results):
                if isinstance(result, Exception):
                    if self.verbose:
                        print(f"  {self.name}: {contract.name} analysis failed: {result}")
        else:
            for contract, budget in selected:
                await self._analyze_contract(llm, contract, context, thinking_budget=budget)

        # Pass 4: Multi-Contract (if dependency graph exists)
        if self.config.enable_multi_contract:
            await self._run_multi_contract(llm, context)

        if self.verbose:
            print(f"  {self.name} completed: {len(self.findings)} findings")

        return self.findings
