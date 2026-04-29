"""
BatchedLLMHunter — shared base for hunters that analyze the whole codebase in
one LLM call with the source bundle pinned in the cached system prefix.

Pattern: specialty instructions + optional references + source bundle → system
prompt (cached). User prompt is a tiny instruction. Calls 2..N in the same
5-min window hit the Anthropic prompt cache at 10% cost.

Use this for hunters where the analysis is LLM-driven and per-contract tool
dispatch (read_file, find_X) is redundant because the LLM already sees the
full source. Do NOT use for hunters that wrap external tools (Slither,
Semgrep, Halmos, regex replay) — those have their own cheap execution model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.audit_bundle import build_source_bundle
from ...core.llm import LLMClient, get_llm_client
from ...core.types import (
    AgentRole,
    AuditState,
    Finding,
    Severity,
    VulnerabilityType,
)


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
    "info": Severity.LOW,
}


BATCHED_FINDINGS_INSTRUCTION = """
The system prompt gives you the hunter's specialty and the complete source
bundle for this audit. Analyze ALL contracts in one pass — cross-contract
chains matter.

Output findings as a JSON array inside a single ```json fence. Each object MUST have:

- "title": short finding title
- "severity": one of Critical, High, Medium, Low
- "bug_class": short tag (e.g. "reentrancy", "precision-loss", "access-control")
- "contract": contract name (must match a name from the source bundle)
- "function": function name or null
- "description": root cause + concrete attack path + quantified impact
- "recommendation": specific fix
- "confidence": integer 0-100

No findings → ```json\n[]\n```. Output ONLY the JSON fence, no other prose.
"""


@dataclass
class BatchedHunterConfig:
    """Configuration shared by every batched hunter."""
    specialty_prompt: str                      # hunter-specific system instructions
    name: str                                  # hunter name (for logs/finding IDs)
    vulnerability_type: VulnerabilityType      # default type for parsed findings
    extra_references: tuple[str, ...] = field(default_factory=tuple)  # optional ref blocks
    ultrathink: bool = True
    thinking_budget: int = 16000
    max_source_chars: int = 250_000
    max_tokens: int = 8192


class BatchedLLMHunter(AnalysisAgent):
    """One batched LLM call over the full source bundle with a cached system prompt."""

    role = "hunter"

    def __init__(
        self,
        state: AuditState,
        config: BatchedHunterConfig,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state=state, llm_client=llm_client, verbose=verbose)
        self.config = config
        self.llm = llm_client or get_llm_client()
        self.findings: list[Finding] = []
        self.name = config.name
        self.description = f"Batched {config.name}"
        self._id_prefix = config.name.upper().replace(" ", "-")

    @property
    def system_prompt(self) -> str:
        bundle = build_source_bundle(
            self.state.contracts, self.config.max_source_chars, state=self.state,
        )
        parts = [self.config.specialty_prompt]
        for ref in self.config.extra_references:
            parts.append(f"\n\n---\n\n{ref}")
        parts.append(f"\n\n---\n\n# Source Bundle (all contracts under audit)\n\n{bundle}")
        return "".join(parts) if len(parts) == 1 else "\n".join(parts)

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        self.log(f"Starting {self.name} (batched)...", style="cyan")
        if not self.state.contracts:
            return []

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": BATCHED_FINDINGS_INSTRUCTION}],
                system=self.system_prompt,
                max_tokens=self.config.max_tokens,
                extended_thinking=self.config.ultrathink,
                thinking_budget=self.config.thinking_budget,
                enable_prompt_cache=True,
            )
        except Exception as e:
            self.log(f"{self.name} LLM call failed: {e}", style="red")
            return []

        for raw in self._extract_findings(response.text):
            self._record(raw)
        self.log(f"{self.name}: {len(self.findings)} findings", style="green")
        return self.findings

    def _extract_findings(self, text: str) -> list[dict]:
        match = re.search(r"```json\s*(\[.*?\])\s*```", text, re.DOTALL)
        if not match:
            return []
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return []
        return [x for x in data if isinstance(x, dict)]

    def _record(self, raw: dict) -> None:
        title = str(raw.get("title") or "").strip()
        if not title:
            return
        severity = SEVERITY_MAP.get(str(raw.get("severity", "medium")).lower(), Severity.MEDIUM)
        confidence_raw = raw.get("confidence", 70)
        try:
            confidence = float(confidence_raw) / 100.0 if confidence_raw is not None else 0.7
        except (TypeError, ValueError):
            confidence = 0.7

        contract_name = str(raw.get("contract") or "").strip()
        if not contract_name and self.state.contracts:
            contract_name = self.state.contracts[0].name

        finding = Finding(
            id=f"{self._id_prefix}-{len(self.findings) + 1:03d}",
            title=title,
            severity=severity,
            vulnerability_type=self.config.vulnerability_type,
            description=str(raw.get("description", "")),
            contract=contract_name,
            function=raw.get("function"),
            impact=str(raw.get("impact", "")),
            recommendation=str(raw.get("recommendation", "")),
            confidence=max(0.0, min(1.0, confidence)),
            found_by=AgentRole.VULNERABILITY_HUNTER,
        )
        self.findings.append(finding)
        self.state.add_finding(finding)
