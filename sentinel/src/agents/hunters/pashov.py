"""
Pashov Audit Group specialist hunters.

Each persona runs as ONE batched LLM call over the full source bundle, not one
call per contract. The persona markdown + shared rules + optional BugHunter
reference material + the source bundle all live in the cached system prompt,
so calls 2..N for a single audit read the prefix at 10% cost (Anthropic 5-min
prompt cache).

Upstream: https://github.com/pashov/skills (MIT)
           https://github.com/Yonkoo11/bughunter (MIT, knowledge subset only)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.audit_bundle import build_source_bundle
from ...core.llm import LLMClient, get_llm_client
from ...core.types import (
    AgentRole,
    AuditState,
    ContractInfo,
    Finding,
    Severity,
    VulnerabilityType,
)


# Resolve vendored paths.
_MODULE_DIR = Path(__file__).resolve().parent          # src/agents/hunters
_REPO_ROOT = _MODULE_DIR.parent.parent.parent          # <repo>
PASHOV_REFS = _REPO_ROOT / "vendor" / "pashov-skills" / "solidity-auditor" / "references"
BUGHUNTER_REFS = _REPO_ROOT / "vendor" / "bughunter-knowledge"


# Pashov personas + their native extra references.
PERSONAS: dict[str, tuple[str, tuple[str, ...]]] = {
    "vector-scan": ("vector-scan-agent.md", ("attack-vectors/attack-vectors.md",)),
    "math-precision": ("math-precision-agent.md", ()),
    "access-control": ("access-control-agent.md", ()),
    "economic-security": ("economic-security-agent.md", ()),
    "execution-trace": ("execution-trace-agent.md", ()),
    "invariant": ("invariant-agent.md", ()),
    "periphery": ("periphery-agent.md", ()),
    "first-principles": ("first-principles-agent.md", ()),
}

# BugHunter knowledge routed to the most-relevant persona. Each persona gets at
# most one BugHunter doc to keep the system prefix compact.
BUGHUNTER_BY_PERSONA: dict[str, str] = {
    "vector-scan": "ATTACK_PATTERNS.md",
    "economic-security": "LENDING_PROTOCOL_MASTERY.md",
    "periphery": "INTEGRATION_RISKS.md",
    "first-principles": "BRIDGE_HUNTING_GUIDE.md",
}


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
    "info": Severity.LOW,
}


def _vuln_type(bug_class: str) -> VulnerabilityType:
    """Map Pashov's free-form bug_class tag to sentinel's VulnerabilityType enum."""
    b = (bug_class or "").lower()
    if any(k in b for k in ("reentran",)):
        return VulnerabilityType.REENTRANCY
    if any(k in b for k in ("access", "auth", "permission", "role", "owner")):
        return VulnerabilityType.ACCESS_CONTROL
    if any(k in b for k in ("oracle", "price")):
        return VulnerabilityType.ORACLE_MANIPULATION
    if any(k in b for k in ("overflow", "underflow")):
        return VulnerabilityType.INTEGER_OVERFLOW
    if any(k in b for k in ("precision", "rounding", "truncat")):
        return VulnerabilityType.PRECISION_LOSS
    if any(k in b for k in ("slippage", "mev", "sandwich")):
        return VulnerabilityType.MISSING_SLIPPAGE
    if any(k in b for k in ("flash",)):
        return VulnerabilityType.FLASH_LOAN
    if any(k in b for k in ("invariant",)):
        return VulnerabilityType.INVARIANT_VIOLATION
    return VulnerabilityType.BUSINESS_LOGIC


def load_persona(persona: str, load_bughunter_kb: bool = True) -> str:
    """Persona markdown + shared-rules + extras (+ BugHunter ref for mapped personas)."""
    if persona not in PERSONAS:
        raise ValueError(f"Unknown Pashov persona: {persona}. Valid: {list(PERSONAS)}")

    persona_file, extras = PERSONAS[persona]
    hacking_agents = PASHOV_REFS / "hacking-agents"
    parts: list[str] = []

    persona_path = hacking_agents / persona_file
    shared_path = hacking_agents / "shared-rules.md"
    if not persona_path.exists():
        raise FileNotFoundError(
            f"Pashov persona not found: {persona_path}. "
            f"Run `scripts/update-pashov-skills.sh` to sync the vendored skills."
        )

    parts.append(persona_path.read_text())
    if shared_path.exists():
        parts.append("\n\n---\n\n# Shared Rules\n\n" + shared_path.read_text())
    for extra in extras:
        extra_path = PASHOV_REFS / extra
        if extra_path.exists():
            parts.append(f"\n\n---\n\n# {extra}\n\n" + extra_path.read_text())

    if load_bughunter_kb and persona in BUGHUNTER_BY_PERSONA:
        bh_path = BUGHUNTER_REFS / BUGHUNTER_BY_PERSONA[persona]
        if bh_path.exists():
            parts.append(
                f"\n\n---\n\n# BugHunter Reference: {bh_path.name}\n\n" + bh_path.read_text()
            )

    return "\n".join(parts)


FINDINGS_INSTRUCTION = """
You have been given the persona instructions, reference material, and the complete
source bundle for this audit in the system prompt. Analyze ALL contracts in one
pass — cross-contract chains matter.

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
class PashovHunterConfig:
    persona: str
    ultrathink: bool = True
    thinking_budget: int = 16000
    max_source_chars: int = 250_000  # total bundle size; per-contract auto-scaled
    load_bughunter_kb: bool = True


class PashovHunter(AnalysisAgent):
    """
    One Pashov specialist persona making a single batched call over all contracts.

    System prompt (cached): persona + shared-rules + extras + BugHunter ref + source bundle.
    User prompt: FINDINGS_INSTRUCTION only (tiny, uncached).

    Running all 8 personas back-to-back: call 1 warms the cache, calls 2-8 read
    the 100K+ token prefix at 10% cost. Net: ~1 full system-prompt cost for the
    whole run instead of 8.
    """

    role = "hunter"

    def __init__(
        self,
        state: AuditState,
        config: PashovHunterConfig,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state=state, llm_client=llm_client, verbose=verbose)
        self.config = config
        self.llm = llm_client or get_llm_client()
        self.findings: list[Finding] = []
        self.name = f"pashov_{config.persona.replace('-', '_')}"
        self.description = f"Pashov {config.persona} specialist"
        self._persona_text = load_persona(config.persona, load_bughunter_kb=config.load_bughunter_kb)

    @property
    def system_prompt(self) -> str:
        bundle = build_source_bundle(
            self.state.contracts, self.config.max_source_chars, state=self.state,
        )
        return (
            f"{self._persona_text}\n\n---\n\n"
            f"# Source Bundle (all contracts under audit)\n\n{bundle}"
        )

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        self.log(f"Starting Pashov {self.config.persona} hunter (batched)...", style="cyan")
        if not self.state.contracts:
            return []

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": FINDINGS_INSTRUCTION}],
                system=self.system_prompt,
                max_tokens=8192,
                extended_thinking=self.config.ultrathink,
                thinking_budget=self.config.thinking_budget,
                enable_prompt_cache=True,
            )
        except Exception as e:
            self.log(f"Pashov {self.config.persona} LLM call failed: {e}", style="red")
            return []

        for raw in self._extract_findings(response.text):
            self._record(raw)
        self.log(f"Pashov {self.config.persona}: {len(self.findings)} findings", style="green")
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
            id=f"PASHOV-{self.config.persona.upper()}-{len(self.findings) + 1:03d}",
            title=title,
            severity=severity,
            vulnerability_type=_vuln_type(str(raw.get("bug_class", ""))),
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


def build_all_pashov_hunters(
    state: AuditState,
    llm_client: Optional[LLMClient] = None,
    ultrathink: bool = True,
    thinking_budget: int = 16000,
    verbose: bool = True,
    load_bughunter_kb: bool = True,
) -> list[PashovHunter]:
    """Convenience: instantiate every Pashov persona as a batched hunter."""
    hunters: list[PashovHunter] = []
    for persona in PERSONAS:
        cfg = PashovHunterConfig(
            persona=persona,
            ultrathink=ultrathink,
            thinking_budget=thinking_budget,
            load_bughunter_kb=load_bughunter_kb,
        )
        hunters.append(
            PashovHunter(state=state, config=cfg, llm_client=llm_client, verbose=verbose)
        )
    return hunters
