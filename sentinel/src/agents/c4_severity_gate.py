"""
C4 Severity Gate - Deterministic + light-LLM post-processor for C4 judging rules.

Sentinel overrates findings because it doesn't apply contest judging rules.
A finding on an admin-only function reported as High? C4 says "all roles
assumed trustworthy" -- that's QA at best. A finding about rounding with no
proof of material loss? C4 says "dust amounts" -- cap at Low.

This gate runs AFTER DevilsAdvocate validation and applies hard rules:

Phase 1 (deterministic, free):
  7 rules that check finding metadata/source for automatic downgrade/reject.

Phase 2 (LLM batch, ~$0.02):
  One batch call on surviving M/H findings with C4 severity definitions.
  Confirms or downgrades based on "would a C4 judge accept this?"
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from rich.console import Console
from rich.table import Table

from ..core.llm import LLMClient, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType

console = Console()

# Admin-gated modifier keywords (lowercase)
ADMIN_MODIFIERS = {
    "onlyowner", "onlyadmin", "onlygovernance", "onlygovernor",
    "onlyauthorized", "onlyminter", "onlymanager", "onlyoperator",
    "onlyrole", "onlyguardian", "auth", "requiresauth",
}

# Centralization/governance vulnerability types
CENTRALIZATION_TYPES = {
    VulnerabilityType.CENTRALIZATION,
    VulnerabilityType.SINGLE_POINT_FAILURE,
    VulnerabilityType.MISSING_TIMELOCK,
    VulnerabilityType.GOVERNANCE_MANIPULATION,
}

# Best-practice-only recommendation keywords
BEST_PRACTICE_KEYWORDS = [
    "add timelock", "use two-step", "add event", "emit event",
    "add natspec", "add documentation", "use safecast",
    "add zero-address check", "add zero address check",
]


@dataclass
class C4Verdict:
    """Result of applying a C4 rule to a finding."""
    action: str  # "reject", "downgrade", "cap", "keep"
    max_severity: Optional[Severity] = None
    reason: str = ""
    rule_name: str = ""


@dataclass
class C4Rule:
    """A single C4 judging rule."""
    name: str
    description: str
    check: Callable[["Finding", "AuditState"], Optional[C4Verdict]]


class C4SeverityGate:
    """
    Applies C4 contest judging rules to findings after DA validation.

    Two phases:
    1. Deterministic rules (no LLM, instant) - applied to ALL findings
    2. LLM batch verification - applied to surviving M/H+ findings
    """

    # C4 severity definitions used in LLM prompt
    C4_SEVERITY_DEFINITIONS = """
## C4 Severity Definitions (Exact)

**High**: Assets can be stolen/lost/compromised directly (or indirectly if
there is a valid attack path that does not have hand-wavy hypotheticals).

**Medium**: Assets not at direct risk, but the function of the protocol or
its availability could be impacted, or leak value with a hypothetical attack
path with stated assumptions.

**QA (Low)**: Anything that is not a risk to assets or protocol function.
Includes: best practices, code style, centralization risks where admin is
trusted, gas optimizations, informational observations.

## Key C4 Rules
- All privileged roles (owner, admin, governance) are assumed TRUSTWORTHY.
  Findings that require admin misbehavior are QA, not M/H.
- Findings about fee-on-transfer or rebasing tokens are INVALID unless the
  contest scope explicitly mentions these token types.
- Dust amounts from rounding/precision loss are QA unless proven material.
- "Hand-wavy hypotheticals" (no concrete attack path, no PoC concept) are
  invalid for M/H.
- Centralization risks are QA/informational, not M/H.
"""

    def __init__(
        self,
        state: AuditState,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        self.state = state
        self.llm = llm_client or get_llm_client()
        self.verbose = verbose
        self.verdicts: list[tuple[str, C4Verdict]] = []  # (finding_id, verdict)

    def log(self, message: str, style: str = "white") -> None:
        if self.verbose:
            console.print(f"[{style}][C4Gate][/{style}] {message}")
        self.state.add_log(f"[C4Gate] {message}")

    # ── Deterministic Rules ──────────────────────────────────────────────

    @staticmethod
    def _check_admin_trust(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 1: Finding on admin-only function -> cap at LOW."""
        # Check modifiers on the function
        contract_name = finding.contract.split(",")[0].strip()
        func_name = finding.function

        if not func_name:
            return None

        for contract in state.contracts:
            if contract.name != contract_name and contract_name not in contract.name:
                continue
            for func in contract.functions:
                if func.name != func_name:
                    continue
                # Check modifiers
                mods_lower = {m.lower() for m in func.modifiers}
                if mods_lower & ADMIN_MODIFIERS:
                    return C4Verdict(
                        action="cap",
                        max_severity=Severity.LOW,
                        reason=f"Function has admin modifier ({', '.join(mods_lower & ADMIN_MODIFIERS)}). C4: all roles assumed trustworthy.",
                        rule_name="admin_trust",
                    )
                # Check inline access control: require(msg.sender == owner)
                source = contract.source
                if func.source_lines != (0, 0):
                    func_source = source[func.source_lines[0]:func.source_lines[1]]
                else:
                    # Try to find function in source
                    pattern = rf'function\s+{re.escape(func_name)}\s*\('
                    match = re.search(pattern, source)
                    if match:
                        func_source = source[match.start():match.start() + 2000]
                    else:
                        func_source = ""

                if func_source:
                    inline_admin = re.search(
                        r'(?:require|if)\s*\(\s*msg\.sender\s*==\s*(?:owner|admin|governance|manager|operator)',
                        func_source, re.IGNORECASE,
                    )
                    if inline_admin:
                        return C4Verdict(
                            action="cap",
                            max_severity=Severity.LOW,
                            reason="Function has inline admin check (msg.sender == owner/admin). C4: roles assumed trustworthy.",
                            rule_name="admin_trust",
                        )
        return None

    @staticmethod
    def _check_admin_mistake(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 2: Finding requires admin to pass wrong value -> cap at LOW."""
        desc_lower = (finding.description + " " + finding.impact).lower()
        mistake_indicators = [
            "admin could set", "owner could pass", "admin might set",
            "governance could set", "if admin sets", "if owner sets",
            "missing validation on setter", "no validation on admin",
            "admin could accidentally", "misconfigured by admin",
            "owner mistake", "admin error",
        ]
        if any(ind in desc_lower for ind in mistake_indicators):
            return C4Verdict(
                action="cap",
                max_severity=Severity.LOW,
                reason="Finding requires admin mistake. C4: reckless admin mistakes are invalid at M/H.",
                rule_name="admin_mistake",
            )
        return None

    @staticmethod
    def _check_dust_amounts(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 3: Rounding/precision loss with no proof of material loss -> cap at LOW."""
        if finding.vulnerability_type not in (
            VulnerabilityType.PRECISION_LOSS,
            VulnerabilityType.ROUNDING_ERROR,
        ):
            return None

        # If there's a PoC showing material loss, keep it
        if finding.poc and finding.poc.success and finding.poc.profit and finding.poc.profit > 100:
            return None

        desc_lower = finding.description.lower()
        if any(kw in desc_lower for kw in ["dust", "wei", "negligible", "rounding error", "precision loss"]):
            return C4Verdict(
                action="cap",
                max_severity=Severity.LOW,
                reason="Dust amounts from rounding. C4: no proof of material loss.",
                rule_name="dust_amounts",
            )
        # Even without keywords, precision/rounding findings without PoC are capped
        if not finding.poc:
            return C4Verdict(
                action="cap",
                max_severity=Severity.LOW,
                reason="Precision/rounding finding without proof of material loss.",
                rule_name="dust_amounts",
            )
        return None

    @staticmethod
    def _check_non_standard_tokens(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 4: Fee-on-transfer / rebasing token findings -> reject unless in scope."""
        if finding.vulnerability_type not in (
            VulnerabilityType.FEE_ON_TRANSFER,
            VulnerabilityType.REBASING_TOKEN,
            VulnerabilityType.NON_STANDARD_TOKEN,
        ):
            return None

        # Check documentation for explicit mention
        docs = (state.documentation or "").lower()
        if "fee-on-transfer" in docs or "fee on transfer" in docs or "rebasing" in docs:
            return None  # Explicitly in scope

        return C4Verdict(
            action="reject",
            reason="Fee-on-transfer / rebasing tokens out of scope unless explicitly stated. C4 standard rule.",
            rule_name="non_standard_tokens",
        )

    @staticmethod
    def _check_no_attack_path(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 5: Low confidence + no PoC + severity >= Medium -> cap at LOW."""
        if finding.severity not in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            return None

        if finding.confidence < 0.4 and not finding.poc:
            return C4Verdict(
                action="cap",
                max_severity=Severity.LOW,
                reason=f"Confidence {finding.confidence:.0%} with no PoC. C4: no hand-wavy hypotheticals at M/H.",
                rule_name="no_attack_path",
            )
        return None

    @staticmethod
    def _check_centralization(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 6: Centralization/governance risk -> cap at LOW."""
        if finding.vulnerability_type in CENTRALIZATION_TYPES:
            return C4Verdict(
                action="cap",
                max_severity=Severity.LOW,
                reason="Centralization/governance risk. C4: admin roles trusted, centralization is QA.",
                rule_name="centralization",
            )
        return None

    @staticmethod
    def _check_best_practice(finding: Finding, state: AuditState) -> Optional[C4Verdict]:
        """Rule 7: Best-practice-only recommendation with no concrete exploit -> cap at INFORMATIONAL."""
        rec_lower = (finding.recommendation or "").lower()
        desc_lower = finding.description.lower()

        if any(kw in rec_lower for kw in BEST_PRACTICE_KEYWORDS):
            # Check if there's also a concrete exploit described
            exploit_indicators = [
                "steal", "drain", "extract", "profit", "loss of funds",
                "attacker can", "malicious", "exploit",
            ]
            if not any(ind in desc_lower for ind in exploit_indicators):
                return C4Verdict(
                    action="cap",
                    max_severity=Severity.INFORMATIONAL,
                    reason="Best-practice recommendation with no concrete exploit path.",
                    rule_name="best_practice",
                )
        return None

    # All deterministic rules in order
    RULES: list[C4Rule] = [
        C4Rule("admin_trust", "Admin-only function", _check_admin_trust.__func__),
        C4Rule("admin_mistake", "Requires admin mistake", _check_admin_mistake.__func__),
        C4Rule("dust_amounts", "Dust/rounding amounts", _check_dust_amounts.__func__),
        C4Rule("non_standard_tokens", "Fee-on-transfer/rebasing OOS", _check_non_standard_tokens.__func__),
        C4Rule("no_attack_path", "No concrete attack path", _check_no_attack_path.__func__),
        C4Rule("centralization", "Centralization risk", _check_centralization.__func__),
        C4Rule("best_practice", "Best practice only", _check_best_practice.__func__),
    ]

    def _apply_verdict(self, finding: Finding, verdict: C4Verdict) -> None:
        """Apply a verdict to a finding."""
        self.verdicts.append((finding.id, verdict))

        if verdict.action == "reject":
            finding.false_positive = True
            finding.confidence = 0.0
            self.log(
                f"  [{finding.id}] REJECTED by {verdict.rule_name}: {verdict.reason}",
                style="red",
            )
        elif verdict.action in ("cap", "downgrade"):
            if verdict.max_severity:
                severity_order = [
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFORMATIONAL, Severity.GAS,
                ]
                current_idx = severity_order.index(finding.severity)
                cap_idx = severity_order.index(verdict.max_severity)
                if current_idx < cap_idx:
                    old = finding.severity.value
                    finding.severity = verdict.max_severity
                    self.log(
                        f"  [{finding.id}] {old} -> {verdict.max_severity.value} ({verdict.rule_name}): {verdict.reason}",
                        style="yellow",
                    )

    # ── LLM Batch Verification ───────────────────────────────────────────

    async def _llm_verify_batch(self, findings: list[Finding], state: AuditState) -> None:
        """Batch-verify remaining M/H findings with one LLM call."""
        if not findings:
            return

        self.log(f"LLM batch verification for {len(findings)} M/H findings...", style="cyan")

        sections = []
        for i, f in enumerate(findings):
            sections.append(f"""--- FINDING {i + 1} ---
ID: {f.id}
Title: {f.title}
Severity: {f.severity.value}
Type: {f.vulnerability_type.value}
Contract: {f.contract}
Function: {f.function or "N/A"}
Confidence: {f.confidence:.0%}
Has PoC: {"Yes (verified)" if f.poc and f.poc.success else "No"}

Description (excerpt):
{f.description[:800]}

Impact: {f.impact[:300] if f.impact else "Not specified"}
""")

        prompt = f"""You are a C4 (Code4rena) judge. Review these findings and determine if each
meets the severity bar.

{self.C4_SEVERITY_DEFINITIONS}

{chr(10).join(sections)}

---

For EACH finding, output exactly:

FINDING [ID]: [CONFIRM/DOWNGRADE_TO_MEDIUM/DOWNGRADE_TO_LOW/REJECT] - [one-line reason]

Be strict. Most findings are initially overrated."""

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a strict C4 contest judge. Apply the exact rules provided.",
            max_tokens=2000,
        )

        self._parse_llm_verdicts(response.content, findings)

    def _parse_llm_verdicts(self, response: str, findings: list[Finding]) -> None:
        """Parse LLM batch verification response."""
        sev_map = {
            "downgrade_to_medium": Severity.MEDIUM,
            "downgrade_to_low": Severity.LOW,
            "downgrade_to_qa": Severity.INFORMATIONAL,
        }

        for finding in findings:
            # Match: FINDING <id>: <verdict> - <reason>
            pattern = rf'FINDING\s+{re.escape(finding.id)}\s*:\s*(\w+(?:_TO_\w+)?)\s*-\s*(.+?)(?=\nFINDING|\Z)'
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if not match:
                continue

            verdict_str = match.group(1).lower().strip()
            reason = match.group(2).strip()

            if verdict_str == "confirm":
                self.log(f"  [{finding.id}] LLM CONFIRMED at {finding.severity.value}", style="green")
                continue

            if verdict_str == "reject":
                verdict = C4Verdict(action="reject", reason=f"LLM judge: {reason}", rule_name="llm_verify")
                self._apply_verdict(finding, verdict)
                continue

            new_sev = sev_map.get(verdict_str)
            if new_sev:
                verdict = C4Verdict(
                    action="downgrade",
                    max_severity=new_sev,
                    reason=f"LLM judge: {reason}",
                    rule_name="llm_verify",
                )
                self._apply_verdict(finding, verdict)

    # ── Main Entry Point ─────────────────────────────────────────────────

    async def apply(self, findings: list[Finding], state: AuditState) -> list[Finding]:
        """Apply C4 rules to findings. Returns filtered/adjusted list."""
        if not findings:
            return findings

        self.log(f"Applying C4 severity gate to {len(findings)} findings...", style="bold magenta")

        # Phase 1: Deterministic rules (free)
        for finding in findings:
            if finding.false_positive:
                continue
            for rule in self.RULES:
                verdict = rule.check(finding, state)
                if verdict:
                    self._apply_verdict(finding, verdict)
                    break  # First matching rule wins

        # Phase 2: LLM batch verification for remaining M/H+
        mh_findings = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            and not f.false_positive
        ]
        if mh_findings:
            await self._llm_verify_batch(mh_findings, state)

        # Filter out rejected findings
        result = [f for f in findings if not f.false_positive]

        self.print_summary(findings, result)
        return result

    def print_summary(self, before: list[Finding], after: list[Finding]) -> None:
        """Print C4 gate summary."""
        if not self.verdicts:
            self.log("No C4 rules triggered", style="dim")
            return

        console.print("\n[bold magenta]=== C4 SEVERITY GATE RESULTS ===[/bold magenta]\n")

        table = Table(title="C4 Rule Applications")
        table.add_column("Finding", style="cyan", max_width=20)
        table.add_column("Rule")
        table.add_column("Action")
        table.add_column("Reason", max_width=50)

        for finding_id, verdict in self.verdicts:
            style = {"reject": "red", "cap": "yellow", "downgrade": "yellow"}.get(verdict.action, "white")
            action = verdict.action.upper()
            if verdict.max_severity:
                action += f" -> {verdict.max_severity.value}"
            table.add_row(
                finding_id[:20],
                verdict.rule_name,
                f"[{style}]{action}[/{style}]",
                verdict.reason[:50],
            )

        console.print(table)

        rejected = sum(1 for _, v in self.verdicts if v.action == "reject")
        capped = sum(1 for _, v in self.verdicts if v.action in ("cap", "downgrade"))
        console.print(f"\n{rejected} rejected, {capped} downgraded/capped, {len(after)}/{len(before)} findings remain")
