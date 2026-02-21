"""
Devil's Advocate Agent - Unified validation pipeline.

Merges severity calibration (check designed protections) and feasibility
challenge (is this actually exploitable?) into a single pass. Processes
findings in batches of 3-5 to minimize API calls.

For each finding:
1. Read actual contract source to check for DESIGNED PROTECTIONS
2. Calibrate severity: if protection is FULL, cap at Low
3. Challenge feasibility: is this actually exploitable?
4. Deduplicate by root cause across the batch
5. Return validated, correctly-severed findings

One ultrathink call per batch = 3-5x fewer API calls than one-per-finding.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType

console = Console()


class ChallengeResult(Enum):
    """Result of challenging a finding."""
    VALIDATED = "validated"           # Finding is solid
    ADJUSTED = "adjusted"             # Finding valid but needs adjustment
    DOWNGRADED = "downgraded"         # Severity was too high
    REJECTED = "rejected"             # False positive
    NEEDS_CLARIFICATION = "needs_clarification"  # Needs more investigation


@dataclass
class ChallengeReport:
    """Report from challenging a finding."""
    finding_id: str
    result: ChallengeResult
    original_severity: Severity
    adjusted_severity: Optional[Severity]
    original_confidence: float
    adjusted_confidence: float
    challenges: list[str]
    defenses: list[str]
    judge_perspective: str
    recommendation: str
    protections_found: list[str] = field(default_factory=list)
    protection_effectiveness: str = "none"
    root_cause_key: str = ""


@dataclass
class DevilsAdvocateConfig:
    """Configuration for the Devil's Advocate."""
    ultrathink: bool = True
    thinking_budget: int = 16000
    strict_mode: bool = False  # More aggressive rejection
    min_confidence_threshold: float = 0.3
    severity_adjustment: bool = True
    filter_low_confidence: bool = True
    # Severity calibration settings (merged from SeverityCalibrator)
    read_source: bool = True
    deduplicate_root_cause: bool = True
    max_severity_with_protection: Severity = Severity.LOW
    # Batch settings
    batch_size: int = 4


class DevilsAdvocateAgent(HunterAgent):
    """
    Unified validation: severity calibration + feasibility challenge + dedup.

    Processes findings in batches of 3-5 per LLM call:
    1. For each finding, checks actual source for designed protections
    2. Calibrates severity based on protection effectiveness
    3. Challenges feasibility (is the attack path realistic?)
    4. Deduplicates findings with the same root cause
    5. Filters low-confidence false positives

    One ultrathink call per batch instead of one per finding.
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "DevilsAdvocate"
    description = "Validate findings: calibrate severity, challenge feasibility, deduplicate"

    def __init__(
        self,
        state: AuditState,
        config: Optional[DevilsAdvocateConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or DevilsAdvocateConfig()
        self.challenge_reports: list[ChallengeReport] = []

    @property
    def system_prompt(self) -> str:
        return """You are a Code4rena / Sherlock judge performing final validation on audit findings.

You do TWO things for each finding:

## 1. SEVERITY CALIBRATION (check designed protections)

Search the source code for EXISTING PROTECTIONS that mitigate the reported issue:
- Wrapper functions with pre/post validation
- Oracle price bounds or TWAP checks
- Access controls that limit who can trigger the path
- Rate limits, timelocks, cooldowns
- Reentrancy guards
- Slippage parameters set at a higher level
- Call-chain context (check "Call Chain Context" section in the finding description
  for protections in CALLING functions, not just the function itself)

Protection effectiveness:
- FULL: Protection completely prevents exploitation -> cap at Low/QA
- PARTIAL: Protection limits but doesn't prevent exploitation -> one level lower
- NONE: No protection exists -> keep original severity

Key patterns that REDUCE severity:
- "amountOutMin=0 BUT oracle validates price" -> QA (defense in depth)
- "Missing access control BUT function only callable by owner" -> Low
- "Reentrancy possible BUT follows CEI pattern" -> Low/QA
- "Flash loan attack BUT protocol has cooldown" -> Medium (not Critical)
- "Oracle manipulation BUT TWAP with sufficient window" -> Low/Medium

## 2. FEASIBILITY CHALLENGE (try to prove it wrong)

Ask:
- Is the attack path ACTUALLY feasible? Gas costs vs profit?
- What specific preconditions are needed? Are they realistic?
- Would a contest judge accept this?
- Are there mitigating factors beyond code protections?

## 3. ROOT CAUSE IDENTIFICATION

For deduplication: identify the ONE fundamental root cause. Multiple findings
about the same root cause (e.g., "amountOutMin=0" in V2 and V3 paths) should
share the same ROOT_CAUSE key.

## C4 Severity Definitions (Exact Rules)

- **HIGH**: Assets can be stolen/lost/compromised directly (or indirectly if
  there is a valid attack path that does not have hand-wavy hypotheticals).
  There must be a concrete, realistic attack path with direct asset risk.

- **MEDIUM**: Assets not at direct risk, but the function of the protocol or
  its availability could be impacted, or leak value with a hypothetical attack
  path with stated assumptions.

- **LOW/QA**: Anything that is not a risk to assets or protocol function.
  Includes: best practices, code style, gas optimizations, informational.

## C4 Mandatory Rules

- **Admin roles are TRUSTED**: All privileged roles (owner, admin, governance,
  multisig) are assumed trustworthy. Findings that require admin to misbehave,
  misconfigure, or act maliciously are QA, NOT Medium/High. "Reckless admin
  mistakes" (e.g., setting wrong value) are also QA.

- **Fee-on-transfer / rebasing tokens**: OUT OF SCOPE unless the contest
  explicitly includes them. Do not accept findings about non-standard token
  behavior unless documentation says these tokens are supported.

- **Dust amounts from rounding**: Precision loss / rounding errors with no
  proof of material, cumulative loss are QA/Low, not Medium/High.

- **No hand-wavy hypotheticals**: Findings at M/H MUST have a concrete
  attack path. "An attacker could theoretically..." without specifics is
  insufficient.

- **Centralization risks**: Admin can rug, single point of failure, missing
  timelock — these are QA/informational, not M/H.

Be HARSH but FAIR. Most findings are initially overrated."""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Validate all findings in batches."""
        findings: list[Finding] = kwargs.get("findings", [])

        if not findings:
            self.log("No findings to validate", style="yellow")
            return []

        self.log(f"Validating {len(findings)} findings (batch size={self.config.batch_size})...", style="bold magenta")

        # Split findings into batches
        batches = []
        for i in range(0, len(findings), self.config.batch_size):
            batches.append(findings[i:i + self.config.batch_size])

        self.log(f"Processing {len(batches)} batch(es)...", style="cyan")

        validated_findings = []

        for batch_idx, batch in enumerate(batches):
            self.log(f"Batch {batch_idx + 1}/{len(batches)} ({len(batch)} findings)...", style="cyan")

            reports = await self._challenge_batch(batch)

            for finding, report in zip(batch, reports):
                self.challenge_reports.append(report)

                if report.result == ChallengeResult.REJECTED:
                    self.log(f"  [{finding.id}] REJECTED - False positive", style="red")
                    continue

                if report.result == ChallengeResult.DOWNGRADED:
                    self.log(
                        f"  [{finding.id}] DOWNGRADED {report.original_severity.value} -> {report.adjusted_severity.value}"
                        f" (protection: {report.protection_effectiveness})",
                        style="yellow",
                    )
                    finding.severity = report.adjusted_severity

                finding.confidence = report.adjusted_confidence

                # Filter low confidence
                if self.config.filter_low_confidence:
                    if finding.confidence < self.config.min_confidence_threshold:
                        self.log(f"  [{finding.id}] FILTERED - Confidence too low: {finding.confidence:.0%}", style="dim")
                        continue

                validated_findings.append(finding)
                self.log(f"  [{finding.id}] VALIDATED - Confidence: {finding.confidence:.0%}", style="green")

        # Deduplicate by root cause
        if self.config.deduplicate_root_cause:
            before = len(validated_findings)
            validated_findings = self._deduplicate_by_root_cause(validated_findings)
            after = len(validated_findings)
            if before != after:
                self.log(f"Root cause dedup: {before} -> {after} findings ({before - after} merged)", style="yellow")

        self.print_summary()
        return validated_findings

    async def _challenge_batch(self, batch: list[Finding]) -> list[ChallengeReport]:
        """Challenge a batch of findings in a single LLM call."""
        # Build the batch prompt
        finding_sections = []
        for i, finding in enumerate(batch):
            source_context = self._get_source_context(finding) if self.config.read_source else "Source reading disabled."

            finding_sections.append(f"""--- FINDING {i + 1} ---
ID: {finding.id}
Title: {finding.title}
Severity: {finding.severity.value}
Type: {finding.vulnerability_type.value}
Contract: {finding.contract}
Function: {finding.function or "N/A"}
Confidence: {finding.confidence:.0%}

Description:
{finding.description[:1500]}

Impact: {finding.impact or "Not specified"}
Root Cause: {finding.root_cause or "Not specified"}
Recommendation: {finding.recommendation or "Not specified"}

Source Code Context:
{source_context[:3000]}
""")

        prompt = f"""Validate these {len(batch)} findings. For EACH finding, perform severity calibration (check protections) AND feasibility challenge.

{chr(10).join(finding_sections)}

---

For EACH finding, provide your analysis in this EXACT format (repeat for each finding):

=== FINDING [ID] ===
PROTECTIONS_FOUND:
- [Protection 1 with code reference]
- [Protection 2]
EFFECTIVENESS: [FULL/PARTIAL/NONE]
VERDICT: [VALIDATED/ADJUSTED/DOWNGRADED/REJECTED]
ADJUSTED_SEVERITY: [Critical/High/Medium/Low/Informational] (required if DOWNGRADED)
ADJUSTED_CONFIDENCE: [0-100]%
ROOT_CAUSE: [One-line root cause for dedup grouping]
CHALLENGES:
- [Why this might NOT be exploitable]
DEFENSES:
- [Why this finding IS valid]
JUDGE_PERSPECTIVE: [What would a C4/Sherlock judge say?]
RECOMMENDATION: [Keep/downgrade/reject and why]
=== END ===
"""

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

        return self._parse_batch_response(response.content, batch)

    def _get_source_context(self, finding: Finding) -> str:
        """Get source code context for a finding."""
        contract_name = finding.contract.split(",")[0].strip()

        for contract in self.state.contracts:
            if contract.name == contract_name or contract_name in contract.name:
                source = contract.source
                if len(source) > 6000:
                    # Extract relevant section around the function
                    if finding.function:
                        func_pattern = rf'function\s+{re.escape(finding.function)}\s*\('
                        match = re.search(func_pattern, source)
                        if match:
                            start = max(0, match.start() - 500)
                            end = min(len(source), match.start() + 2500)
                            return f"```solidity\n// ... (around {finding.function})\n{source[start:end]}\n// ...\n```"
                    return f"```solidity\n{source[:6000]}\n// ... [truncated]\n```"
                return f"```solidity\n{source}\n```"

        return "Contract source not found in recon data."

    def _parse_batch_response(self, response: str, batch: list[Finding]) -> list[ChallengeReport]:
        """Parse batch response into individual challenge reports."""
        reports = []

        # Split response by finding sections
        # Try to match each finding by its ID
        for finding in batch:
            # Find the section for this finding
            section = self._extract_finding_section(response, finding.id)
            if section:
                reports.append(self._parse_single_report(section, finding))
            else:
                # Fallback: if we can't find the section, create a default ADJUSTED report
                self.log(f"  Warning: Could not parse response for {finding.id}, keeping as-is", style="dim")
                reports.append(ChallengeReport(
                    finding_id=finding.id,
                    result=ChallengeResult.ADJUSTED,
                    original_severity=finding.severity,
                    adjusted_severity=None,
                    original_confidence=finding.confidence,
                    adjusted_confidence=finding.confidence * 0.9,
                    challenges=[],
                    defenses=[],
                    judge_perspective="Could not parse batch response for this finding",
                    recommendation="Manual review recommended",
                    protections_found=[],
                    protection_effectiveness="unknown",
                    root_cause_key=finding.title[:50],
                ))

        return reports

    def _extract_finding_section(self, response: str, finding_id: str) -> Optional[str]:
        """Extract the section of the response that corresponds to a specific finding."""
        # Try exact ID match first
        pattern = rf'===\s*FINDING\s+{re.escape(finding_id)}\s*===(.*?)(?====\s*(?:FINDING|END)\s*===|$)'
        match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1)

        # Try matching by finding ID appearing anywhere in a section
        pattern = rf'{re.escape(finding_id)}.*?(?====\s*(?:FINDING|END)\s*===|$)'
        match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(0)

        return None

    def _parse_single_report(self, section: str, finding: Finding) -> ChallengeReport:
        """Parse a single finding's challenge report from its section of the response."""
        # Extract protections
        protections = []
        prot_match = re.search(r'PROTECTIONS_FOUND:\s*\n((?:-\s*.+\n?)+)', section)
        if prot_match:
            protections = [
                p.strip().lstrip("- ")
                for p in prot_match.group(1).split("\n")
                if p.strip()
            ]

        # Extract effectiveness
        eff_match = re.search(r'EFFECTIVENESS:\s*(\w+)', section, re.IGNORECASE)
        effectiveness = eff_match.group(1).lower() if eff_match else "none"

        # Extract verdict
        verdict_match = re.search(r'VERDICT:\s*(\w+)', section, re.IGNORECASE)
        verdict_str = verdict_match.group(1).lower() if verdict_match else "adjusted"

        result_map = {
            "validated": ChallengeResult.VALIDATED,
            "adjusted": ChallengeResult.ADJUSTED,
            "downgraded": ChallengeResult.DOWNGRADED,
            "rejected": ChallengeResult.REJECTED,
        }
        result = result_map.get(verdict_str, ChallengeResult.ADJUSTED)

        # Extract adjusted severity
        adjusted_severity = finding.severity
        sev_match = re.search(r'ADJUSTED_SEVERITY:\s*(\w+)', section, re.IGNORECASE)
        if sev_match:
            sev_str = sev_match.group(1).lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "informational": Severity.INFORMATIONAL,
                "qa": Severity.INFORMATIONAL,
                "gas": Severity.GAS,
            }
            adjusted_severity = sev_map.get(sev_str, finding.severity)

        # If protection is FULL, cap at max_severity_with_protection
        if effectiveness == "full":
            severity_order = [
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFORMATIONAL, Severity.GAS,
            ]
            max_idx = severity_order.index(self.config.max_severity_with_protection)
            cal_idx = severity_order.index(adjusted_severity)
            if cal_idx < max_idx:
                adjusted_severity = self.config.max_severity_with_protection
                result = ChallengeResult.DOWNGRADED

        # If downgraded, ensure severity actually changed
        if result == ChallengeResult.DOWNGRADED and adjusted_severity == finding.severity:
            result = ChallengeResult.ADJUSTED

        # Extract adjusted confidence
        conf_match = re.search(r'ADJUSTED_CONFIDENCE:\s*(\d+)', section)
        adjusted_confidence = int(conf_match.group(1)) / 100 if conf_match else finding.confidence

        # If rejected, set confidence very low
        if result == ChallengeResult.REJECTED:
            adjusted_confidence = 0.1

        # Extract root cause
        root_match = re.search(r'ROOT_CAUSE:\s*(.+?)(?=\n|CHALLENGES:|$)', section, re.DOTALL)
        root_cause = root_match.group(1).strip() if root_match else finding.title[:50]

        # Extract challenges
        challenges = []
        challenges_match = re.search(r'CHALLENGES:\s*\n((?:-\s*.+\n?)+)', section)
        if challenges_match:
            challenges = [c.strip().lstrip('- ') for c in challenges_match.group(1).split('\n') if c.strip()]

        # Extract defenses
        defenses = []
        defenses_match = re.search(r'DEFENSES:\s*\n((?:-\s*.+\n?)+)', section)
        if defenses_match:
            defenses = [d.strip().lstrip('- ') for d in defenses_match.group(1).split('\n') if d.strip()]

        # Extract judge perspective
        judge_match = re.search(r'JUDGE_PERSPECTIVE:\s*(.+?)(?=RECOMMENDATION:|$)', section, re.DOTALL)
        judge_perspective = judge_match.group(1).strip() if judge_match else ""

        # Extract recommendation
        rec_match = re.search(r'RECOMMENDATION:\s*(.+?)(?====|$)', section, re.DOTALL)
        recommendation = rec_match.group(1).strip() if rec_match else ""

        return ChallengeReport(
            finding_id=finding.id,
            result=result,
            original_severity=finding.severity,
            adjusted_severity=adjusted_severity if result == ChallengeResult.DOWNGRADED else None,
            original_confidence=finding.confidence,
            adjusted_confidence=adjusted_confidence,
            challenges=challenges[:5],
            defenses=defenses[:5],
            judge_perspective=judge_perspective[:500],
            recommendation=recommendation[:500],
            protections_found=protections[:5],
            protection_effectiveness=effectiveness,
            root_cause_key=root_cause[:100],
        )

    def _deduplicate_by_root_cause(self, findings: list[Finding]) -> list[Finding]:
        """Merge findings with the same root cause."""
        from collections import defaultdict

        # Build root cause keys from challenge reports
        root_cause_map = {}
        for report in self.challenge_reports:
            if report.root_cause_key:
                root_cause_map[report.finding_id] = report.root_cause_key

        # Group findings by normalized root cause
        groups = defaultdict(list)
        for finding in findings:
            key = root_cause_map.get(finding.id, finding.title[:50])
            normalized = key.lower().strip()
            for prefix in ["missing ", "lack of ", "no ", "absent "]:
                if normalized.startswith(prefix):
                    normalized = normalized[len(prefix):]
            groups[normalized].append(finding)

        # Merge groups
        deduped = []
        for key, group in groups.items():
            if len(group) == 1:
                deduped.append(group[0])
                continue

            # Keep the finding with the highest severity as primary
            severity_order = [
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFORMATIONAL, Severity.GAS,
            ]
            group.sort(key=lambda f: severity_order.index(f.severity))
            primary = group[0]

            # Append other locations to description
            other_locations = [
                f"{f.contract}:{f.function or 'N/A'} ({f.id})"
                for f in group[1:]
            ]
            primary.description += f"\n\n**Also affects:** {', '.join(other_locations)}"
            primary.related_findings.extend(f.id for f in group[1:])
            primary.confidence = max(f.confidence for f in group)

            deduped.append(primary)
            self.log(
                f"  Merged {len(group)} findings -> {primary.id} (root cause: {key[:50]})",
                style="dim",
            )

        return deduped

    def print_summary(self) -> None:
        """Print validation summary."""
        if not self.challenge_reports:
            return

        console.print("\n[bold magenta]=== VALIDATION RESULTS (Calibration + Challenge) ===[/bold magenta]\n")

        # Count by result
        result_counts = {}
        for report in self.challenge_reports:
            result = report.result.value
            result_counts[result] = result_counts.get(result, 0) + 1

        summary_table = Table(title="Validation Results")
        summary_table.add_column("Result", style="bold")
        summary_table.add_column("Count", justify="right")

        for result, count in result_counts.items():
            style = {
                "validated": "green",
                "adjusted": "yellow",
                "downgraded": "orange1",
                "rejected": "red",
            }.get(result, "white")
            summary_table.add_row(result.upper(), str(count), style=style)

        console.print(summary_table)

        # Protection effectiveness breakdown
        eff_counts = {}
        for report in self.challenge_reports:
            eff = report.protection_effectiveness
            eff_counts[eff] = eff_counts.get(eff, 0) + 1

        if any(e != "none" and e != "unknown" for e in eff_counts):
            prot_table = Table(title="Protection Effectiveness")
            prot_table.add_column("Level", style="bold")
            prot_table.add_column("Count", justify="right")
            for eff, count in eff_counts.items():
                style = {"full": "green", "partial": "yellow", "none": "red"}.get(eff, "dim")
                prot_table.add_row(eff.upper(), str(count), style=style)
            console.print(prot_table)

        # Detailed results
        details_table = Table(title="Finding Details")
        details_table.add_column("ID", style="cyan", max_width=20)
        details_table.add_column("Result")
        details_table.add_column("Severity Change")
        details_table.add_column("Protection")
        details_table.add_column("Confidence")

        for report in self.challenge_reports:
            result_style = {
                ChallengeResult.VALIDATED: "green",
                ChallengeResult.ADJUSTED: "yellow",
                ChallengeResult.DOWNGRADED: "orange1",
                ChallengeResult.REJECTED: "red",
            }.get(report.result, "white")

            sev_change = ""
            if report.adjusted_severity:
                sev_change = f"{report.original_severity.value} -> {report.adjusted_severity.value}"

            conf_change = f"{report.original_confidence:.0%} -> {report.adjusted_confidence:.0%}"

            details_table.add_row(
                report.finding_id[:20],
                f"[{result_style}]{report.result.value.upper()}[/{result_style}]",
                sev_change,
                report.protection_effectiveness,
                conf_change,
            )

        console.print(details_table)


# Convenience function
async def validate_findings(findings: list[Finding]) -> list[Finding]:
    """Challenge and validate findings."""
    from ..core.types import AuditState
    state = AuditState(project_path="")
    config = DevilsAdvocateConfig()
    agent = DevilsAdvocateAgent(state=state, config=config)
    return await agent.run(findings=findings)
