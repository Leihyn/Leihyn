"""
Severity Calibrator - Recalibrates finding severity against actual code protections.

Sentinel's #1 problem: severity inflation. The SlippageHunter finds amountOutMin=0
and reports CRITICAL, ignoring that the contract has an oracle wrapper that bounds
extraction to 5%. A judge would rate this QA, not Critical.

This agent:
1. For each finding, reads the actual contract source
2. Asks: "Does the contract have DESIGNED PROTECTION for this exact issue?"
3. If yes: downgrade severity based on how effective the protection is
4. Deduplicates by root cause (not just title matching)
5. Produces calibrated findings that match what a C4/Sherlock judge would accept

Runs BEFORE DevilsAdvocate (which handles feasibility), AFTER hunters (which find raw issues).
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType

console = Console()


@dataclass
class CalibrationResult:
    """Result of calibrating a finding's severity."""
    finding_id: str
    original_severity: Severity
    calibrated_severity: Severity
    protections_found: list[str]
    protection_effectiveness: str  # "none", "partial", "full"
    reasoning: str
    root_cause_key: str  # For deduplication


@dataclass
class SeverityCalibratorConfig:
    """Configuration for severity calibration."""
    ultrathink: bool = True
    thinking_budget: int = 12000
    # Check actual source for protections
    read_source: bool = True
    # Aggressive dedup by root cause
    deduplicate_root_cause: bool = True
    # Maximum severity if protection exists
    max_severity_with_protection: Severity = Severity.LOW


class SeverityCalibratorAgent(HunterAgent):
    """
    Recalibrates finding severity by checking actual code protections.

    The key question for each finding:
    "Does the contract have DESIGNED PROTECTION that mitigates this issue?"

    If yes -> downgrade. The finding becomes informational/QA.
    If partial -> adjust. The finding stays but at correct severity.
    If no -> keep. The finding is legitimate at reported severity.
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "SeverityCalibrator"
    description = "Recalibrates finding severity against actual code protections"

    def __init__(
        self,
        state: AuditState,
        config: Optional[SeverityCalibratorConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or SeverityCalibratorConfig()
        self.calibration_results: list[CalibrationResult] = []

    @property
    def system_prompt(self) -> str:
        return """You are a Code4rena / Sherlock judge calibrating finding severity.

Your job: determine if the REPORTED vulnerability is actually mitigated by
EXISTING PROTECTIONS in the code. Sentinel's hunters find pattern matches
(e.g., "amountOutMin=0") but miss that the same contract has an oracle wrapper
that validates prices before AND after the swap.

## Calibration Framework

### Step 1: Identify the Claimed Vulnerability
What exactly does the finding claim is wrong?

### Step 2: Search for Designed Protections
Look in the ACTUAL SOURCE for:
- Wrapper functions that add validation (pre/post checks)
- Oracle price bounds
- Access control that limits who can trigger the vulnerable path
- Rate limits, timelocks, or cooldowns
- Reentrancy guards
- Slippage parameters passed at a higher level

### Step 3: Assess Protection Effectiveness
- FULL: The protection completely prevents exploitation (-> Informational/QA)
- PARTIAL: The protection limits but doesn't prevent exploitation (-> one level lower)
- NONE: No protection exists (-> keep original severity)

### Step 4: Apply C4/Sherlock Severity Standards
- CRITICAL: Unconditional loss of funds, no preconditions, automated exploit
- HIGH: Conditional loss of funds, requires specific (but realistic) conditions
- MEDIUM: Limited loss, significant preconditions, or partial mitigation
- LOW: Best practice violation, unlikely scenario, or well-mitigated
- QA: Code quality, informational, "defense in depth" suggestions

### Key Patterns That Reduce Severity

1. "amountOutMin=0 BUT oracle validates price" -> QA (defense in depth)
2. "Missing access control BUT function is only callable by owner" -> Low
3. "Reentrancy possible BUT follows CEI pattern" -> Low/QA
4. "Flash loan attack BUT protocol has cooldown" -> Medium (not Critical)
5. "Oracle manipulation BUT TWAP with sufficient window" -> Low/Medium
6. "Centralization risk BUT behind timelock + multisig" -> QA

### Root Cause Deduplication
Multiple findings with the SAME root cause should be merged:
- Same vulnerable pattern in different functions -> ONE finding
- Same missing protection across V2/V3 paths -> ONE finding
- Access control findings on related admin functions -> ONE finding"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Calibrate severity of all findings."""
        findings: list[Finding] = kwargs.get("findings", [])

        if not findings:
            self.log("No findings to calibrate", style="yellow")
            return []

        self.log(f"Calibrating severity for {len(findings)} findings...", style="bold magenta")

        # Phase 1: Calibrate each finding against source code
        calibrated = []
        for finding in findings:
            self.log(f"Calibrating: {finding.title[:50]}...", style="cyan")
            result = await self._calibrate_finding(finding)
            self.calibration_results.append(result)

            if result.calibrated_severity != result.original_severity:
                self.log(
                    f"  [{result.original_severity.value} -> {result.calibrated_severity.value}] "
                    f"{result.protection_effectiveness} protection",
                    style="yellow",
                )
                finding.severity = result.calibrated_severity
            else:
                self.log(f"  [KEPT] {finding.severity.value}", style="green")

            calibrated.append(finding)

        # Phase 2: Deduplicate by root cause
        if self.config.deduplicate_root_cause:
            before = len(calibrated)
            calibrated = self._deduplicate_by_root_cause(calibrated)
            after = len(calibrated)
            if before != after:
                self.log(f"Root cause dedup: {before} -> {after} findings ({before - after} merged)", style="yellow")

        self.print_summary()
        return calibrated

    async def _calibrate_finding(self, finding: Finding) -> CalibrationResult:
        """Calibrate a single finding's severity against source code."""
        # Get relevant source code
        source_context = self._get_source_context(finding)

        prompt = f"""Calibrate this finding's severity by checking for EXISTING PROTECTIONS in the source code.

**Finding:**
- ID: {finding.id}
- Title: {finding.title}
- Reported Severity: {finding.severity.value}
- Type: {finding.vulnerability_type.value}
- Contract: {finding.contract}
- Function: {finding.function or "N/A"}

**Description:**
{finding.description[:2000]}

**Impact:**
{finding.impact or "Not specified"}

**Source Code Context:**
{source_context}

---

**YOUR CALIBRATION:**

1. What is the EXACT vulnerability claimed?
2. Search the source code above for ANY designed protection:
   - Wrapper functions with pre/post validation?
   - Oracle price checks?
   - Access controls?
   - Rate limits, timelocks?
   - Slippage parameters at a higher level?
3. How effective is the protection?
4. What severity would a C4/Sherlock JUDGE assign?

Format:
PROTECTIONS_FOUND:
- [Protection 1 with line reference]
- [Protection 2 with line reference]
EFFECTIVENESS: [FULL/PARTIAL/NONE]
CALIBRATED_SEVERITY: [Critical/High/Medium/Low/Informational]
ROOT_CAUSE: [One-line description of the fundamental issue]
REASONING: [Why this severity is correct]
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

        return self._parse_calibration(response.content, finding)

    def _get_source_context(self, finding: Finding) -> str:
        """Get source code context for a finding."""
        if not self.config.read_source:
            return "Source reading disabled."

        # Find the contract
        contract_name = finding.contract.split(",")[0].strip()  # Handle "ContractA, ContractB"

        for contract in self.state.contracts:
            if contract.name == contract_name or contract_name in contract.name:
                source = contract.source
                if len(source) > 10000:
                    # If source is too long, try to extract relevant section
                    if finding.function:
                        # Find the function and surrounding context
                        func_pattern = rf'function\s+{re.escape(finding.function)}\s*\('
                        match = re.search(func_pattern, source)
                        if match:
                            start = max(0, match.start() - 500)
                            end = min(len(source), match.start() + 3000)
                            return f"```solidity\n// ... (showing context around {finding.function})\n{source[start:end]}\n// ...\n```"
                    # Fall back to first 10K
                    return f"```solidity\n{source[:10000]}\n// ... [truncated]\n```"
                return f"```solidity\n{source}\n```"

        return "Contract source not found in recon data."

    def _parse_calibration(self, response: str, finding: Finding) -> CalibrationResult:
        """Parse calibration result from LLM response."""
        # Extract protections
        protections = []
        prot_match = re.search(r'PROTECTIONS_FOUND:\s*\n((?:-\s*.+\n?)+)', response)
        if prot_match:
            protections = [
                p.strip().lstrip("- ")
                for p in prot_match.group(1).split("\n")
                if p.strip()
            ]

        # Extract effectiveness
        eff_match = re.search(r'EFFECTIVENESS:\s*(\w+)', response, re.IGNORECASE)
        effectiveness = eff_match.group(1).lower() if eff_match else "none"

        # Extract calibrated severity
        sev_match = re.search(r'CALIBRATED_SEVERITY:\s*(\w+)', response, re.IGNORECASE)
        sev_str = sev_match.group(1).lower() if sev_match else finding.severity.value.lower()

        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
            "qa": Severity.INFORMATIONAL,
            "gas": Severity.GAS,
        }
        calibrated_severity = sev_map.get(sev_str, finding.severity)

        # If protection is FULL, cap at max_severity_with_protection
        if effectiveness == "full":
            severity_order = [
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFORMATIONAL, Severity.GAS,
            ]
            max_idx = severity_order.index(self.config.max_severity_with_protection)
            cal_idx = severity_order.index(calibrated_severity)
            if cal_idx < max_idx:
                calibrated_severity = self.config.max_severity_with_protection

        # Extract root cause
        root_match = re.search(r'ROOT_CAUSE:\s*(.+?)(?=\n|REASONING:|$)', response, re.DOTALL)
        root_cause = root_match.group(1).strip() if root_match else finding.title

        # Extract reasoning
        reason_match = re.search(r'REASONING:\s*(.+?)$', response, re.DOTALL)
        reasoning = reason_match.group(1).strip()[:500] if reason_match else ""

        return CalibrationResult(
            finding_id=finding.id,
            original_severity=finding.severity,
            calibrated_severity=calibrated_severity,
            protections_found=protections[:5],
            protection_effectiveness=effectiveness,
            reasoning=reasoning,
            root_cause_key=root_cause[:100],
        )

    def _deduplicate_by_root_cause(self, findings: list[Finding]) -> list[Finding]:
        """Merge findings with the same root cause."""
        from collections import defaultdict

        # Build root cause keys from calibration results
        root_cause_map = {}
        for result in self.calibration_results:
            root_cause_map[result.finding_id] = result.root_cause_key

        # Group findings by root cause
        groups = defaultdict(list)
        for finding in findings:
            key = root_cause_map.get(finding.id, finding.title[:50])
            # Normalize the key for better matching
            normalized = key.lower().strip()
            # Remove common prefixes
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
        """Print calibration summary."""
        if not self.calibration_results:
            return

        console.print("\n[bold magenta]=== SEVERITY CALIBRATION RESULTS ===[/bold magenta]\n")

        table = Table(title="Calibration Results")
        table.add_column("ID", style="cyan", max_width=15)
        table.add_column("Original")
        table.add_column("Calibrated")
        table.add_column("Protection")
        table.add_column("Reason", max_width=40)

        for result in self.calibration_results:
            changed = result.original_severity != result.calibrated_severity
            style = "yellow" if changed else "dim"

            table.add_row(
                result.finding_id[:15],
                result.original_severity.value,
                f"[{style}]{result.calibrated_severity.value}[/{style}]",
                result.protection_effectiveness,
                result.reasoning[:40],
            )

        console.print(table)

        # Count changes
        downgraded = sum(
            1 for r in self.calibration_results
            if r.calibrated_severity != r.original_severity
        )
        console.print(f"\n{downgraded}/{len(self.calibration_results)} findings had severity adjusted")
