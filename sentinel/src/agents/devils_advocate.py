"""
Devil's Advocate Agent - Challenge and validate findings.

Before submitting findings, challenge them:
- Is this ACTUALLY exploitable?
- What preconditions are needed?
- Is the severity inflated?
- Would a judge accept this?

This agent:
1. Critically examines each finding
2. Tries to find why it's NOT exploitable
3. Adjusts confidence and severity
4. Filters out false positives
"""

import asyncio
from dataclasses import dataclass
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


@dataclass
class DevilsAdvocateConfig:
    """Configuration for the Devil's Advocate."""
    ultrathink: bool = True
    thinking_budget: int = 16000
    strict_mode: bool = False  # More aggressive rejection
    min_confidence_threshold: float = 0.3
    severity_adjustment: bool = True
    filter_low_confidence: bool = True


class DevilsAdvocateAgent(HunterAgent):
    """
    Challenge every finding to validate quality.

    Analysis:
    1. Is the attack path feasible?
    2. What preconditions are needed?
    3. Is severity correctly assessed?
    4. Would a judge/reviewer accept this?
    5. Are there mitigating factors?

    Goal: Reduce false positives and improve finding quality.
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "DevilsAdvocate"
    description = "Critically challenge and validate findings"

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
        return """You are a skeptical security reviewer and judge.

Your job is to CHALLENGE every finding and try to PROVE IT WRONG.

Ask these questions:
1. **Is it ACTUALLY exploitable?**
   - Can an attacker really execute this?
   - What specific preconditions are needed?
   - Are those preconditions realistic?

2. **Is the attack path FEASIBLE?**
   - Gas costs vs profit?
   - Time constraints?
   - Required capital/flash loans?
   - Competition from other attackers?

3. **Is the severity CORRECT?**
   - Is the impact overstated?
   - Are there mitigating factors?
   - Compare to similar historical issues

4. **Would a JUDGE accept this?**
   - Is the description clear?
   - Is there sufficient evidence?
   - Are edge cases considered?
   - Is the PoC convincing?

5. **What DEFENDS this finding?**
   - Are there access controls?
   - Time locks or delays?
   - Rate limits?
   - Other safeguards?

Be HARSH but FAIR:
- Look for reasons to REJECT
- But acknowledge when findings are solid
- Don't let good findings through with inflated severity
- Don't reject valid findings out of excessive skepticism

Severity Guidelines (for calibration):
- CRITICAL: Direct, unconditional loss of all funds
- HIGH: Conditional loss of funds, requires specific conditions
- MEDIUM: Limited loss, temporary issues, griefing
- LOW: Best practices, unlikely scenarios

When adjusting:
- Most findings are initially overrated
- If preconditions are unlikely, downgrade
- If impact is limited, downgrade
- If exploit cost > profit, consider rejecting"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[Finding]:
        """Challenge all findings and return validated ones."""
        findings: list[Finding] = kwargs.get("findings", [])

        if not findings:
            self.log("No findings to challenge", style="yellow")
            return []

        self.log(f"Challenging {len(findings)} findings...", style="bold magenta")

        validated_findings = []

        for finding in findings:
            self.log(f"Challenging: {finding.title[:50]}...", style="cyan")

            report = await self.challenge_finding(finding)
            self.challenge_reports.append(report)

            if report.result == ChallengeResult.REJECTED:
                self.log(f"  [REJECTED] False positive", style="red")
                continue

            if report.result == ChallengeResult.DOWNGRADED:
                self.log(f"  [DOWNGRADED] {report.original_severity.value} -> {report.adjusted_severity.value}", style="yellow")
                finding.severity = report.adjusted_severity

            finding.confidence = report.adjusted_confidence

            # Filter low confidence
            if self.config.filter_low_confidence:
                if finding.confidence < self.config.min_confidence_threshold:
                    self.log(f"  [FILTERED] Confidence too low: {finding.confidence:.0%}", style="dim")
                    continue

            validated_findings.append(finding)
            self.log(f"  [VALIDATED] Confidence: {finding.confidence:.0%}", style="green")

        self.print_summary()
        return validated_findings

    async def challenge_finding(self, finding: Finding) -> ChallengeReport:
        """Challenge a single finding."""
        prompt = f"""Challenge this security finding. Try to prove it's NOT valid or overrated.

**Finding:**
- ID: {finding.id}
- Title: {finding.title}
- Severity: {finding.severity.value}
- Type: {finding.vulnerability_type.value}
- Contract: {finding.contract}
- Confidence: {finding.confidence:.0%}

**Description:**
{finding.description}

**Root Cause:**
{finding.root_cause or "Not specified"}

**Impact:**
{finding.impact or "Not specified"}

**Recommendation:**
{finding.recommendation or "Not specified"}

---

**YOUR CHALLENGE:**

1. **Attack Feasibility Analysis**
   - List ALL preconditions needed
   - Assess likelihood of each precondition
   - Calculate: Is it profitable after gas/fees?

2. **Mitigation Search**
   - Are there access controls we missed?
   - Time locks, rate limits, pauses?
   - Other safeguards in the code?

3. **Severity Calibration**
   - Compare to similar historical issues
   - What severity would Code4rena/Sherlock assign?
   - Is impact quantified correctly?

4. **Counter-Arguments**
   - Why might this NOT be exploitable?
   - What assumptions could be wrong?
   - Edge cases that break the attack?

5. **Defense (if valid)**
   - What makes this finding solid?
   - Evidence that supports it?

**Final Verdict:**
- VALIDATED: Finding is solid as-is
- ADJUSTED: Valid but needs confidence/details adjusted
- DOWNGRADED: Valid but severity should be lower (specify new severity)
- REJECTED: False positive (explain why)

Format:
VERDICT: [VALIDATED/ADJUSTED/DOWNGRADED/REJECTED]
ADJUSTED_SEVERITY: [if DOWNGRADED]
ADJUSTED_CONFIDENCE: [0-100]%
CHALLENGES:
- [Challenge 1]
- [Challenge 2]
DEFENSES:
- [Defense 1]
- [Defense 2]
JUDGE_PERSPECTIVE: [What would a contest judge say?]
RECOMMENDATION: [What should be done with this finding?]
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

        return self._parse_challenge_report(response.content, finding)

    def _parse_challenge_report(self, response: str, finding: Finding) -> ChallengeReport:
        """Parse challenge report from LLM response."""
        import re

        # Extract verdict
        verdict_match = re.search(r'VERDICT:\s*(\w+)', response, re.IGNORECASE)
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
        if result == ChallengeResult.DOWNGRADED:
            sev_match = re.search(r'ADJUSTED_SEVERITY:\s*(\w+)', response, re.IGNORECASE)
            if sev_match:
                sev_str = sev_match.group(1).lower()
                sev_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "informational": Severity.INFORMATIONAL,
                }
                adjusted_severity = sev_map.get(sev_str, finding.severity)

        # Extract adjusted confidence
        conf_match = re.search(r'ADJUSTED_CONFIDENCE:\s*(\d+)', response)
        adjusted_confidence = int(conf_match.group(1)) / 100 if conf_match else finding.confidence

        # If rejected, set confidence very low
        if result == ChallengeResult.REJECTED:
            adjusted_confidence = 0.1

        # Extract challenges
        challenges = []
        challenges_match = re.search(r'CHALLENGES:\s*\n((?:-\s*.+\n?)+)', response)
        if challenges_match:
            challenges = [c.strip().lstrip('- ') for c in challenges_match.group(1).split('\n') if c.strip()]

        # Extract defenses
        defenses = []
        defenses_match = re.search(r'DEFENSES:\s*\n((?:-\s*.+\n?)+)', response)
        if defenses_match:
            defenses = [d.strip().lstrip('- ') for d in defenses_match.group(1).split('\n') if d.strip()]

        # Extract judge perspective
        judge_match = re.search(r'JUDGE_PERSPECTIVE:\s*(.+?)(?=RECOMMENDATION:|$)', response, re.DOTALL)
        judge_perspective = judge_match.group(1).strip() if judge_match else ""

        # Extract recommendation
        rec_match = re.search(r'RECOMMENDATION:\s*(.+?)$', response, re.DOTALL)
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
        )

    def print_summary(self) -> None:
        """Print challenge summary."""
        if not self.challenge_reports:
            return

        console.print("\n[bold magenta]═══ DEVIL'S ADVOCATE RESULTS ═══[/bold magenta]\n")

        # Count by result
        result_counts = {}
        for report in self.challenge_reports:
            result = report.result.value
            result_counts[result] = result_counts.get(result, 0) + 1

        summary_table = Table(title="Challenge Results")
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

        # Detailed results
        details_table = Table(title="Finding Challenges")
        details_table.add_column("ID", style="cyan", max_width=20)
        details_table.add_column("Result")
        details_table.add_column("Severity Change")
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
                sev_change = f"{report.original_severity.value} → {report.adjusted_severity.value}"

            conf_change = f"{report.original_confidence:.0%} → {report.adjusted_confidence:.0%}"

            details_table.add_row(
                report.finding_id[:20],
                f"[{result_style}]{report.result.value.upper()}[/{result_style}]",
                sev_change,
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
