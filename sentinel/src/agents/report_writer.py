"""
ReportWriter Agent - Generates professional audit and bug bounty reports.

Trained on high-quality findings from Code4rena, Sherlock, and Immunefi.
Uses extended thinking for deep analysis and precise writing.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
import yaml

from rich.console import Console
from rich.panel import Panel

from ..core.agent import BaseAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import AuditState, Finding, Severity, VulnerabilityType

console = Console()

# Load knowledge base
KNOWLEDGE_BASE_PATH = Path(__file__).parent.parent.parent / "knowledge_base" / "reports"


class ReportFormat(Enum):
    """Supported report formats."""
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    CANTINA = "cantina"
    IMMUNEFI = "immunefi"
    MARKDOWN = "markdown"


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    format: ReportFormat = ReportFormat.MARKDOWN
    include_poc: bool = True
    include_gas: bool = True
    include_qa: bool = True
    executive_summary: bool = True
    ultrathink: bool = True  # Use extended thinking for better analysis
    thinking_budget: int = 16000


class ReportWriterAgent(BaseAgent):
    """
    Agent specialized in writing professional security audit reports.

    Features:
    - Trained on real Code4rena, Sherlock, Immunefi findings
    - Uses extended thinking for precise vulnerability descriptions
    - Supports multiple output formats
    - Generates contest-ready submissions
    """

    role = AgentRole.REPORTER
    name = "ReportWriter"
    description = "Generates professional audit and bug bounty reports"

    def __init__(
        self,
        state: AuditState,
        config: Optional[ReportConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or ReportConfig()
        self._load_knowledge_base()

    def _load_knowledge_base(self) -> None:
        """Load report templates and examples from knowledge base."""
        self.templates = {}
        self.examples = {}

        # Load contest formats
        formats_path = KNOWLEDGE_BASE_PATH / "contest_formats.yaml"
        if formats_path.exists():
            with open(formats_path) as f:
                data = yaml.safe_load(f)
                self.templates = data.get("platforms", {})
                self.severity_guidelines = data.get("severity_guidelines", {})

        # Load example findings
        examples_path = KNOWLEDGE_BASE_PATH / "example_findings.yaml"
        if examples_path.exists():
            with open(examples_path) as f:
                self.examples = yaml.safe_load(f)

    @property
    def system_prompt(self) -> str:
        """System prompt trained on professional report writing."""
        examples_section = self._build_examples_section()

        return f"""You are an expert smart contract security auditor and technical writer.
You specialize in writing clear, precise, and actionable security findings for competitive audits and bug bounties.

## Your Writing Style

1. **Clarity First**: Every sentence should add value. No filler words.
2. **Impact-Focused**: Lead with what can go wrong, not technical details.
3. **Evidence-Based**: Always reference specific code, line numbers, and provide working PoCs.
4. **Actionable**: Recommendations must be specific and implementable.

## Severity Guidelines

**Critical/High Indicators:**
- Direct theft of funds without preconditions
- Permanent freezing of funds
- Protocol insolvency
- Complete access control bypass

**Medium Indicators:**
- Theft with conditions (timing, specific state)
- Temporary DoS
- Significant functionality broken
- Oracle manipulation with limited impact

**Low Indicators:**
- Best practice violations
- Minor precision issues
- Missing events
- Code quality

## Report Structure

For each finding, include:
1. **Title**: Clear, specific, includes impact
2. **Summary**: 1-2 sentences max
3. **Vulnerability Detail**: Root cause, code walkthrough, attack path
4. **Impact**: Quantified if possible ($X at risk, Y% of funds)
5. **Proof of Concept**: Working Foundry test or step-by-step
6. **Recommendation**: Specific fix with code

## Example Findings

{examples_section}

## Important Rules

- NEVER exaggerate severity. Downgrade if unsure.
- NEVER submit findings without working PoC for High/Critical.
- ALWAYS reference exact code locations (file.sol#L100-L120).
- Be concise. Judges read hundreds of reports.
- Avoid generic recommendations like "add checks".

## Handling Unknown Vulnerability Types

If you encounter a vulnerability that doesn't match any known category:

1. **Don't panic** - Use the generic template structure
2. **Classify by impact:**
   - Fund loss → High/Critical (use reentrancy/flash loan format)
   - Access bypass → High (use access control format)
   - Data manipulation → Medium/High (use oracle format)
   - Availability impact → Medium (use DoS format)
   - Best practices → Low/Info

3. **Always include:**
   - Root cause (what's broken)
   - Attack vector (how to exploit)
   - Impact (what's at risk, quantified)
   - PoC (working code)
   - Fix (specific, implementable)

4. **When in doubt:** Focus on the security invariant being violated and explain it clearly.
"""

    def _build_examples_section(self) -> str:
        """Build examples section from knowledge base."""
        sections = []

        # Add one example per vulnerability type
        example_types = [
            ("reentrancy_examples", "Reentrancy"),
            ("access_control_examples", "Access Control"),
            ("oracle_manipulation_examples", "Oracle Manipulation"),
            ("flash_loan_examples", "Flash Loan"),
            ("signature_replay_examples", "Signature Replay"),
            ("frontrunning_examples", "Front-running/MEV"),
            ("dos_examples", "Denial of Service"),
            ("business_logic_examples", "Business Logic"),
            ("centralization_examples", "Centralization Risk"),
            ("precision_loss_examples", "Precision Loss"),
        ]

        for key, name in example_types:
            if key in self.examples and self.examples[key]:
                ex = self.examples[key][0]
                sections.append(f"""
### {name} Example
**[{ex['id']}] {ex['title']}**
Severity: {ex['severity']}

{ex['summary']}
""")

        # Add generic template for unknown types
        if "generic_template" in self.examples:
            generic = self.examples["generic_template"]
            sections.append(f"""
### Fallback Template (for any vulnerability type)
{generic.get('structure', '')}

**Principles:**
{chr(10).join('- ' + p for p in generic.get('principles', []))}

**Handling Novel Vulnerabilities:**
{generic.get('adapting_to_unknown_vulns', '')}
""")

        # Add handling guidelines
        if "writing_guidelines" in self.examples:
            guidelines = self.examples["writing_guidelines"]
            if "handling_novel_vulnerabilities" in guidelines:
                sections.append(f"""
### Adapting to Unknown Vulnerability Types
{guidelines['handling_novel_vulnerabilities']}
""")

        return "\n".join(sections) if sections else "No examples loaded."

    def get_tools(self) -> list[Tool]:
        """No tools needed - pure generation."""
        return []

    async def run(self, **kwargs) -> str:
        """Generate the full audit report."""
        self.log("Generating audit report...", style="bold magenta")

        # Generate report based on format
        if self.config.format == ReportFormat.IMMUNEFI:
            report = await self._generate_immunefi_report()
        elif self.config.format == ReportFormat.CODE4RENA:
            report = await self._generate_contest_report("code4rena")
        elif self.config.format == ReportFormat.SHERLOCK:
            report = await self._generate_contest_report("sherlock")
        else:
            report = await self._generate_markdown_report()

        return report

    async def write_finding(
        self,
        finding: Finding,
        format: Optional[ReportFormat] = None,
        include_poc: Optional[bool] = None,
    ) -> str:
        """
        Write a single finding in professional format.

        Uses extended thinking to produce high-quality output.
        """
        format = format or self.config.format
        if include_poc is None:
            include_poc = self.config.include_poc
        template = self._get_finding_template(format)

        poc_section = ""
        if include_poc and finding.poc and finding.poc.code:
            poc_section = f"""
**Proof of Concept:**
```solidity
{finding.poc.code}
```
{"**PoC Output:** " + finding.poc.output[:1000] if finding.poc.output else ""}
"""

        verification_note = ""
        if finding.validated:
            verification_note = "**Status:** VERIFIED (PoC passes)"
        elif finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            verification_note = "**Status:** Unverified - manual review recommended"

        prompt = f"""Write a professional security finding based on this data:

**Finding Data:**
- Title: {finding.title}
- Severity: {finding.severity.value}
- Type: {finding.vulnerability_type.value}
- Contract: {finding.contract}
- Function: {finding.function or 'N/A'}
- Description: {finding.description}
- Impact: {finding.impact}
- Root Cause: {finding.root_cause}
- Recommendation: {finding.recommendation}
- Confidence: {finding.confidence}
{verification_note}
{poc_section}

**Template to Follow:**
{template}

**Instructions:**
1. Rewrite in professional audit report style
2. Ensure severity justification is clear
3. Add specific code references
4. Make recommendation actionable
5. Format for {format.value} submission
{"6. Include the Proof of Concept code in the finding" if include_poc and finding.poc else "6. Do NOT include any PoC section"}
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=self.config.thinking_budget,
                stream=self.verbose,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        return response.content

    async def write_immunefi_submission(
        self,
        finding: Finding,
        program_name: str,
        affected_contracts: list[str],
    ) -> str:
        """
        Write an Immunefi-optimized bug bounty submission.

        Focuses on:
        - Clear impact quantification
        - Working PoC
        - Affected assets
        - Risk breakdown
        """
        prompt = f"""Write an Immunefi bug bounty submission for:

**Program:** {program_name}
**Affected Contracts:** {', '.join(affected_contracts)}

**Finding:**
- Title: {finding.title}
- Severity: {finding.severity.value}
- Type: {finding.vulnerability_type.value}
- Description: {finding.description}
- Impact: {finding.impact}

**Immunefi Submission Requirements:**
1. Bug Description - Clear and specific
2. Impact - Quantified in dollar terms if possible
3. Risk Breakdown - Difficulty, Likelihood, Impact ratings
4. Proof of Concept - Step-by-step reproduction
5. Recommended Fix - Specific mitigation

**Tips for Higher Payouts:**
- Include mainnet fork PoC
- Reference specific contract addresses
- Quantify funds at risk
- Compare to similar past bugs

Write the complete submission:
"""

        response = self.llm.ultrathink(
            prompt=prompt,
            system=self.system_prompt,
            thinking_budget=20000,  # More thinking for bounty submissions
            stream=self.verbose,
        )

        return response.content

    def _get_finding_template(self, format: ReportFormat) -> str:
        """Get the finding template for the specified format."""
        format_key = format.value
        if format_key in self.templates:
            return self.templates[format_key].get("finding_template", "")

        # Default template
        return """
## [{ID}] {Title}

### Summary
{Brief summary}

### Vulnerability Detail
{Detailed explanation with code}

### Impact
{Specific impact}

### Proof of Concept
```solidity
{PoC code}
```

### Recommendation
{Specific fix}
"""

    def _categorize_findings(self) -> dict[str, list[Finding]]:
        """Split findings into verified, unverified, low/info, and observations."""
        from ..core.types import VulnerabilityType

        observation_types = {
            VulnerabilityType.CENTRALIZATION,
            VulnerabilityType.SINGLE_POINT_FAILURE,
            VulnerabilityType.MISSING_TIMELOCK,
            VulnerabilityType.GAS_OPTIMIZATION,
        }
        poc_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}

        verified = [f for f in self.state.findings if f.validated and f.poc]
        unverified = [
            f for f in self.state.findings
            if not f.validated
            and f.severity in poc_severities
            and f.vulnerability_type not in observation_types
        ]
        observations = [
            f for f in self.state.findings
            if f.vulnerability_type in observation_types
        ]
        low_info = [
            f for f in self.state.findings
            if f.severity in (Severity.LOW, Severity.INFORMATIONAL, Severity.GAS)
            and f.vulnerability_type not in observation_types
            and f not in verified and f not in unverified
        ]

        return {
            "verified": verified,
            "unverified": unverified,
            "low_info": low_info,
            "observations": observations,
        }

    async def _generate_markdown_report(self) -> str:
        """Generate a standard markdown report with verification stratification."""
        lines = [
            f"# Security Audit Report: {self.state.target_name}",
            "",
            f"**Generated by Sentinel**",
            "",
            "---",
            "",
        ]

        if self.config.executive_summary:
            summary = await self._generate_executive_summary()
            lines.extend([
                "## Executive Summary",
                "",
                summary,
                "",
                "---",
                "",
            ])

        categories = self._categorize_findings()

        # Verified findings
        if categories["verified"]:
            lines.append("## Verified Findings (with Proof of Concept)")
            lines.append("")

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                sev_findings = [f for f in categories["verified"] if f.severity == severity]
                if not sev_findings:
                    continue

                lines.append(f"### {severity.value} Severity")
                lines.append("")

                for finding in sev_findings:
                    finding_text = await self.write_finding(finding, include_poc=True)
                    lines.append(finding_text)
                    lines.append("")
                    lines.append("---")
                    lines.append("")

        # Unverified findings
        if categories["unverified"]:
            lines.append("## Unverified Findings (Manual Review Recommended)")
            lines.append("")
            lines.append("> These findings could not be verified with a working PoC. Manual review is recommended.")
            lines.append("")

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                sev_findings = [f for f in categories["unverified"] if f.severity == severity]
                if not sev_findings:
                    continue

                lines.append(f"### {severity.value} Severity")
                lines.append("")

                for finding in sev_findings:
                    finding_text = await self.write_finding(finding, include_poc=False)
                    lines.append(finding_text)
                    lines.append("")
                    lines.append("---")
                    lines.append("")

        # Low/Informational
        if categories["low_info"]:
            lines.append("## Low / Informational")
            lines.append("")

            for finding in categories["low_info"]:
                finding_text = await self.write_finding(finding, include_poc=False)
                lines.append(finding_text)
                lines.append("")
                lines.append("---")
                lines.append("")

        # Design observations
        if categories["observations"]:
            lines.append("## Design Observations")
            lines.append("")
            lines.append("> Architectural or design observations, not directly exploitable.")
            lines.append("")

            for finding in categories["observations"]:
                finding_text = await self.write_finding(finding, include_poc=False)
                lines.append(finding_text)
                lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    async def _generate_contest_report(self, platform: str) -> str:
        """Generate a contest-specific report (Code4rena, Sherlock)."""
        template = self.templates.get(platform, {})

        lines = [
            f"# {self.state.target_name} - Security Audit",
            "",
        ]

        categories = self._categorize_findings()

        # Verified findings first
        if categories["verified"]:
            lines.append("# Verified Findings")
            lines.append("")

        finding_counter = {"H": 0, "M": 0, "L": 0, "Q": 0, "G": 0}

        for group_key, group_label in [("verified", "Verified"), ("unverified", "Unverified")]:
            group = categories[group_key]
            if not group:
                continue

            if group_key == "unverified":
                lines.append("# Unverified Findings (Manual Review Recommended)")
                lines.append("")

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                sev_findings = [f for f in group if f.severity == severity]
                if not sev_findings:
                    continue

                prefix = {
                    Severity.CRITICAL: "H",
                    Severity.HIGH: "H",
                    Severity.MEDIUM: "M",
                    Severity.LOW: "L",
                }.get(severity, "L")

                for finding in sev_findings:
                    finding_counter[prefix] += 1
                    finding.id = f"{prefix}-{finding_counter[prefix]:02d}"

                    include_poc = group_key == "verified"
                    finding_text = await self.write_finding(
                        finding,
                        format=ReportFormat(platform),
                        include_poc=include_poc,
                    )
                    lines.append(finding_text)
                    lines.append("")

        # Low/info and observations
        for group_key, group_label in [("low_info", "Low / Informational"), ("observations", "Design Observations")]:
            group = categories[group_key]
            if not group:
                continue

            lines.append(f"# {group_label}")
            lines.append("")

            for finding in group:
                finding_text = await self.write_finding(
                    finding,
                    format=ReportFormat(platform),
                    include_poc=False,
                )
                lines.append(finding_text)
                lines.append("")

        return "\n".join(lines)

    async def _generate_immunefi_report(self) -> str:
        """Generate an Immunefi-optimized report."""
        lines = [
            f"# Bug Bounty Submission: {self.state.target_name}",
            "",
        ]

        # Only high-severity findings for bounties
        critical_high = (
            self.state.get_findings_by_severity(Severity.CRITICAL) +
            self.state.get_findings_by_severity(Severity.HIGH)
        )

        for finding in critical_high:
            submission = await self.write_immunefi_submission(
                finding,
                program_name=self.state.target_name,
                affected_contracts=[finding.contract],
            )
            lines.append(submission)
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    async def _generate_executive_summary(self) -> str:
        """Generate executive summary using extended thinking."""
        findings_summary = []
        for severity in Severity:
            count = len(self.state.get_findings_by_severity(severity))
            if count > 0:
                findings_summary.append(f"{count} {severity.value}")

        prompt = f"""Write a concise executive summary for this security audit:

**Target:** {self.state.target_name}
**Findings:** {', '.join(findings_summary) if findings_summary else 'None'}
**Architecture:** {'DeFi protocol' if self.state.architecture and self.state.architecture.is_defi else 'Smart contract system'}

The summary should:
1. State the scope in one sentence
2. Highlight the most critical findings
3. Provide overall risk assessment
4. Be 3-5 sentences maximum
"""

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=self.system_prompt,
            extended_thinking=self.config.ultrathink,
            thinking_budget=8000,
        )

        return response.content


async def generate_report(
    state: AuditState,
    format: ReportFormat = ReportFormat.MARKDOWN,
    output_path: Optional[Path] = None,
) -> str:
    """
    Convenience function to generate a report.

    Args:
        state: Audit state with findings
        format: Output format
        output_path: Path to save the report

    Returns:
        The generated report text
    """
    config = ReportConfig(format=format)
    agent = ReportWriterAgent(state=state, config=config)

    report = await agent.run()

    if output_path:
        output_path.write_text(report)
        console.print(f"[green]Report saved to: {output_path}[/green]")

    return report
