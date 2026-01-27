"""
Audit Workflow Engine - LLM-Assisted Audit Methodology

Structured 5-phase audit workflow combining:
- pontifex73/audit-assistant-playbook: Exploration → Hypothesis → Validation → Drafting → Review
- MixBytes Three Mindsets: Hacker, Invariant, System Architect
- Solcurity 12-step review methodology
- Ackee Wake vibe fuzzing 4-phase flow

Sources:
- https://github.com/pontifex73/audit-assistant-playbook
- https://mixbytes.io/blog/mastering-effective-test-writing-for-web3-protocol-audits
- https://github.com/transmissions11/solcurity
- https://ackee.xyz/blog/vibe-fuzzing-guide-for-wakes-manually-guided-fuzzing/
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path


class AuditPhase(Enum):
    EXPLORATION = "exploration"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    DRAFTING = "drafting"
    REVIEW = "review"


class TestingMindset(Enum):
    HACKER = "hacker"
    INVARIANT = "invariant"
    SYSTEM_ARCHITECT = "system_architect"


@dataclass
class PhaseChecklist:
    """Checklist for a single audit phase."""
    phase: AuditPhase
    items: list[dict]
    completed: list[str] = field(default_factory=list)

    @property
    def progress(self) -> float:
        if not self.items:
            return 0.0
        return (len(self.completed) / len(self.items)) * 100

    def to_markdown(self) -> str:
        lines = [f"### Phase: {self.phase.value.title()} ({self.progress:.0f}%)", ""]
        for item in self.items:
            status = "[x]" if item["id"] in self.completed else "[ ]"
            lines.append(f"- {status} **{item['id']}**: {item['description']}")
            if item.get("mindset"):
                lines.append(f"  - Mindset: {item['mindset']}")
        return "\n".join(lines)


@dataclass
class AuditWorkflow:
    """Complete audit workflow state."""
    project_name: str
    current_phase: AuditPhase
    phases: dict[str, PhaseChecklist]
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def overall_progress(self) -> float:
        if not self.phases:
            return 0.0
        return sum(p.progress for p in self.phases.values()) / len(self.phases)

    def to_markdown(self) -> str:
        lines = [
            f"# Audit Workflow: {self.project_name}",
            "",
            f"**Overall Progress**: {self.overall_progress:.0f}%",
            f"**Current Phase**: {self.current_phase.value.title()}",
            f"**Findings**: {len(self.findings)}",
            "",
        ]
        for phase in self.phases.values():
            lines.append(phase.to_markdown())
            lines.append("")
        return "\n".join(lines)


# Phase definitions combining all methodologies
EXPLORATION_ITEMS = [
    {"id": "E-01", "description": "Read project documentation, specs, and README"},
    {"id": "E-02", "description": "Identify contract architecture and inheritance tree (Surya/sol2uml)"},
    {"id": "E-03", "description": "Map entry points: external/public functions and access levels"},
    {"id": "E-04", "description": "Identify privileged roles and access control patterns"},
    {"id": "E-05", "description": "Map value flows: ETH, tokens, state changes"},
    {"id": "E-06", "description": "List external dependencies and integrations"},
    {"id": "E-07", "description": "Review deployment scripts and configuration"},
    {"id": "E-08", "description": "Analyze test coverage and identify untested paths"},
    {"id": "E-09", "description": "Create mental model of intended behavior"},
    {"id": "E-10", "description": "Document initial threat model and attack surface"},
]

HYPOTHESIS_ITEMS = [
    # Hacker Mindset (MixBytes)
    {"id": "H-01", "description": "Access control: What use cases should NOT be accessible to regular users?", "mindset": "hacker"},
    {"id": "H-02", "description": "Call sequencing: What limitations on function call order/frequency?", "mindset": "hacker"},
    {"id": "H-03", "description": "Input validation: What constraints on user input parameters?", "mindset": "hacker"},
    {"id": "H-04", "description": "Parameter restriction: Which params should NOT be user-controlled?", "mindset": "hacker"},
    {"id": "H-05", "description": "Reentrancy: Can external calls re-enter state-changing functions?", "mindset": "hacker"},
    {"id": "H-06", "description": "Flash loan: Can flash loans manipulate protocol state?", "mindset": "hacker"},
    # Invariant Mindset (MixBytes)
    {"id": "H-07", "description": "Identify balance invariants (sum(balances) <= totalSupply)", "mindset": "invariant"},
    {"id": "H-08", "description": "Identify state invariants (paused => no state changes)", "mindset": "invariant"},
    {"id": "H-09", "description": "Identify transition invariants (balance_before - amount == balance_after)", "mindset": "invariant"},
    {"id": "H-10", "description": "Identify economic invariants (LP_value >= sum(underlying))", "mindset": "invariant"},
    # System Architect Mindset (MixBytes)
    {"id": "H-11", "description": "Map external dependencies that could fail", "mindset": "system_architect"},
    {"id": "H-12", "description": "Identify oracle failure modes (stale, manipulated, zero)", "mindset": "system_architect"},
    {"id": "H-13", "description": "Assess token integration edge cases (fee-on-transfer, rebasing)", "mindset": "system_architect"},
    {"id": "H-14", "description": "Review governance/upgrade failure scenarios", "mindset": "system_architect"},
]

VALIDATION_ITEMS = [
    {"id": "V-01", "description": "Run static analysis (Slither, Aderyn, 4naly3er)"},
    {"id": "V-02", "description": "Run existing test suite and check coverage"},
    {"id": "V-03", "description": "Write PoC tests for suspected vulnerabilities"},
    {"id": "V-04", "description": "Verify invariants with fuzzing (Echidna/Foundry/Medusa)"},
    {"id": "V-05", "description": "Verify findings with symbolic execution (Halmos/Certora)"},
    {"id": "V-06", "description": "Test edge cases: zero, max, boundary values"},
    {"id": "V-07", "description": "Test external dependency failures with mocks"},
    {"id": "V-08", "description": "Validate severity using Impact x Likelihood matrix"},
]

DRAFTING_ITEMS = [
    {"id": "D-01", "description": "Document each finding with: description, impact, PoC, recommendation"},
    {"id": "D-02", "description": "Assign severity (Critical/High/Medium/Low) using risk matrix"},
    {"id": "D-03", "description": "Write clear attack scenarios for each finding"},
    {"id": "D-04", "description": "Provide specific, actionable remediation steps"},
    {"id": "D-05", "description": "Separate confirmed exploits from informational observations"},
    {"id": "D-06", "description": "Generate executive summary with risk overview"},
]

REVIEW_ITEMS = [
    {"id": "R-01", "description": "Self-review: challenge each finding as devil's advocate"},
    {"id": "R-02", "description": "Verify each PoC compiles and demonstrates the issue"},
    {"id": "R-03", "description": "Check severity calibration against contest/bounty standards"},
    {"id": "R-04", "description": "Ensure no duplicate findings or overlapping issues"},
    {"id": "R-05", "description": "Final pass: re-read from auditor-skeptic perspective"},
    {"id": "R-06", "description": "Verify all code references are correct (file:line)"},
]


class AuditWorkflowEngine:
    """
    Orchestrate structured audit workflow.

    Combines methodologies from:
    - pontifex73: 5-phase LLM-assisted audit flow
    - MixBytes: Three Mindsets testing framework
    - Solcurity: 12-step review methodology
    - Ackee Wake: Vibe fuzzing patterns

    Usage:
        engine = AuditWorkflowEngine("MyProtocol")
        workflow = engine.create_workflow()
        # Progress through phases...
        engine.complete_item(workflow, "E-01")
    """

    SEVERITY_MATRIX = {
        ("high", "high"): "Critical",
        ("high", "medium"): "High",
        ("high", "low"): "Medium",
        ("medium", "high"): "High",
        ("medium", "medium"): "Medium",
        ("medium", "low"): "Low",
        ("low", "high"): "Medium",
        ("low", "medium"): "Low",
        ("low", "low"): "Low",
    }

    def __init__(self, project_name: str):
        self.project_name = project_name

    def create_workflow(self) -> AuditWorkflow:
        """Create a new audit workflow with all phases."""
        phases = {
            AuditPhase.EXPLORATION.value: PhaseChecklist(
                phase=AuditPhase.EXPLORATION,
                items=EXPLORATION_ITEMS,
            ),
            AuditPhase.HYPOTHESIS.value: PhaseChecklist(
                phase=AuditPhase.HYPOTHESIS,
                items=HYPOTHESIS_ITEMS,
            ),
            AuditPhase.VALIDATION.value: PhaseChecklist(
                phase=AuditPhase.VALIDATION,
                items=VALIDATION_ITEMS,
            ),
            AuditPhase.DRAFTING.value: PhaseChecklist(
                phase=AuditPhase.DRAFTING,
                items=DRAFTING_ITEMS,
            ),
            AuditPhase.REVIEW.value: PhaseChecklist(
                phase=AuditPhase.REVIEW,
                items=REVIEW_ITEMS,
            ),
        }

        return AuditWorkflow(
            project_name=self.project_name,
            current_phase=AuditPhase.EXPLORATION,
            phases=phases,
        )

    def complete_item(self, workflow: AuditWorkflow, item_id: str):
        """Mark a checklist item as completed."""
        for phase in workflow.phases.values():
            for item in phase.items:
                if item["id"] == item_id:
                    if item_id not in phase.completed:
                        phase.completed.append(item_id)
                    return

    def classify_severity(self, impact: str, likelihood: str) -> str:
        """Classify severity using Impact x Likelihood matrix (Pashov style)."""
        return self.SEVERITY_MATRIX.get(
            (impact.lower(), likelihood.lower()), "Medium"
        )

    def add_finding(self, workflow: AuditWorkflow, finding: dict):
        """Add a finding to the workflow."""
        if "severity" not in finding and "impact" in finding and "likelihood" in finding:
            finding["severity"] = self.classify_severity(
                finding["impact"], finding["likelihood"]
            )
        workflow.findings.append(finding)

    def generate_report(self, workflow: AuditWorkflow) -> str:
        """Generate audit report from workflow."""
        lines = [
            f"# Security Audit Report: {workflow.project_name}",
            "",
            "## Overview",
            "",
            f"**Findings**: {len(workflow.findings)}",
            f"**Critical**: {len([f for f in workflow.findings if f.get('severity') == 'Critical'])}",
            f"**High**: {len([f for f in workflow.findings if f.get('severity') == 'High'])}",
            f"**Medium**: {len([f for f in workflow.findings if f.get('severity') == 'Medium'])}",
            f"**Low**: {len([f for f in workflow.findings if f.get('severity') == 'Low'])}",
            "",
            "## Severity Classification",
            "",
            "| | High Impact | Medium Impact | Low Impact |",
            "|---|---|---|---|",
            "| **High Likelihood** | Critical | High | Medium |",
            "| **Medium Likelihood** | High | Medium | Low |",
            "| **Low Likelihood** | Medium | Low | Low |",
            "",
            "## Findings",
            "",
        ]

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            workflow.findings,
            key=lambda f: severity_order.get(f.get("severity", "Low"), 4),
        )

        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "Unknown")
            lines.append(f"### [{sev.upper()}] {finding.get('title', f'Finding {i}')}")
            lines.append("")
            if finding.get("description"):
                lines.append(f"**Description**: {finding['description']}")
            if finding.get("impact"):
                lines.append(f"**Impact**: {finding['impact']}")
            if finding.get("likelihood"):
                lines.append(f"**Likelihood**: {finding['likelihood']}")
            if finding.get("location"):
                lines.append(f"**Location**: `{finding['location']}`")
            if finding.get("recommendation"):
                lines.append(f"**Recommendation**: {finding['recommendation']}")
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)


def create_audit_workflow(
    project_name: str, output_path: Optional[str] = None
) -> AuditWorkflow:
    """Create a new structured audit workflow."""
    engine = AuditWorkflowEngine(project_name)
    workflow = engine.create_workflow()
    if output_path:
        Path(output_path).write_text(workflow.to_markdown())
    return workflow
