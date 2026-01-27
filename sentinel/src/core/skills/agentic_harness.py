"""
Agentic Vulnerability Research Harness - Based on Kritt.ai Methodology

Structured harness that forces verification-driven vulnerability research
instead of "vibes-based" reasoning. Decomposes research into verifiable
subtasks with deterministic checkpoints.

Key principles:
1. Harnesses beat vibes - force explicit hypothesis generation
2. CodeQL as determinism injection - query semantics, don't reason about them
3. Compute-optimal allocation - spend more on promising leads
4. SOTA-first model selection - frontier models with native toolchains
5. Search-and-proof over classification - explore, deepen, verify, artifact

Sources:
- Kritt.ai: Building Agentic Infrastructure for Zero-Day Vulnerability Research (2026)
- SavantChat: AI-Assisted Hack Analysis Methodology (2026)
- Nethermind: AI-Augmented Smart Contract Audits (2026)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path


class HypothesisConfidence(Enum):
    SPECULATIVE = "speculative"     # Initial suspicion, no evidence
    LOW = "low"                      # Some pattern match, unverified
    MEDIUM = "medium"                # Reachability confirmed
    HIGH = "high"                    # Controllability confirmed
    VERIFIED = "verified"            # PoC demonstrates impact


class ResearchPhase(Enum):
    IDENTIFY = "identify"            # Suspicious behavior / invariant violation
    PROVE_REACHABILITY = "reachability"  # Call paths, entrypoints, conditions
    PROVE_CONTROLLABILITY = "controllability"  # Attacker influence on state
    DETERMINE_IMPACT = "impact"      # Theft, DoS, privilege escalation
    DEMONSTRATE = "demonstrate"      # PoC, simulation, repro
    REPORT = "report"                # Explanation, remediation


@dataclass
class Hypothesis:
    """A vulnerability hypothesis with evidence chain."""
    id: str
    title: str
    description: str
    confidence: HypothesisConfidence
    phase: ResearchPhase
    # Evidence chain - each entry is a verifiable checkpoint
    evidence: list[dict] = field(default_factory=list)
    # Deterministic tool results (CodeQL, Slither, etc.)
    tool_results: list[dict] = field(default_factory=list)
    # Whether hypothesis has been pruned (dead end)
    pruned: bool = False
    prune_reason: str = ""
    # Compute spent (tokens/time)
    compute_spent: int = 0

    def add_evidence(self, evidence_type: str, content: str, tool: str = "manual"):
        """Add verifiable evidence to the hypothesis."""
        self.evidence.append({
            "type": evidence_type,
            "content": content,
            "tool": tool,
            "phase": self.phase.value,
        })

    def escalate(self, new_confidence: HypothesisConfidence, reason: str):
        """Escalate confidence with justification."""
        self.evidence.append({
            "type": "escalation",
            "content": f"{self.confidence.value} -> {new_confidence.value}: {reason}",
            "tool": "harness",
            "phase": self.phase.value,
        })
        self.confidence = new_confidence

    def to_markdown(self) -> str:
        status = "PRUNED" if self.pruned else self.confidence.value.upper()
        lines = [
            f"### [{status}] {self.title}",
            "",
            f"**Phase**: {self.phase.value}",
            f"**Confidence**: {self.confidence.value}",
            f"**Description**: {self.description}",
            "",
        ]
        if self.evidence:
            lines.append("**Evidence Chain:**")
            for i, e in enumerate(self.evidence, 1):
                lines.append(f"  {i}. [{e['tool']}] {e['content'][:200]}")
            lines.append("")
        if self.pruned:
            lines.append(f"**Pruned**: {self.prune_reason}")
        return "\n".join(lines)


@dataclass
class ResearchSession:
    """A complete agentic research session."""
    target: str
    hypotheses: list[Hypothesis] = field(default_factory=list)
    verified_vulns: list[Hypothesis] = field(default_factory=list)
    total_compute: int = 0

    def to_markdown(self) -> str:
        lines = [
            f"# Agentic Research Session: {self.target}",
            "",
            f"**Hypotheses Generated**: {len(self.hypotheses)}",
            f"**Verified Vulnerabilities**: {len(self.verified_vulns)}",
            f"**Pruned**: {len([h for h in self.hypotheses if h.pruned])}",
            f"**Active**: {len([h for h in self.hypotheses if not h.pruned and h not in self.verified_vulns])}",
            "",
        ]
        if self.verified_vulns:
            lines.append("## Verified Vulnerabilities")
            lines.append("")
            for v in self.verified_vulns:
                lines.append(v.to_markdown())
                lines.append("---")
                lines.append("")

        active = [h for h in self.hypotheses if not h.pruned and h not in self.verified_vulns]
        if active:
            lines.append("## Active Hypotheses")
            lines.append("")
            for h in sorted(active, key=lambda x: x.confidence.value, reverse=True):
                lines.append(h.to_markdown())
                lines.append("")

        return "\n".join(lines)


# Deterministic queries that should use tools (CodeQL, Slither) not LLM reasoning
DETERMINISTIC_QUERIES = {
    "taint_reachability": {
        "question": "Does taint from this input reach that sink?",
        "tool": "codeql",
        "query_type": "taint_tracking",
    },
    "call_paths": {
        "question": "Which call paths lead to this function?",
        "tool": "slither",
        "query_type": "call_graph",
    },
    "state_mutation_guards": {
        "question": "Where is this state mutated, and under what guards?",
        "tool": "slither",
        "query_type": "state_analysis",
    },
    "auth_check_patterns": {
        "question": "Are there missing auth checks on state-changing functions?",
        "tool": "slither",
        "query_type": "access_control",
    },
    "unchecked_returns": {
        "question": "Are there unchecked return values from external calls?",
        "tool": "slither",
        "query_type": "detector",
    },
    "arbitrary_calls": {
        "question": "Are there user-controlled addresses in .call() targets?",
        "tool": "codeql",
        "query_type": "taint_tracking",
    },
    "approval_patterns": {
        "question": "Which contracts hold token approvals and can make arbitrary calls?",
        "tool": "slither",
        "query_type": "approval_analysis",
    },
}

# Known high-value vulnerability patterns (from real exploits)
EXPLOIT_PATTERNS = {
    "arbitrary_call": {
        "description": "User-controlled address and calldata in .call()",
        "severity": "critical",
        "example": "$3.2M WBTC hack (Jan 2026) - arbitrary call on liquidity manager",
        "detection": "Taint analysis: user input → .call() target address",
    },
    "approval_drain": {
        "description": "Contract with approvals can be tricked into transferFrom",
        "severity": "critical",
        "example": "Approval exploits via arbitrary call patterns",
        "detection": "Find contracts that hold approvals AND have user-controlled calls",
    },
    "flash_loan_oracle": {
        "description": "Oracle price manipulated via flash loan within single tx",
        "severity": "critical",
        "example": "Multiple DeFi exploits using flash loans to manipulate AMM prices",
        "detection": "Spot price usage without TWAP or freshness checks",
    },
    "reentrancy_cross_function": {
        "description": "State inconsistency exploited across different functions",
        "severity": "high",
        "example": "Read-only reentrancy via view functions during callback",
        "detection": "External calls before state updates with cross-function state reads",
    },
    "precision_loss_accumulation": {
        "description": "Rounding errors accumulate across many operations",
        "severity": "high",
        "example": "Division before multiplication in fee/reward calculations",
        "detection": "Divide-before-multiply patterns in financial calculations",
    },
}


class AgenticHarness:
    """
    Structured harness for agentic vulnerability research.

    Forces verification-driven research:
    - Hypotheses must have evidence before confidence escalation
    - Deterministic tools used for answerable questions
    - Dead ends pruned fast to save compute
    - Artifacts produced for reviewer trust

    Based on Kritt.ai methodology:
    "Harnesses are the difference between occasional brilliance
     and repeatable output."
    """

    def __init__(self, target: str):
        self.session = ResearchSession(target=target)
        self._hypothesis_counter = 0

    def create_hypothesis(
        self, title: str, description: str, initial_evidence: str = ""
    ) -> Hypothesis:
        """Create a new vulnerability hypothesis."""
        self._hypothesis_counter += 1
        h = Hypothesis(
            id=f"H-{self._hypothesis_counter:03d}",
            title=title,
            description=description,
            confidence=HypothesisConfidence.SPECULATIVE,
            phase=ResearchPhase.IDENTIFY,
        )
        if initial_evidence:
            h.add_evidence("initial_observation", initial_evidence)
        self.session.hypotheses.append(h)
        return h

    def advance_phase(self, hypothesis: Hypothesis, new_phase: ResearchPhase):
        """Advance hypothesis to next research phase."""
        hypothesis.phase = new_phase
        # Auto-escalate confidence based on phase progression
        phase_confidence = {
            ResearchPhase.IDENTIFY: HypothesisConfidence.SPECULATIVE,
            ResearchPhase.PROVE_REACHABILITY: HypothesisConfidence.LOW,
            ResearchPhase.PROVE_CONTROLLABILITY: HypothesisConfidence.MEDIUM,
            ResearchPhase.DETERMINE_IMPACT: HypothesisConfidence.HIGH,
            ResearchPhase.DEMONSTRATE: HypothesisConfidence.HIGH,
            ResearchPhase.REPORT: HypothesisConfidence.VERIFIED,
        }
        min_confidence = phase_confidence.get(new_phase, HypothesisConfidence.SPECULATIVE)
        if hypothesis.confidence.value < min_confidence.value:
            hypothesis.escalate(min_confidence, f"Advanced to {new_phase.value} phase")

    def prune(self, hypothesis: Hypothesis, reason: str):
        """Prune a dead-end hypothesis."""
        hypothesis.pruned = True
        hypothesis.prune_reason = reason

    def verify(self, hypothesis: Hypothesis, poc_description: str):
        """Mark hypothesis as verified with PoC."""
        hypothesis.confidence = HypothesisConfidence.VERIFIED
        hypothesis.phase = ResearchPhase.REPORT
        hypothesis.add_evidence("poc", poc_description, tool="foundry")
        self.session.verified_vulns.append(hypothesis)

    def get_deterministic_query(self, query_type: str) -> Optional[dict]:
        """Get the right deterministic tool for a question."""
        return DETERMINISTIC_QUERIES.get(query_type)

    def suggest_patterns(self, code_context: str = "") -> list[dict]:
        """Suggest exploit patterns to investigate based on code context."""
        suggestions = []
        for name, pattern in EXPLOIT_PATTERNS.items():
            suggestions.append({
                "pattern": name,
                "description": pattern["description"],
                "severity": pattern["severity"],
                "detection_method": pattern["detection"],
                "real_world_example": pattern["example"],
            })
        return suggestions

    def compute_allocation_hint(self, hypothesis: Hypothesis) -> str:
        """Suggest compute allocation based on hypothesis promise."""
        if hypothesis.confidence == HypothesisConfidence.VERIFIED:
            return "minimal - already verified, document and report"
        elif hypothesis.confidence == HypothesisConfidence.HIGH:
            return "high - promising lead, invest in PoC generation"
        elif hypothesis.confidence == HypothesisConfidence.MEDIUM:
            return "medium - controllability confirmed, prove impact"
        elif hypothesis.confidence == HypothesisConfidence.LOW:
            return "low-medium - use deterministic tools to verify reachability"
        else:
            return "low - quick triage, prune if no signal"

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate research session report."""
        report = self.session.to_markdown()
        if output_path:
            Path(output_path).write_text(report)
        return report


def create_research_session(target: str) -> AgenticHarness:
    """Create a new agentic research session."""
    return AgenticHarness(target)
