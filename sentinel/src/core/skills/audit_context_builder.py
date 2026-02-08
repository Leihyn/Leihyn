"""
Audit Context Builder - Trail of Bits Skill

Deep context building for security audits using line-by-line analysis,
First Principles thinking, 5 Whys, and 5 Hows methodology.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/audit-context-building
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from pathlib import Path
import re


class AnalysisPhase(Enum):
    """Phases of context building."""
    ORIENTATION = "orientation"  # Initial mapping
    MICRO_ANALYSIS = "micro_analysis"  # Line-by-line
    GLOBAL_UNDERSTANDING = "global_understanding"  # System-level


@dataclass
class InputAssumption:
    """Assumption about function input."""
    parameter: str
    assumption: str
    source: str  # "explicit" or "implicit"
    evidence: str


@dataclass
class StateEffect:
    """Effect on contract state."""
    variable: str
    operation: str  # "read", "write", "both"
    condition: Optional[str] = None


@dataclass
class ExternalCall:
    """External call information."""
    target: str
    function: str
    parameters: list[str]
    return_handling: str
    risk_level: str  # "low", "medium", "high"
    assumptions: list[str] = field(default_factory=list)


@dataclass
class Invariant:
    """Identified invariant."""
    description: str
    type: str  # "explicit", "implicit", "derived"
    enforcement_location: Optional[str] = None
    can_be_violated: bool = False


@dataclass
class BlockAnalysis:
    """Analysis of a code block."""
    start_line: int
    end_line: int
    what_it_does: str
    why_here: str  # Ordering logic
    assumptions: list[str]
    invariants_established: list[str]
    dependencies: list[str]  # What later code depends on this
    first_principles: Optional[str] = None
    five_whys: list[str] = field(default_factory=list)
    five_hows: list[str] = field(default_factory=list)


@dataclass
class FunctionAnalysis:
    """Complete analysis of a function."""
    name: str
    file_path: str
    start_line: int
    end_line: int

    # Purpose
    purpose: str
    role_in_system: str

    # Inputs & Assumptions
    parameters: list[dict]
    implicit_inputs: list[str]  # state, sender, env
    preconditions: list[str]
    input_assumptions: list[InputAssumption] = field(default_factory=list)

    # Outputs & Effects
    return_values: list[dict] = field(default_factory=list)
    state_effects: list[StateEffect] = field(default_factory=list)
    events_emitted: list[str] = field(default_factory=list)
    external_calls: list[ExternalCall] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)

    # Block-by-block analysis
    block_analyses: list[BlockAnalysis] = field(default_factory=list)

    # Invariants
    invariants: list[Invariant] = field(default_factory=list)

    # Cross-function
    calls_to: list[str] = field(default_factory=list)
    called_by: list[str] = field(default_factory=list)
    shared_state: list[str] = field(default_factory=list)

    # Risk assessment
    complexity_score: int = 0
    risk_factors: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Generate markdown documentation."""
        lines = [
            f"## Function: `{self.name}`",
            f"**Location**: `{self.file_path}:{self.start_line}-{self.end_line}`",
            "",
            "### Purpose",
            self.purpose,
            "",
            f"**Role in System**: {self.role_in_system}",
            "",
            "### Inputs & Assumptions",
            "",
        ]

        # Parameters
        if self.parameters:
            lines.append("**Parameters:**")
            for p in self.parameters:
                lines.append(f"- `{p.get('name', '?')}`: {p.get('type', '?')} - {p.get('description', '')}")
            lines.append("")

        # Implicit inputs
        if self.implicit_inputs:
            lines.append("**Implicit Inputs:**")
            for i in self.implicit_inputs:
                lines.append(f"- {i}")
            lines.append("")

        # Preconditions
        if self.preconditions:
            lines.append("**Preconditions:**")
            for p in self.preconditions:
                lines.append(f"- {p}")
            lines.append("")

        # State effects
        lines.append("### Outputs & Effects")
        lines.append("")

        if self.state_effects:
            lines.append("**State Changes:**")
            for s in self.state_effects:
                condition = f" (when {s.condition})" if s.condition else ""
                lines.append(f"- `{s.variable}`: {s.operation}{condition}")
            lines.append("")

        if self.external_calls:
            lines.append("**External Calls:**")
            for c in self.external_calls:
                lines.append(f"- `{c.target}.{c.function}()` - Risk: {c.risk_level}")
                for a in c.assumptions:
                    lines.append(f"  - Assumption: {a}")
            lines.append("")

        # Invariants
        if self.invariants:
            lines.append("### Invariants")
            lines.append("")
            for inv in self.invariants:
                lines.append(f"- [{inv.type}] {inv.description}")
            lines.append("")

        # Risk factors
        if self.risk_factors:
            lines.append("### Risk Factors")
            lines.append("")
            for r in self.risk_factors:
                lines.append(f"- {r}")

        return "\n".join(lines)


@dataclass
class Actor:
    """System actor/role."""
    name: str
    description: str
    privileges: list[str]
    entry_points: list[str]
    trust_level: str  # "trusted", "semi-trusted", "untrusted"


@dataclass
class Workflow:
    """End-to-end workflow."""
    name: str
    description: str
    steps: list[dict]  # {"function": str, "description": str}
    state_transitions: list[str]
    invariants_maintained: list[str]


@dataclass
class SystemContext:
    """Complete system-level context."""
    project_name: str

    # Phase 1: Orientation
    modules: list[str]
    entry_points: list[str]
    actors: list[Actor]
    key_state_variables: list[dict]

    # Phase 2: Function analyses
    function_analyses: dict[str, FunctionAnalysis] = field(default_factory=dict)

    # Phase 3: Global understanding
    global_invariants: list[Invariant] = field(default_factory=list)
    workflows: list[Workflow] = field(default_factory=list)
    trust_boundaries: list[dict] = field(default_factory=list)
    complexity_clusters: list[dict] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Generate complete context document."""
        lines = [
            f"# Audit Context: {self.project_name}",
            "",
            "## System Overview",
            "",
            "### Modules",
            "",
        ]

        for m in self.modules:
            lines.append(f"- `{m}`")
        lines.append("")

        lines.append("### Actors & Roles")
        lines.append("")
        for actor in self.actors:
            lines.append(f"**{actor.name}** ({actor.trust_level})")
            lines.append(f"- {actor.description}")
            lines.append(f"- Privileges: {', '.join(actor.privileges)}")
            lines.append("")

        lines.append("### Key State Variables")
        lines.append("")
        for var in self.key_state_variables:
            lines.append(f"- `{var.get('name', '?')}`: {var.get('description', '')}")
        lines.append("")

        # Function analyses
        lines.append("---")
        lines.append("")
        lines.append("## Function Analyses")
        lines.append("")

        for name, analysis in self.function_analyses.items():
            lines.append(analysis.to_markdown())
            lines.append("")
            lines.append("---")
            lines.append("")

        # Global invariants
        if self.global_invariants:
            lines.append("## Global Invariants")
            lines.append("")
            for inv in self.global_invariants:
                lines.append(f"- [{inv.type}] {inv.description}")
            lines.append("")

        # Workflows
        if self.workflows:
            lines.append("## Workflows")
            lines.append("")
            for wf in self.workflows:
                lines.append(f"### {wf.name}")
                lines.append(f"{wf.description}")
                lines.append("")
                for i, step in enumerate(wf.steps, 1):
                    lines.append(f"{i}. `{step.get('function', '?')}`: {step.get('description', '')}")
                lines.append("")

        return "\n".join(lines)


class AuditContextBuilder:
    """
    Builds deep audit context through systematic analysis.

    Applies First Principles, 5 Whys, and 5 Hows methodology
    at micro (line/block) and macro (system) levels.

    This is for CONTEXT BUILDING only - not vulnerability hunting.
    """

    # Rationalizations to reject
    RATIONALIZATIONS = {
        "I get the gist": "Gist-level understanding misses edge cases. Line-by-line analysis required.",
        "This function is simple": "Simple functions compose into complex bugs. Apply 5 Whys anyway.",
        "I'll remember this invariant": "You won't. Context degrades. Write it down explicitly.",
        "External call is probably fine": "External = adversarial until proven otherwise.",
        "I can skip this helper": "Helpers contain assumptions that propagate. Trace the full call chain.",
        "This is taking too long": "Rushed context = hallucinated vulnerabilities later. Slow is fast.",
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.context = SystemContext(
            project_name=self.project_path.name,
            modules=[],
            entry_points=[],
            actors=[],
            key_state_variables=[],
        )

    def phase1_orientation(self) -> None:
        """
        Phase 1: Initial Orientation (Bottom-Up Scan)

        Minimal mapping before deep analysis:
        1. Identify major modules/files/contracts
        2. Note obvious public/external entrypoints
        3. Identify likely actors
        4. Identify important storage variables
        """
        # Find contract files
        for pattern in ["**/*.sol", "**/*.vy", "**/*.rs", "**/*.move"]:
            for f in self.project_path.glob(pattern):
                rel_path = str(f.relative_to(self.project_path))
                self.context.modules.append(rel_path)

        # Further analysis would parse files for entry points, actors, state vars

    def phase2_micro_analysis(self, file_path: str, function_name: str) -> FunctionAnalysis:
        """
        Phase 2: Ultra-Granular Function Analysis

        Every non-trivial function receives full micro analysis:
        1. Purpose
        2. Inputs & Assumptions
        3. Outputs & Effects
        4. Block-by-Block Analysis with First Principles / 5 Whys / 5 Hows
        """
        full_path = self.project_path / file_path
        content = full_path.read_text()

        # Find function (simplified - actual implementation needs proper parsing)
        func_pattern = re.compile(
            rf'function\s+{function_name}\s*\([^)]*\)[^{{]*\{{',
            re.MULTILINE | re.DOTALL
        )

        match = func_pattern.search(content)
        if not match:
            raise ValueError(f"Function {function_name} not found in {file_path}")

        start_line = content[:match.start()].count('\n') + 1

        # Create analysis (would need full parsing in production)
        analysis = FunctionAnalysis(
            name=function_name,
            file_path=file_path,
            start_line=start_line,
            end_line=start_line + 50,  # Placeholder
            purpose="[Requires manual analysis]",
            role_in_system="[Requires manual analysis]",
            parameters=[],
            implicit_inputs=["msg.sender", "block.timestamp", "contract state"],
            preconditions=[],
        )

        self.context.function_analyses[function_name] = analysis
        return analysis

    def analyze_block(
        self,
        code_block: str,
        start_line: int,
        context: str = "",
    ) -> BlockAnalysis:
        """
        Analyze a code block with First Principles / 5 Whys / 5 Hows.

        For each logical block:
        - What it does
        - Why it appears here (ordering logic)
        - What assumptions it relies on
        - What invariants it establishes or maintains
        - What later logic depends on it
        """
        return BlockAnalysis(
            start_line=start_line,
            end_line=start_line + code_block.count('\n'),
            what_it_does="[Manual analysis required]",
            why_here="[Manual analysis required]",
            assumptions=[],
            invariants_established=[],
            dependencies=[],
        )

    def apply_five_whys(self, observation: str) -> list[str]:
        """
        Apply 5 Whys methodology to understand root cause.

        Start with an observation and ask "Why?" repeatedly
        to drill down to fundamental assumptions.
        """
        return [
            f"Why 1: Why does {observation}?",
            "Why 2: [Requires manual analysis]",
            "Why 3: [Requires manual analysis]",
            "Why 4: [Requires manual analysis]",
            "Why 5: [Requires manual analysis - root cause]",
        ]

    def apply_five_hows(self, goal: str) -> list[str]:
        """
        Apply 5 Hows methodology to understand implementation.

        Start with a goal and ask "How?" repeatedly
        to understand the implementation chain.
        """
        return [
            f"How 1: How does the system achieve {goal}?",
            "How 2: [Requires manual analysis]",
            "How 3: [Requires manual analysis]",
            "How 4: [Requires manual analysis]",
            "How 5: [Requires manual analysis - concrete implementation]",
        ]

    def phase3_global_understanding(self) -> None:
        """
        Phase 3: Global System Understanding

        After sufficient micro-analysis:
        1. State & Invariant Reconstruction
        2. Workflow Reconstruction
        3. Trust Boundary Mapping
        4. Complexity & Fragility Clustering
        """
        # Derive global invariants from function analyses
        for name, analysis in self.context.function_analyses.items():
            for inv in analysis.invariants:
                if inv.type == "global":
                    self.context.global_invariants.append(inv)

        # Identify complexity clusters
        for name, analysis in self.context.function_analyses.items():
            if analysis.complexity_score > 10 or len(analysis.external_calls) > 2:
                self.context.complexity_clusters.append({
                    "function": name,
                    "complexity": analysis.complexity_score,
                    "risk_factors": analysis.risk_factors,
                })

    def add_invariant(
        self,
        description: str,
        type: str = "explicit",
        function: Optional[str] = None,
    ) -> None:
        """Add an identified invariant."""
        invariant = Invariant(
            description=description,
            type=type,
        )

        if function and function in self.context.function_analyses:
            self.context.function_analyses[function].invariants.append(invariant)
        else:
            self.context.global_invariants.append(invariant)

    def add_actor(
        self,
        name: str,
        description: str,
        privileges: list[str],
        trust_level: str = "untrusted",
    ) -> None:
        """Add a system actor."""
        self.context.actors.append(Actor(
            name=name,
            description=description,
            privileges=privileges,
            entry_points=[],
            trust_level=trust_level,
        ))

    def build(self) -> SystemContext:
        """
        Build complete audit context.

        Runs all phases and returns comprehensive context.
        """
        self.phase1_orientation()
        # Phase 2 is called per-function as needed
        self.phase3_global_understanding()
        return self.context

    def export_markdown(self, output_path: str) -> None:
        """Export context to markdown file."""
        Path(output_path).write_text(self.context.to_markdown())


def build_audit_context(
    project_path: str,
    output_path: Optional[str] = None,
) -> SystemContext:
    """
    Build audit context for a project.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown export

    Returns:
        SystemContext with complete analysis
    """
    builder = AuditContextBuilder(project_path)
    context = builder.build()

    if output_path:
        builder.export_markdown(output_path)

    return context
