"""
Attack Graph Visualizer

Generate visual attack graphs from security findings:
1. Mermaid diagrams - Markdown embeddable
2. D3.js interactive - Web dashboard
3. DOT format - Graphviz
4. ASCII art - Terminal display

Features:
- Attack path visualization
- Risk flow mapping
- Entry point identification
- Impact assessment visualization
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
import json


class OutputFormat(Enum):
    """Supported output formats."""
    MERMAID = "mermaid"
    DOT = "dot"
    D3_JSON = "d3_json"
    ASCII = "ascii"
    CYTOSCAPE = "cytoscape"


class NodeType(Enum):
    """Types of nodes in attack graph."""
    ENTRY_POINT = "entry_point"
    VULNERABILITY = "vulnerability"
    STATE_CHANGE = "state_change"
    EXTERNAL_CALL = "external_call"
    ASSET = "asset"
    ATTACKER_GOAL = "attacker_goal"
    PRECONDITION = "precondition"


class EdgeType(Enum):
    """Types of edges in attack graph."""
    EXPLOITS = "exploits"
    LEADS_TO = "leads_to"
    REQUIRES = "requires"
    ENABLES = "enables"
    DRAINS = "drains"


@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    node_type: NodeType
    label: str
    description: str
    severity: Optional[str] = None
    contract: Optional[str] = None
    function: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    """An edge in the attack graph."""
    source: str
    target: str
    edge_type: EdgeType
    label: Optional[str] = None
    probability: float = 1.0


@dataclass
class AttackGraph:
    """Complete attack graph."""
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    title: str = "Attack Graph"
    description: str = ""

    def add_node(self, node: AttackNode) -> None:
        """Add node if not exists."""
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: AttackEdge) -> None:
        """Add edge."""
        self.edges.append(edge)


class AttackGraphVisualizer:
    """
    Generate visual attack graphs from security findings.

    Supports multiple output formats for different use cases:
    - Mermaid: Embed in markdown documentation
    - DOT: Generate images with Graphviz
    - D3.js: Interactive web visualization
    - ASCII: Terminal display
    """

    def __init__(self):
        self.graph = AttackGraph()

    def build_from_findings(
        self,
        findings: list[dict],
        contract_name: str = "Target",
    ) -> AttackGraph:
        """
        Build attack graph from security findings.

        Args:
            findings: List of finding dicts with vulnerability info
            contract_name: Name of the target contract

        Returns:
            AttackGraph object
        """
        self.graph = AttackGraph(
            title=f"Attack Graph: {contract_name}",
            description="Visual representation of attack vectors",
        )

        # Add entry point
        entry = AttackNode(
            id="entry",
            node_type=NodeType.ENTRY_POINT,
            label="Attacker",
            description="Malicious actor with EOA",
        )
        self.graph.add_node(entry)

        # Add asset (goal)
        asset = AttackNode(
            id="asset",
            node_type=NodeType.ASSET,
            label="Protocol Funds",
            description="Target assets to extract",
            metadata={"contract": contract_name},
        )
        self.graph.add_node(asset)

        # Process each finding
        for i, finding in enumerate(findings):
            vuln_id = f"vuln_{i}"

            # Add vulnerability node
            vuln_node = AttackNode(
                id=vuln_id,
                node_type=NodeType.VULNERABILITY,
                label=finding.get("title", f"Vulnerability {i}"),
                description=finding.get("description", ""),
                severity=finding.get("severity", "Unknown"),
                contract=finding.get("contract", contract_name),
                function=finding.get("function"),
            )
            self.graph.add_node(vuln_node)

            # Connect entry to vulnerability
            self.graph.add_edge(AttackEdge(
                source="entry",
                target=vuln_id,
                edge_type=EdgeType.EXPLOITS,
                label="exploits",
            ))

            # If vulnerability can lead to fund extraction
            severity = finding.get("severity", "").lower()
            if severity in ("critical", "high"):
                self.graph.add_edge(AttackEdge(
                    source=vuln_id,
                    target="asset",
                    edge_type=EdgeType.DRAINS,
                    label="drains",
                    probability=0.9 if severity == "critical" else 0.7,
                ))

        # Build attack chains from related findings
        self._build_attack_chains(findings)

        return self.graph

    def _build_attack_chains(self, findings: list[dict]) -> None:
        """Build attack chains from related vulnerabilities."""
        # Group by type to find chains
        vuln_types = {}
        for i, f in enumerate(findings):
            vtype = f.get("type", f.get("category", "other"))
            if vtype not in vuln_types:
                vuln_types[vtype] = []
            vuln_types[vtype].append((i, f))

        # Common chains
        chains = [
            (["oracle", "manipulation"], ["borrow", "liquidation"]),
            (["access", "control"], ["admin", "withdraw"]),
            (["reentrancy"], ["drain", "theft"]),
            (["flashloan"], ["price", "manipulation"]),
        ]

        for prereq_keywords, follow_keywords in chains:
            prereq_findings = []
            follow_findings = []

            for i, f in enumerate(findings):
                title = f.get("title", "").lower()
                desc = f.get("description", "").lower()

                if any(k in title or k in desc for k in prereq_keywords):
                    prereq_findings.append(i)
                if any(k in title or k in desc for k in follow_keywords):
                    follow_findings.append(i)

            # Connect prereqs to follows
            for prereq in prereq_findings:
                for follow in follow_findings:
                    if prereq != follow:
                        self.graph.add_edge(AttackEdge(
                            source=f"vuln_{prereq}",
                            target=f"vuln_{follow}",
                            edge_type=EdgeType.ENABLES,
                            label="enables",
                        ))

    def render(self, format: OutputFormat = OutputFormat.MERMAID) -> str:
        """
        Render attack graph to specified format.
        """
        renderers = {
            OutputFormat.MERMAID: self._render_mermaid,
            OutputFormat.DOT: self._render_dot,
            OutputFormat.D3_JSON: self._render_d3_json,
            OutputFormat.ASCII: self._render_ascii,
            OutputFormat.CYTOSCAPE: self._render_cytoscape,
        }

        renderer = renderers.get(format, self._render_mermaid)
        return renderer()

    def _render_mermaid(self) -> str:
        """Render as Mermaid diagram."""
        lines = [
            "```mermaid",
            "flowchart TD",
            f"    %% {self.graph.title}",
            "",
        ]

        # Define node styles
        lines.append("    %% Node styles")
        lines.append("    classDef entry fill:#e74c3c,color:#fff")
        lines.append("    classDef vuln fill:#f39c12,color:#fff")
        lines.append("    classDef critical fill:#c0392b,color:#fff")
        lines.append("    classDef high fill:#e67e22,color:#fff")
        lines.append("    classDef medium fill:#f1c40f,color:#000")
        lines.append("    classDef asset fill:#27ae60,color:#fff")
        lines.append("")

        # Add nodes
        lines.append("    %% Nodes")
        for node in self.graph.nodes:
            shape = self._get_mermaid_shape(node.node_type)
            label = node.label.replace('"', "'")[:50]
            lines.append(f"    {node.id}{shape[0]}\"{label}\"{shape[1]}")

        lines.append("")

        # Add edges
        lines.append("    %% Edges")
        for edge in self.edges_sorted():
            arrow = self._get_mermaid_arrow(edge.edge_type)
            label = edge.label or edge.edge_type.value
            lines.append(f"    {edge.source} {arrow}|{label}| {edge.target}")

        lines.append("")

        # Apply styles
        lines.append("    %% Apply styles")
        for node in self.graph.nodes:
            style = self._get_mermaid_style(node)
            if style:
                lines.append(f"    class {node.id} {style}")

        lines.append("```")

        return "\n".join(lines)

    def _get_mermaid_shape(self, node_type: NodeType) -> tuple[str, str]:
        """Get Mermaid shape brackets for node type."""
        shapes = {
            NodeType.ENTRY_POINT: ("((", "))"),      # Circle
            NodeType.VULNERABILITY: ("[", "]"),      # Rectangle
            NodeType.ASSET: ("([", "])"),            # Stadium
            NodeType.ATTACKER_GOAL: ("{{", "}}"),    # Hexagon
            NodeType.EXTERNAL_CALL: (">", "]"),      # Flag
            NodeType.PRECONDITION: ("(", ")"),       # Rounded
        }
        return shapes.get(node_type, ("[", "]"))

    def _get_mermaid_arrow(self, edge_type: EdgeType) -> str:
        """Get Mermaid arrow style for edge type."""
        arrows = {
            EdgeType.EXPLOITS: "-->",
            EdgeType.LEADS_TO: "-->",
            EdgeType.REQUIRES: "-.->",
            EdgeType.ENABLES: "==>",
            EdgeType.DRAINS: "--x",
        }
        return arrows.get(edge_type, "-->")

    def _get_mermaid_style(self, node: AttackNode) -> Optional[str]:
        """Get Mermaid style class for node."""
        if node.node_type == NodeType.ENTRY_POINT:
            return "entry"
        if node.node_type == NodeType.ASSET:
            return "asset"
        if node.node_type == NodeType.VULNERABILITY:
            severity = (node.severity or "").lower()
            if severity == "critical":
                return "critical"
            elif severity == "high":
                return "high"
            elif severity == "medium":
                return "medium"
        return None

    def _render_dot(self) -> str:
        """Render as DOT/Graphviz format."""
        lines = [
            "digraph AttackGraph {",
            f'    label="{self.graph.title}"',
            "    rankdir=TB",
            "    node [fontname=\"Helvetica\"]",
            "",
        ]

        # Node styles
        styles = {
            NodeType.ENTRY_POINT: 'shape=circle,style=filled,fillcolor="#e74c3c",fontcolor=white',
            NodeType.VULNERABILITY: 'shape=box,style=filled,fillcolor="#f39c12"',
            NodeType.ASSET: 'shape=cylinder,style=filled,fillcolor="#27ae60",fontcolor=white',
            NodeType.ATTACKER_GOAL: 'shape=hexagon,style=filled,fillcolor="#9b59b6",fontcolor=white',
        }

        # Add nodes
        for node in self.graph.nodes:
            style = styles.get(node.node_type, 'shape=box')
            label = node.label.replace('"', '\\"')
            lines.append(f'    {node.id} [label="{label}",{style}]')

        lines.append("")

        # Add edges
        for edge in self.graph.edges:
            label = edge.label or ""
            style = "bold" if edge.edge_type == EdgeType.DRAINS else "solid"
            lines.append(f'    {edge.source} -> {edge.target} [label="{label}",style={style}]')

        lines.append("}")

        return "\n".join(lines)

    def _render_d3_json(self) -> str:
        """Render as D3.js compatible JSON."""
        data = {
            "nodes": [],
            "links": [],
            "metadata": {
                "title": self.graph.title,
                "description": self.graph.description,
            },
        }

        # Add nodes
        for node in self.graph.nodes:
            data["nodes"].append({
                "id": node.id,
                "label": node.label,
                "type": node.node_type.value,
                "severity": node.severity,
                "description": node.description,
                "contract": node.contract,
                "function": node.function,
            })

        # Add links
        for edge in self.graph.edges:
            data["links"].append({
                "source": edge.source,
                "target": edge.target,
                "type": edge.edge_type.value,
                "label": edge.label,
                "probability": edge.probability,
            })

        return json.dumps(data, indent=2)

    def _render_ascii(self) -> str:
        """Render as ASCII art for terminal."""
        lines = [
            "=" * 60,
            f"  ATTACK GRAPH: {self.graph.title}",
            "=" * 60,
            "",
        ]

        # Group nodes by type
        entry_nodes = [n for n in self.graph.nodes if n.node_type == NodeType.ENTRY_POINT]
        vuln_nodes = [n for n in self.graph.nodes if n.node_type == NodeType.VULNERABILITY]
        asset_nodes = [n for n in self.graph.nodes if n.node_type == NodeType.ASSET]

        # Entry points
        lines.append("  ENTRY POINTS:")
        for node in entry_nodes:
            lines.append(f"    [*] {node.label}")

        lines.append("        |")
        lines.append("        v")

        # Vulnerabilities
        lines.append("  VULNERABILITIES:")
        for node in vuln_nodes:
            severity_icon = {
                "critical": "!!!",
                "high": "!! ",
                "medium": "!  ",
                "low": ".  ",
            }.get((node.severity or "").lower(), "   ")
            lines.append(f"    [{severity_icon}] {node.label}")

            # Show edges from this vulnerability
            edges = [e for e in self.graph.edges if e.source == node.id]
            for edge in edges:
                target = next((n for n in self.graph.nodes if n.id == edge.target), None)
                if target and target.node_type == NodeType.ASSET:
                    lines.append(f"          --({edge.label})--> ${target.label}")

        lines.append("        |")
        lines.append("        v")

        # Assets
        lines.append("  ASSETS AT RISK:")
        for node in asset_nodes:
            lines.append(f"    [$] {node.label}")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    def _render_cytoscape(self) -> str:
        """Render as Cytoscape.js compatible JSON."""
        elements = []

        for node in self.graph.nodes:
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.node_type.value,
                    "severity": node.severity,
                },
                "classes": node.node_type.value,
            })

        for i, edge in enumerate(self.graph.edges):
            elements.append({
                "data": {
                    "id": f"edge_{i}",
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.label,
                    "type": edge.edge_type.value,
                },
            })

        return json.dumps({"elements": elements}, indent=2)

    def edges_sorted(self) -> list[AttackEdge]:
        """Return edges sorted by source then target."""
        return sorted(self.graph.edges, key=lambda e: (e.source, e.target))


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def visualize_findings(
    findings: list[dict],
    format: str = "mermaid",
    contract_name: str = "Target",
) -> str:
    """
    Generate attack graph visualization from findings.

    Args:
        findings: List of security findings
        format: Output format (mermaid, dot, d3_json, ascii)
        contract_name: Name of target contract

    Returns:
        Formatted visualization string
    """
    visualizer = AttackGraphVisualizer()
    visualizer.build_from_findings(findings, contract_name)

    format_map = {
        "mermaid": OutputFormat.MERMAID,
        "dot": OutputFormat.DOT,
        "d3": OutputFormat.D3_JSON,
        "d3_json": OutputFormat.D3_JSON,
        "ascii": OutputFormat.ASCII,
        "cytoscape": OutputFormat.CYTOSCAPE,
    }

    output_format = format_map.get(format.lower(), OutputFormat.MERMAID)
    return visualizer.render(output_format)


def generate_mermaid_diagram(findings: list[dict]) -> str:
    """Generate Mermaid diagram from findings."""
    return visualize_findings(findings, "mermaid")


def generate_ascii_graph(findings: list[dict]) -> str:
    """Generate ASCII attack graph from findings."""
    return visualize_findings(findings, "ascii")
