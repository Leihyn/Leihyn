"""
SENTINEL Elite - Knowledge Graph

Maps contract relationships, dependencies, and attack surfaces
for comprehensive security analysis of composable DeFi systems.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from enum import Enum
import re
import json
from collections import defaultdict


class NodeType(Enum):
    """Types of nodes in the knowledge graph"""
    CONTRACT = "contract"
    FUNCTION = "function"
    STATE_VAR = "state_variable"
    EVENT = "event"
    MODIFIER = "modifier"
    EXTERNAL_CALL = "external_call"
    PROTOCOL = "protocol"
    TOKEN = "token"
    ORACLE = "oracle"
    PROXY = "proxy"
    LIBRARY = "library"


class EdgeType(Enum):
    """Types of edges/relationships"""
    CALLS = "calls"
    INHERITS = "inherits"
    IMPORTS = "imports"
    DELEGATES_TO = "delegates_to"
    READS = "reads"
    WRITES = "writes"
    EMITS = "emits"
    USES_MODIFIER = "uses_modifier"
    DEPENDS_ON = "depends_on"
    FLASH_LOANS_FROM = "flash_loans_from"
    PROVIDES_PRICE = "provides_price"
    MANAGES = "manages"
    UPGRADES_TO = "upgrades_to"


@dataclass
class GraphNode:
    """Node in the knowledge graph"""
    id: str
    type: NodeType
    name: str
    address: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    tags: Set[str] = field(default_factory=set)


@dataclass
class GraphEdge:
    """Edge in the knowledge graph"""
    source_id: str
    target_id: str
    type: EdgeType
    metadata: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class AttackPath:
    """Potential attack path through the graph"""
    nodes: List[str]
    edges: List[GraphEdge]
    entry_point: str
    target: str
    attack_type: str
    risk_score: float
    description: str


class ContractKnowledgeGraph:
    """
    Knowledge graph for smart contract relationships

    Tracks:
    - Contract dependencies and imports
    - External call chains
    - State variable access patterns
    - Oracle dependencies
    - Flash loan sources
    - Upgrade patterns
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph"""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph"""
        self.edges.append(edge)
        self.adjacency[edge.source_id].append((edge.target_id, edge))
        self.reverse_adjacency[edge.target_id].append((edge.source_id, edge))

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID"""
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[GraphNode]:
        """Get neighboring nodes"""
        neighbors = []
        for target_id, edge in self.adjacency.get(node_id, []):
            if edge_type is None or edge.type == edge_type:
                node = self.nodes.get(target_id)
                if node:
                    neighbors.append(node)
        return neighbors

    def get_callers(self, node_id: str) -> List[GraphNode]:
        """Get all nodes that call this node"""
        callers = []
        for source_id, edge in self.reverse_adjacency.get(node_id, []):
            if edge.type == EdgeType.CALLS:
                node = self.nodes.get(source_id)
                if node:
                    callers.append(node)
        return callers


class ContractGraphBuilder:
    """Builds knowledge graph from smart contract source code"""

    # Known protocol addresses
    KNOWN_PROTOCOLS = {
        "0xBA12222222228d8Ba445958a75a0704d566BF2C8": ("Balancer Vault", "balancer"),
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2": ("Aave V3 Pool", "aave"),
        "0x1F98431c8aD98523631AE4a59f267346ea31F984": ("Uniswap V3 Factory", "uniswap"),
        "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419": ("Chainlink ETH/USD", "chainlink"),
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", "token"),
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", "token"),
    }

    # External call patterns
    EXTERNAL_CALL_PATTERNS = [
        (r'(\w+)\.call\{', 'low_level_call'),
        (r'(\w+)\.delegatecall\(', 'delegatecall'),
        (r'(\w+)\.staticcall\(', 'staticcall'),
        (r'(\w+)\.transfer\(', 'transfer'),
        (r'(\w+)\.send\(', 'send'),
        (r'(\w+)\.(\w+)\(', 'function_call'),
    ]

    def __init__(self):
        self.graph = ContractKnowledgeGraph()

    def build_from_source(self, source: str, contract_name: str) -> ContractKnowledgeGraph:
        """Build knowledge graph from Solidity source code"""

        # Add main contract node
        contract_id = f"contract:{contract_name}"
        self.graph.add_node(GraphNode(
            id=contract_id,
            type=NodeType.CONTRACT,
            name=contract_name,
            metadata={"source_length": len(source)}
        ))

        # Parse and add components
        self._extract_imports(source, contract_id)
        self._extract_inheritance(source, contract_id)
        self._extract_state_variables(source, contract_id)
        self._extract_functions(source, contract_id)
        self._extract_external_calls(source, contract_id)
        self._extract_events(source, contract_id)
        self._extract_modifiers(source, contract_id)

        # Identify protocol integrations
        self._identify_protocols(source, contract_id)

        # Calculate risk scores
        self._calculate_risk_scores()

        return self.graph

    def _extract_imports(self, source: str, contract_id: str) -> None:
        """Extract import statements"""
        import_pattern = r'import\s+["\']([^"\']+)["\']|import\s+\{([^}]+)\}\s+from\s+["\']([^"\']+)["\']'

        for match in re.finditer(import_pattern, source):
            import_path = match.group(1) or match.group(3)
            import_id = f"import:{import_path}"

            self.graph.add_node(GraphNode(
                id=import_id,
                type=NodeType.LIBRARY,
                name=import_path,
                metadata={"path": import_path}
            ))

            self.graph.add_edge(GraphEdge(
                source_id=contract_id,
                target_id=import_id,
                type=EdgeType.IMPORTS
            ))

    def _extract_inheritance(self, source: str, contract_id: str) -> None:
        """Extract contract inheritance"""
        # Match: contract Foo is Bar, Baz, Qux
        inherit_pattern = r'contract\s+\w+\s+is\s+([^{]+)'

        match = re.search(inherit_pattern, source)
        if match:
            parents = [p.strip() for p in match.group(1).split(',')]
            for parent in parents:
                # Remove any constructor args
                parent_name = parent.split('(')[0].strip()
                parent_id = f"contract:{parent_name}"

                self.graph.add_node(GraphNode(
                    id=parent_id,
                    type=NodeType.CONTRACT,
                    name=parent_name,
                    tags={"inherited"}
                ))

                self.graph.add_edge(GraphEdge(
                    source_id=contract_id,
                    target_id=parent_id,
                    type=EdgeType.INHERITS
                ))

    def _extract_state_variables(self, source: str, contract_id: str) -> None:
        """Extract state variables"""
        # Pattern for state variable declarations
        var_pattern = r'^\s*(mapping|address|uint\d*|int\d*|bytes\d*|string|bool|struct\s+\w+)\s+(?:public|private|internal)?\s*(\w+)\s*[;=]'

        for match in re.finditer(var_pattern, source, re.MULTILINE):
            var_type = match.group(1)
            var_name = match.group(2)
            var_id = f"var:{contract_id}:{var_name}"

            self.graph.add_node(GraphNode(
                id=var_id,
                type=NodeType.STATE_VAR,
                name=var_name,
                metadata={"var_type": var_type}
            ))

            self.graph.add_edge(GraphEdge(
                source_id=contract_id,
                target_id=var_id,
                type=EdgeType.MANAGES
            ))

    def _extract_functions(self, source: str, contract_id: str) -> None:
        """Extract function definitions"""
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(external|public|internal|private)?[^{]*\{'

        for match in re.finditer(func_pattern, source):
            func_name = match.group(1)
            visibility = match.group(2) or "internal"
            func_id = f"func:{contract_id}:{func_name}"

            tags = set()
            if visibility in ["external", "public"]:
                tags.add("entry_point")

            self.graph.add_node(GraphNode(
                id=func_id,
                type=NodeType.FUNCTION,
                name=func_name,
                metadata={"visibility": visibility},
                tags=tags
            ))

            self.graph.add_edge(GraphEdge(
                source_id=contract_id,
                target_id=func_id,
                type=EdgeType.MANAGES
            ))

    def _extract_external_calls(self, source: str, contract_id: str) -> None:
        """Extract external calls and dependencies"""

        for pattern, call_type in self.EXTERNAL_CALL_PATTERNS:
            for match in re.finditer(pattern, source):
                target = match.group(1)
                call_id = f"call:{target}"

                # Skip common local variables
                if target in ['msg', 'block', 'tx', 'this', 'super']:
                    continue

                self.graph.add_node(GraphNode(
                    id=call_id,
                    type=NodeType.EXTERNAL_CALL,
                    name=target,
                    metadata={"call_type": call_type}
                ))

                self.graph.add_edge(GraphEdge(
                    source_id=contract_id,
                    target_id=call_id,
                    type=EdgeType.CALLS,
                    metadata={"call_type": call_type}
                ))

    def _extract_events(self, source: str, contract_id: str) -> None:
        """Extract event definitions and emissions"""
        event_pattern = r'event\s+(\w+)\s*\([^)]*\)'

        for match in re.finditer(event_pattern, source):
            event_name = match.group(1)
            event_id = f"event:{contract_id}:{event_name}"

            self.graph.add_node(GraphNode(
                id=event_id,
                type=NodeType.EVENT,
                name=event_name
            ))

            self.graph.add_edge(GraphEdge(
                source_id=contract_id,
                target_id=event_id,
                type=EdgeType.EMITS
            ))

    def _extract_modifiers(self, source: str, contract_id: str) -> None:
        """Extract modifier definitions"""
        modifier_pattern = r'modifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{'

        for match in re.finditer(modifier_pattern, source):
            mod_name = match.group(1)
            mod_id = f"mod:{contract_id}:{mod_name}"

            self.graph.add_node(GraphNode(
                id=mod_id,
                type=NodeType.MODIFIER,
                name=mod_name
            ))

            self.graph.add_edge(GraphEdge(
                source_id=contract_id,
                target_id=mod_id,
                type=EdgeType.MANAGES
            ))

    def _identify_protocols(self, source: str, contract_id: str) -> None:
        """Identify known protocol integrations"""

        for address, (name, protocol_type) in self.KNOWN_PROTOCOLS.items():
            if address.lower() in source.lower():
                protocol_id = f"protocol:{protocol_type}:{name}"

                node_type = NodeType.TOKEN if protocol_type == "token" else NodeType.PROTOCOL

                self.graph.add_node(GraphNode(
                    id=protocol_id,
                    type=node_type,
                    name=name,
                    address=address,
                    metadata={"protocol": protocol_type}
                ))

                edge_type = EdgeType.DEPENDS_ON
                if "flash" in source.lower():
                    edge_type = EdgeType.FLASH_LOANS_FROM
                elif "price" in source.lower() or "oracle" in source.lower():
                    edge_type = EdgeType.PROVIDES_PRICE

                self.graph.add_edge(GraphEdge(
                    source_id=contract_id,
                    target_id=protocol_id,
                    type=edge_type
                ))

    def _calculate_risk_scores(self) -> None:
        """Calculate risk scores for all nodes"""

        risk_factors = {
            NodeType.EXTERNAL_CALL: 0.3,
            NodeType.PROXY: 0.4,
            EdgeType.DELEGATECALL: 0.5,
            EdgeType.FLASH_LOANS_FROM: 0.3,
        }

        for node_id, node in self.graph.nodes.items():
            score = 0.0

            # Base risk by node type
            score += risk_factors.get(node.type, 0.1)

            # Risk from edges
            for _, edge in self.graph.adjacency.get(node_id, []):
                score += risk_factors.get(edge.type, 0.05)

            # Entry points are higher risk
            if "entry_point" in node.tags:
                score += 0.2

            node.risk_score = min(score, 1.0)


class AttackPathFinder:
    """Find potential attack paths through the knowledge graph"""

    def __init__(self, graph: ContractKnowledgeGraph):
        self.graph = graph

    def find_attack_paths(self) -> List[AttackPath]:
        """Find all potential attack paths"""
        paths = []

        # Find entry points
        entry_points = [
            node_id for node_id, node in self.graph.nodes.items()
            if "entry_point" in node.tags
        ]

        # Find high-value targets
        targets = self._identify_targets()

        # BFS/DFS to find paths from entry points to targets
        for entry in entry_points:
            for target in targets:
                found_paths = self._find_paths_between(entry, target)
                paths.extend(found_paths)

        return sorted(paths, key=lambda p: p.risk_score, reverse=True)

    def _identify_targets(self) -> List[str]:
        """Identify high-value targets in the graph"""
        targets = []

        for node_id, node in self.graph.nodes.items():
            # State variables that hold funds
            if node.type == NodeType.STATE_VAR:
                if any(kw in node.name.lower() for kw in ['balance', 'token', 'fund', 'reserve']):
                    targets.append(node_id)

            # External protocols (flash loan, oracle)
            if node.type == NodeType.PROTOCOL:
                targets.append(node_id)

        return targets

    def _find_paths_between(self, start: str, end: str, max_depth: int = 10) -> List[AttackPath]:
        """Find paths between two nodes using BFS"""
        from collections import deque

        paths = []
        queue = deque([(start, [start], [])])
        visited = set()

        while queue:
            current, path, edges = queue.popleft()

            if len(path) > max_depth:
                continue

            if current == end:
                paths.append(self._create_attack_path(path, edges, start, end))
                continue

            if current in visited:
                continue
            visited.add(current)

            for neighbor_id, edge in self.graph.adjacency.get(current, []):
                if neighbor_id not in visited:
                    queue.append((
                        neighbor_id,
                        path + [neighbor_id],
                        edges + [edge]
                    ))

        return paths

    def _create_attack_path(
        self,
        nodes: List[str],
        edges: List[GraphEdge],
        entry: str,
        target: str
    ) -> AttackPath:
        """Create an attack path from found nodes/edges"""

        # Determine attack type based on edges
        attack_type = "unknown"
        if any(e.type == EdgeType.FLASH_LOANS_FROM for e in edges):
            attack_type = "flash_loan"
        elif any(e.type == EdgeType.DELEGATES_TO for e in edges):
            attack_type = "delegatecall"
        elif any(e.type == EdgeType.PROVIDES_PRICE for e in edges):
            attack_type = "oracle_manipulation"

        # Calculate risk score
        risk_score = sum(
            self.graph.nodes[n].risk_score
            for n in nodes if n in self.graph.nodes
        ) / len(nodes)

        return AttackPath(
            nodes=nodes,
            edges=edges,
            entry_point=entry,
            target=target,
            attack_type=attack_type,
            risk_score=risk_score,
            description=f"Path from {entry} to {target} via {attack_type}"
        )


class ComposabilityAnalyzer:
    """Analyze cross-contract composability risks"""

    def __init__(self, graph: ContractKnowledgeGraph):
        self.graph = graph

    def analyze_composability_risks(self) -> List[Dict[str, Any]]:
        """Identify composability risks"""
        risks = []

        # Check for reentrancy-prone patterns
        risks.extend(self._check_external_call_patterns())

        # Check for oracle dependencies
        risks.extend(self._check_oracle_dependencies())

        # Check for flash loan vulnerabilities
        risks.extend(self._check_flash_loan_risks())

        return risks

    def _check_external_call_patterns(self) -> List[Dict[str, Any]]:
        """Check for risky external call patterns"""
        risks = []

        call_nodes = [
            n for n in self.graph.nodes.values()
            if n.type == NodeType.EXTERNAL_CALL
        ]

        for node in call_nodes:
            call_type = node.metadata.get("call_type", "")

            if call_type == "delegatecall":
                risks.append({
                    "type": "delegatecall_risk",
                    "severity": "HIGH",
                    "node": node.id,
                    "description": f"Delegatecall to {node.name} may allow storage collision"
                })
            elif call_type == "low_level_call":
                risks.append({
                    "type": "low_level_call",
                    "severity": "MEDIUM",
                    "node": node.id,
                    "description": f"Low-level call to {node.name} - check return value"
                })

        return risks

    def _check_oracle_dependencies(self) -> List[Dict[str, Any]]:
        """Check oracle dependencies for manipulation risks"""
        risks = []

        oracle_nodes = [
            n for n in self.graph.nodes.values()
            if n.type == NodeType.ORACLE or
            any(e.type == EdgeType.PROVIDES_PRICE for _, e in self.graph.adjacency.get(n.id, []))
        ]

        for node in oracle_nodes:
            risks.append({
                "type": "oracle_dependency",
                "severity": "MEDIUM",
                "node": node.id,
                "description": f"Oracle dependency on {node.name} - verify freshness and manipulation resistance"
            })

        return risks

    def _check_flash_loan_risks(self) -> List[Dict[str, Any]]:
        """Check for flash loan related risks"""
        risks = []

        for edge in self.graph.edges:
            if edge.type == EdgeType.FLASH_LOANS_FROM:
                target = self.graph.nodes.get(edge.target_id)
                if target:
                    risks.append({
                        "type": "flash_loan_integration",
                        "severity": "MEDIUM",
                        "node": edge.source_id,
                        "description": f"Flash loan from {target.name} - ensure callback is protected"
                    })

        return risks


def build_contract_graph(source: str, name: str) -> ContractKnowledgeGraph:
    """Build knowledge graph from contract source"""
    builder = ContractGraphBuilder()
    return builder.build_from_source(source, name)


def find_attack_surfaces(graph: ContractKnowledgeGraph) -> List[AttackPath]:
    """Find attack paths in the graph"""
    finder = AttackPathFinder(graph)
    return finder.find_attack_paths()


def analyze_composability(graph: ContractKnowledgeGraph) -> List[Dict[str, Any]]:
    """Analyze composability risks"""
    analyzer = ComposabilityAnalyzer(graph)
    return analyzer.analyze_composability_risks()
