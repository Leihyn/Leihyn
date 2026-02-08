"""
Advanced Security Analysis Modules

New enhancement dimensions for Sentinel:
1. Bridge Security - Cross-chain message validation
2. Upgrade Safety - Proxy pattern vulnerabilities
3. MEV Analysis - Sandwich, frontrunning, JIT
4. ZK Circuits - Underconstrained circuit detection
5. Account Abstraction - ERC-4337 vulnerabilities
6. Differential Auditing - Version comparison
7. Attack Visualization - Graph generation
8. Slither Deep - Custom detector integration
9. Severity Prediction - ML-based severity
10. Collaborative Audit - Multi-auditor workflows
"""

# Bridge Security
from .bridge_analyzer import (
    BridgeSecurityAnalyzer,
    BridgeVulnerability,
    BridgeType,
    analyze_bridge,
)

# Upgrade Safety
from .upgrade_safety import (
    UpgradeSafetyAnalyzer,
    StorageLayoutAnalyzer,
    ProxyPattern,
    UpgradeFinding as UpgradeIssue,
    analyze_upgrade_safety as check_upgrade_safety,
)

# MEV Analysis
from .mev_analyzer import (
    MEVAnalyzer,
    MEVVector,
    MEVSeverity as MEVType,
    analyze_mev,
)

# ZK Circuit Analysis
from .zk_circuit_analyzer import (
    ZKCircuitAnalyzer,
    ZKLanguage,
    ZKVulnerability as CircuitVulnerability,
    analyze_circom as analyze_zk_circuit,
)

# Account Abstraction
from .account_abstraction import (
    AccountAbstractionAnalyzer,
    AAComponent,
    AAVulnerability,
    analyze_smart_account as analyze_account_abstraction,
)

# Differential Auditing
from .differential_auditor import (
    DifferentialAuditor,
    CodeChange as ContractDiff,
    ChangeType as DiffType,
    diff_contracts as compare_versions,
)

# Attack Graph Visualization
from .attack_graph_visualizer import (
    AttackGraphVisualizer,
    AttackGraph,
    AttackNode,
    AttackEdge,
    OutputFormat,
    visualize_findings,
    generate_mermaid_diagram,
    generate_ascii_graph,
)

# Slither Deep Integration
from .slither_deep import (
    SlitherDeepIntegration,
    SlitherFinding,
    TaintPath,
    TaintSource,
    TaintSink,
    CustomDetectorSpec,
    run_slither,
    analyze_taint,
    create_detector,
)

# Severity Prediction
from .severity_predictor import (
    SeverityPredictor,
    SeverityPrediction,
    Severity,
    Platform,
    FindingFeatures,
    predict_severity,
    compare_platforms,
)

# Collaborative Audit
from .collaborative_audit import (
    CollaborativeAudit,
    AuditSession,
    Auditor as AuditorRole,
    AuditFinding as SharedFinding,
    AuditPhase,
    create_audit_session as create_session,
    merge_findings_from_auditors as join_session,
)

__all__ = [
    # Bridge Security
    "BridgeSecurityAnalyzer",
    "BridgeVulnerability",
    "BridgeType",
    "analyze_bridge",
    # Upgrade Safety
    "UpgradeSafetyAnalyzer",
    "StorageLayoutAnalyzer",
    "ProxyPattern",
    "UpgradeIssue",
    "check_upgrade_safety",
    # MEV Analysis
    "MEVAnalyzer",
    "MEVVector",
    "MEVType",
    "analyze_mev",
    # ZK Circuit Analysis
    "ZKCircuitAnalyzer",
    "ZKLanguage",
    "CircuitVulnerability",
    "analyze_zk_circuit",
    # Account Abstraction
    "AccountAbstractionAnalyzer",
    "AAComponent",
    "AAVulnerability",
    "analyze_account_abstraction",
    # Differential Auditing
    "DifferentialAuditor",
    "ContractDiff",
    "DiffType",
    "compare_versions",
    # Attack Graph Visualization
    "AttackGraphVisualizer",
    "AttackGraph",
    "AttackNode",
    "AttackEdge",
    "OutputFormat",
    "visualize_findings",
    "generate_mermaid_diagram",
    "generate_ascii_graph",
    # Slither Deep Integration
    "SlitherDeepIntegration",
    "SlitherFinding",
    "TaintPath",
    "TaintSource",
    "TaintSink",
    "CustomDetectorSpec",
    "run_slither",
    "analyze_taint",
    "create_detector",
    # Severity Prediction
    "SeverityPredictor",
    "SeverityPrediction",
    "Severity",
    "Platform",
    "FindingFeatures",
    "predict_severity",
    "compare_platforms",
    # Collaborative Audit
    "CollaborativeAudit",
    "AuditSession",
    "AuditorRole",
    "SharedFinding",
    "AuditPhase",
    "create_session",
    "join_session",
]
