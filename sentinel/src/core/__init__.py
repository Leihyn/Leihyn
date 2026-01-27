"""
SENTINEL Core - World-Class Smart Contract Security

Components:
- types: Core data types
- llm: LLM client interface
- agent: Base agent classes
- sentinel: Main auditor orchestrator
- bug_detection: Pattern-based vulnerability detection (8 languages)
- poc_generator: Slop-free PoC generation
- test_templates: Concrete exploit test generation
- report_generator: Professional audit reports
- ultrathink_strict: Zero-slop analysis prompts
- ultrathink_max: Maximum-depth multi-language analysis
- ultrathink_prompts: Protocol-aware prompt building

Advanced Analysis (Beyond Pattern Matching):
- semantic_analyzer: AST-based control/data flow analysis
- symbolic_integration: Slither/Mythril/Halmos/Echidna integration
- economic_analyzer: DeFi economic invariant analysis
- llm_guided: LLM-powered novel vulnerability discovery

New Enhancement Dimensions (advanced/):
- bridge_analyzer: Cross-chain bridge security analysis
- upgrade_safety: Proxy upgrade safety verification
- mev_analyzer: MEV vulnerability detection
- zk_circuit_analyzer: ZK circuit security (Circom/Noir/Cairo/Halo2)
- account_abstraction: ERC-4337 and intent security
- differential_auditor: Version comparison and regression detection
- attack_graph_visualizer: Visual attack path mapping
- slither_deep: Deep Slither integration with custom detectors
- severity_predictor: ML-based severity prediction
- collaborative_audit: Multi-auditor workflow management
"""

# Original types
from .types import (
    AuditState,
    Finding,
    Severity,
    VulnerabilityType,
    ContractInfo,
    FunctionInfo,
)
from .llm import LLMClient, get_llm_client, Tool
from .agent import BaseAgent, HunterAgent

# New modules
from .bug_detection import (
    detect_bugs,
    DetectedBug,
    SolidityBugDetector,
    RustAnchorBugDetector,
    MoveAptosBugDetector,
    MoveSuiBugDetector,
    CairoBugDetector,
    CosmWasmBugDetector,
    VyperBugDetector,
)

from .poc_generator import (
    generate_poc,
    PoCType,
    PoCValidator,
    SlopFreePoCGenerator,
)

from .test_templates import (
    generate_exploit_test,
    TestFramework,
    ConcreteTestGenerator,
)

from .report_generator import (
    generate_report,
    ReportFormat,
    ReportGenerator,
    AuditReport,
)

from .ultrathink_strict import (
    build_strict_prompt,
    validate_finding,
    StrictOutputValidator,
    BANNED_PHRASES,
)

from .ultrathink_max import (
    build_max_ultrathink,
    Language,
    MaxUltrathinkBuilder,
)

from .ultrathink_prompts import (
    build_ultrathink_prompt,
    UltrathinkPromptBuilder,
)

# Advanced Analysis Modules
from .semantic_analyzer import (
    analyze_semantically,
    SemanticAnalyzer,
    CrossContractAnalyzer,
    TaintSource,
    TaintSink,
)

from .symbolic_integration import (
    prove_exploitability,
    SymbolicOrchestrator,
    SlitherIntegration,
    MythrilIntegration,
    HalmosIntegration,
    EchidnaIntegration,
    AnalysisTool,
)

from .economic_analyzer import (
    analyze_economics,
    EconomicAnalyzer,
    EconomicInvariants,
    TokenFlowAnalyzer,
    FlashLoanAnalyzer,
    MEVAnalyzer,
)

from .llm_guided import (
    build_ultimate_prompt,
    LLMGuidedAnalyzer,
    AdversarialReasoning,
    ProtocolSpecificReasoning,
    AnalysisDepth,
)

# New Enhancement Dimensions
from .advanced import (
    # Bridge Security
    BridgeSecurityAnalyzer,
    BridgeVulnerability,
    analyze_bridge,
    # Upgrade Safety
    UpgradeSafetyAnalyzer,
    StorageLayoutAnalyzer,
    check_upgrade_safety,
    # MEV Analysis
    MEVAnalyzer as AdvancedMEVAnalyzer,
    MEVVector,
    analyze_mev,
    # ZK Circuit Analysis
    ZKCircuitAnalyzer,
    ZKLanguage,
    analyze_zk_circuit,
    # Account Abstraction
    AccountAbstractionAnalyzer,
    AAComponent,
    analyze_account_abstraction,
    # Differential Auditing
    DifferentialAuditor,
    ContractDiff,
    compare_versions,
    # Attack Graph Visualization
    AttackGraphVisualizer,
    AttackGraph,
    visualize_findings,
    # Slither Deep Integration
    SlitherDeepIntegration,
    TaintPath,
    run_slither,
    analyze_taint,
    # Severity Prediction
    SeverityPredictor,
    SeverityPrediction,
    predict_severity,
    # Collaborative Audit
    CollaborativeAudit,
    AuditSession,
    AuditorRole,
)

# Trail of Bits Skills
from .skills import (
    # Entry Point Analysis
    EntryPointAnalyzer,
    # Audit Context
    AuditContextBuilder,
    # Review & Analysis
    DifferentialReviewer,
    VariantAnalyzer,
    FixReviewer,
    SharpEdgesAnalyzer,
    # Token Analysis
    TokenIntegrationAnalyzer,
    CodeMaturityAssessor,
    # Static Analysis Integration
    SemgrepIntegration,
    CodeQLIntegration,
    # Specialized Analysis
    ConstantTimeAnalyzer,
    PropertyBasedTestingGuide,
    SpecComplianceChecker,
    # Audit Lifecycle
    AuditPrepAssistant,
    # Vulnerability Scanners
    SolanaVulnerabilityScanner,
    CairoVulnerabilityScanner,
    PlatformScanner,
    ScanReport,
)

__all__ = [
    # Original
    "AuditState",
    "Finding",
    "Severity",
    "VulnerabilityType",
    "ContractInfo",
    "FunctionInfo",
    "LLMClient",
    "get_llm_client",
    "Tool",
    "BaseAgent",
    "HunterAgent",
    # Bug Detection
    "detect_bugs",
    "DetectedBug",
    "SolidityBugDetector",
    "RustAnchorBugDetector",
    "MoveAptosBugDetector",
    "MoveSuiBugDetector",
    "CairoBugDetector",
    "CosmWasmBugDetector",
    "VyperBugDetector",
    # PoC Generation
    "generate_poc",
    "PoCType",
    "PoCValidator",
    "SlopFreePoCGenerator",
    # Test Generation
    "generate_exploit_test",
    "TestFramework",
    "ConcreteTestGenerator",
    # Report Generation
    "generate_report",
    "ReportFormat",
    "ReportGenerator",
    "AuditReport",
    # Ultrathink
    "build_strict_prompt",
    "build_max_ultrathink",
    "build_ultrathink_prompt",
    "validate_finding",
    "Language",
    "BANNED_PHRASES",
    # Semantic Analysis
    "analyze_semantically",
    "SemanticAnalyzer",
    "CrossContractAnalyzer",
    "TaintSource",
    "TaintSink",
    # Symbolic Execution
    "prove_exploitability",
    "SymbolicOrchestrator",
    "SlitherIntegration",
    "MythrilIntegration",
    "HalmosIntegration",
    "EchidnaIntegration",
    "AnalysisTool",
    # Economic Analysis
    "analyze_economics",
    "EconomicAnalyzer",
    "EconomicInvariants",
    "TokenFlowAnalyzer",
    "FlashLoanAnalyzer",
    "MEVAnalyzer",
    # LLM-Guided Analysis
    "build_ultimate_prompt",
    "LLMGuidedAnalyzer",
    "AdversarialReasoning",
    "ProtocolSpecificReasoning",
    "AnalysisDepth",
    # Bridge Security
    "BridgeSecurityAnalyzer",
    "BridgeVulnerability",
    "analyze_bridge",
    # Upgrade Safety
    "UpgradeSafetyAnalyzer",
    "StorageLayoutAnalyzer",
    "check_upgrade_safety",
    # MEV Analysis (Advanced)
    "AdvancedMEVAnalyzer",
    "MEVVector",
    "analyze_mev",
    # ZK Circuit Analysis
    "ZKCircuitAnalyzer",
    "ZKLanguage",
    "analyze_zk_circuit",
    # Account Abstraction
    "AccountAbstractionAnalyzer",
    "AAComponent",
    "analyze_account_abstraction",
    # Differential Auditing
    "DifferentialAuditor",
    "ContractDiff",
    "compare_versions",
    # Attack Graph Visualization
    "AttackGraphVisualizer",
    "AttackGraph",
    "visualize_findings",
    # Slither Deep Integration
    "SlitherDeepIntegration",
    "TaintPath",
    "run_slither",
    "analyze_taint",
    # Severity Prediction
    "SeverityPredictor",
    "SeverityPrediction",
    "predict_severity",
    # Collaborative Audit
    "CollaborativeAudit",
    "AuditSession",
    "AuditorRole",
    # Trail of Bits Skills
    "EntryPointAnalyzer",
    "AuditContextBuilder",
    "DifferentialReviewer",
    "VariantAnalyzer",
    "FixReviewer",
    "SharpEdgesAnalyzer",
    "TokenIntegrationAnalyzer",
    "CodeMaturityAssessor",
    "SemgrepIntegration",
    "CodeQLIntegration",
    "ConstantTimeAnalyzer",
    "PropertyBasedTestingGuide",
    "SpecComplianceChecker",
    "AuditPrepAssistant",
    "SolanaVulnerabilityScanner",
    "CairoVulnerabilityScanner",
    "PlatformScanner",
    "ScanReport",
]
