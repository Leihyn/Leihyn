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
]
