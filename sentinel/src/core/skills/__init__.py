"""
SENTINEL Skills - Trail of Bits Inspired Security Skills

Based on https://github.com/trailofbits/skills
Comprehensive security analysis skills for smart contract auditing.

Entry Point Analysis:
- entry_point_analyzer: Identify state-changing entry points for audits

Context Building:
- audit_context_builder: Deep context building before vulnerability hunting
- spec_compliance_checker: Verify code implements spec exactly

Review & Analysis:
- differential_review: Security-focused code change review
- variant_analyzer: Find similar vulnerabilities across codebase
- fix_reviewer: Verify fixes address audit findings
- sharp_edges: Find dangerous API designs and footguns

Vulnerability Scanners (Platform-Specific):
- solana_scanner: Solana/Anchor vulnerabilities (CPI, PDA, signer checks)
- cairo_scanner: Cairo/StarkNet vulnerabilities (L1-L2, felt252, signatures)
- cosmos_scanner: CosmWasm vulnerabilities
- ton_scanner: TON/FunC/Tact vulnerabilities
- substrate_scanner: Substrate/Polkadot vulnerabilities
- algorand_scanner: Algorand vulnerabilities

Token Analysis:
- token_integration_analyzer: ERC20/ERC721 integration security

Audit Lifecycle:
- audit_prep_assistant: Prepare codebase for security review
- code_maturity_assessor: 9-category maturity assessment

Static Analysis Integration:
- semgrep_integration: Semgrep rule creation and scanning
- codeql_integration: CodeQL database and query management

Specialized Analysis:
- constant_time_analyzer: Timing side-channel detection
- property_based_testing: PBT guidance for smart contracts

Community-Sourced Skills:
- solcurity_checker: Automated Solcurity checklist (100+ items, 12 categories)
- audit_workflow: 5-phase LLM-assisted audit workflow (MixBytes + pontifex73)
- move_scanner: Move/Aptos/Sui vulnerability scanner (MVD v2.0, 501 findings)

AI-Assisted Security (SavantChat + Kritt.ai + Nethermind):
- agentic_harness: Verification-driven vulnerability research pipeline
- decompilation_workflow: AI-assisted bytecode decompilation and recovery

Vulnerability Intelligence (Immunefi):
- immunefi_taxonomy: 14-class vulnerability taxonomy with SCSVS standard and exploit DB
- bug_bounty_rules: Immunefi compliance checker, pre-submission review, severity guide
- immunefi_reports: Published report intelligence (1,970+ reports, pattern rankings, scan plans)
- competitive_audit_intel: Cross-platform intel (C4 + Sherlock + Immunefi + Secureum)
"""

# Entry Point Analysis
from .entry_point_analyzer import (
    EntryPointAnalyzer,
    EntryPoint,
    AccessLevel,
    analyze_entry_points,
)

# Context Building
from .audit_context_builder import (
    AuditContextBuilder,
    FunctionAnalysis,
    SystemContext,
    build_audit_context,
)

from .spec_compliance_checker import (
    SpecComplianceChecker,
    SpecIR,
    CodeIR,
    AlignmentRecord,
    check_compliance,
)

# Review & Analysis
from .differential_review import (
    DifferentialReviewer,
    CodeChange,
    ReviewFinding,
    review_changes,
)

from .variant_analyzer import (
    VariantAnalyzer,
    VulnerabilityPattern,
    Variant,
    find_variants,
)

from .fix_reviewer import (
    FixReviewer,
    FixStatus,
    FixVerification,
    verify_fixes,
)

from .sharp_edges import (
    SharpEdgesAnalyzer,
    SharpEdge,
    FootgunCategory,
    find_sharp_edges,
)

# Token Analysis
from .token_integration_analyzer import (
    TokenIntegrationAnalyzer,
    TokenPattern,
    WeirdToken,
    analyze_token_integration,
)

# Audit Lifecycle
from .audit_prep_assistant import (
    AuditPrepAssistant,
    PrepChecklist,
    PrepStatus,
    prepare_for_audit,
)

from .code_maturity_assessor import (
    CodeMaturityAssessor,
    MaturityCategory,
    MaturityRating,
    MaturityReport,
    assess_maturity,
)

# Static Analysis Integration
from .semgrep_integration import (
    SemgrepIntegration,
    SemgrepRule,
    SemgrepResult,
    run_semgrep,
    create_semgrep_rule,
)

from .codeql_integration import (
    CodeQLIntegration,
    CodeQLQuery,
    CodeQLResult,
    run_codeql,
    create_codeql_database,
)

# Specialized Analysis
from .constant_time_analyzer import (
    ConstantTimeAnalyzer,
    TimingViolation,
    analyze_constant_time,
)

from .property_based_testing import (
    PropertyBasedTestingGuide,
    PropertyType,
    TestStrategy,
    suggest_properties,
)

# Vulnerability Scanners
from .vulnerability_scanners import (
    SolanaVulnerabilityScanner,
    CairoVulnerabilityScanner,
    CosmosVulnerabilityScanner,
    TONVulnerabilityScanner,
    SubstrateVulnerabilityScanner,
    AlgorandVulnerabilityScanner,
    scan_solana,
    scan_cairo,
    scan_cosmos,
    scan_ton,
    scan_substrate,
    scan_algorand,
    MoveVulnerabilityScanner,
    scan_move,
)

# Community-Sourced Skills
from .solcurity_checker import (
    SolcurityChecker,
    SolcurityReport,
    CheckCategory,
    check_solcurity,
)

from .audit_workflow import (
    AuditWorkflowEngine,
    AuditWorkflow,
    AuditPhase,
    TestingMindset,
    create_audit_workflow,
)

# AI-Assisted Security
from .agentic_harness import (
    AgenticHarness,
    Hypothesis,
    HypothesisConfidence,
    ResearchPhase,
    ResearchSession,
    create_research_session,
)

from .decompilation_workflow import (
    DecompilationWorkflow,
    DecompilationReport,
    RecoveredFunction,
    RecoveryPhase,
    create_decompilation_workflow,
)

# Vulnerability Intelligence
from .immunefi_taxonomy import (
    ImmunefiTaxonomy,
    VulnClass,
    VulnPattern,
    ExploitReference,
    SCVSCategory,
    create_immunefi_taxonomy,
)

from .bug_bounty_rules import (
    BugBountyCompliance,
    SubmissionReview,
    ReportQuality,
    Violation,
    create_compliance_checker,
)

from .immunefi_reports import (
    ImmunefiReportsIntel,
    AuditCompetition,
    NotableFinding,
    FindingSeverity,
    create_reports_intel,
)

from .competitive_audit_intel import (
    CompetitiveAuditIntel,
    CrossPlatformPattern,
    Platform,
    create_competitive_intel,
)

__all__ = [
    # Entry Point Analysis
    "EntryPointAnalyzer",
    "EntryPoint",
    "AccessLevel",
    "analyze_entry_points",
    # Context Building
    "AuditContextBuilder",
    "FunctionAnalysis",
    "SystemContext",
    "build_audit_context",
    "SpecComplianceChecker",
    "SpecIR",
    "CodeIR",
    "AlignmentRecord",
    "check_compliance",
    # Review & Analysis
    "DifferentialReviewer",
    "CodeChange",
    "ReviewFinding",
    "review_changes",
    "VariantAnalyzer",
    "VulnerabilityPattern",
    "Variant",
    "find_variants",
    "FixReviewer",
    "FixStatus",
    "FixVerification",
    "verify_fixes",
    "SharpEdgesAnalyzer",
    "SharpEdge",
    "FootgunCategory",
    "find_sharp_edges",
    # Token Analysis
    "TokenIntegrationAnalyzer",
    "TokenPattern",
    "WeirdToken",
    "analyze_token_integration",
    # Audit Lifecycle
    "AuditPrepAssistant",
    "PrepChecklist",
    "PrepStatus",
    "prepare_for_audit",
    "CodeMaturityAssessor",
    "MaturityCategory",
    "MaturityRating",
    "MaturityReport",
    "assess_maturity",
    # Static Analysis Integration
    "SemgrepIntegration",
    "SemgrepRule",
    "SemgrepResult",
    "run_semgrep",
    "create_semgrep_rule",
    "CodeQLIntegration",
    "CodeQLQuery",
    "CodeQLResult",
    "run_codeql",
    "create_codeql_database",
    # Specialized Analysis
    "ConstantTimeAnalyzer",
    "TimingViolation",
    "analyze_constant_time",
    "PropertyBasedTestingGuide",
    "PropertyType",
    "TestStrategy",
    "suggest_properties",
    # Vulnerability Scanners
    "SolanaVulnerabilityScanner",
    "CairoVulnerabilityScanner",
    "CosmosVulnerabilityScanner",
    "TONVulnerabilityScanner",
    "SubstrateVulnerabilityScanner",
    "AlgorandVulnerabilityScanner",
    "scan_solana",
    "scan_cairo",
    "scan_cosmos",
    "scan_ton",
    "scan_substrate",
    "scan_algorand",
    # Community-Sourced Skills
    "SolcurityChecker",
    "SolcurityReport",
    "CheckCategory",
    "check_solcurity",
    "AuditWorkflowEngine",
    "AuditWorkflow",
    "AuditPhase",
    "TestingMindset",
    "create_audit_workflow",
    "MoveVulnerabilityScanner",
    "scan_move",
    # AI-Assisted Security
    "AgenticHarness",
    "Hypothesis",
    "HypothesisConfidence",
    "ResearchPhase",
    "ResearchSession",
    "create_research_session",
    "DecompilationWorkflow",
    "DecompilationReport",
    "RecoveredFunction",
    "RecoveryPhase",
    "create_decompilation_workflow",
    # Vulnerability Intelligence
    "ImmunefiTaxonomy",
    "VulnClass",
    "VulnPattern",
    "ExploitReference",
    "SCVSCategory",
    "create_immunefi_taxonomy",
    # Bug Bounty Compliance
    "BugBountyCompliance",
    "SubmissionReview",
    "ReportQuality",
    "Violation",
    "create_compliance_checker",
    # Immunefi Reports Intelligence
    "ImmunefiReportsIntel",
    "AuditCompetition",
    "NotableFinding",
    "FindingSeverity",
    "create_reports_intel",
    # Competitive Audit Intelligence
    "CompetitiveAuditIntel",
    "CrossPlatformPattern",
    "Platform",
    "create_competitive_intel",
]
