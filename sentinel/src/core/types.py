"""
Core types and data structures for the Sentinel auditing system.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(Enum):
    """Finding severity levels matching contest standards."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    GAS = "Gas"


class VulnerabilityType(Enum):
    """
    Categories of vulnerabilities.

    Full catalog: knowledge_base/vulnerabilities/catalog.yaml
    """
    # Category 1: Reentrancy
    REENTRANCY = "reentrancy"
    REENTRANCY_CROSS_FUNCTION = "reentrancy_cross_function"
    REENTRANCY_CROSS_CONTRACT = "reentrancy_cross_contract"
    REENTRANCY_READ_ONLY = "reentrancy_read_only"

    # Category 2: Access Control
    ACCESS_CONTROL = "access_control"
    UNPROTECTED_INITIALIZER = "unprotected_initializer"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TX_ORIGIN = "tx_origin"
    MISSING_SIGNER_CHECK = "missing_signer_check"  # Solana
    MISSING_OWNER_CHECK = "missing_owner_check"    # Solana
    CAPABILITY_LEAK = "capability_leak"            # Move

    # Category 3: Oracle
    ORACLE_MANIPULATION = "oracle_manipulation"
    ORACLE_STALE_PRICE = "oracle_stale_price"
    ORACLE_DECIMALS = "oracle_decimals"
    LP_PRICE_MANIPULATION = "lp_price_manipulation"

    # Category 4: Flash Loan
    FLASH_LOAN = "flash_loan"
    FLASH_LOAN_GOVERNANCE = "flash_loan_governance"
    FLASH_LOAN_REWARD = "flash_loan_reward"

    # Category 5: Arithmetic
    ARITHMETIC = "arithmetic"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    PRECISION_LOSS = "precision_loss"
    ROUNDING_ERROR = "rounding_error"
    UNSAFE_CASTING = "unsafe_casting"
    FELT_OVERFLOW = "felt_overflow"  # Cairo

    # Category 6: Signature & Crypto
    SIGNATURE_REPLAY = "signature_replay"
    SIGNATURE_MALLEABILITY = "signature_malleability"
    MISSING_CHAIN_ID = "missing_chain_id"
    WEAK_RANDOMNESS = "weak_randomness"
    HASH_COLLISION = "hash_collision"
    ECRECOVER_ZERO = "ecrecover_zero"

    # Category 7: Front-running & MEV
    FRONTRUNNING = "frontrunning"
    SANDWICH_ATTACK = "sandwich_attack"
    MISSING_SLIPPAGE = "missing_slippage"
    MISSING_DEADLINE = "missing_deadline"

    # Category 8: Denial of Service
    DOS = "denial_of_service"
    UNBOUNDED_LOOP = "unbounded_loop"
    BLOCK_GAS_LIMIT = "block_gas_limit"
    EXTERNAL_CALL_DOS = "external_call_dos"
    GRIEFING = "griefing"
    SELFDESTRUCT_DOS = "selfdestruct_dos"

    # Category 9: Business Logic
    BUSINESS_LOGIC = "business_logic"
    INVARIANT_VIOLATION = "invariant_violation"
    INCORRECT_ACCOUNTING = "incorrect_accounting"
    RACE_CONDITION = "race_condition"
    TIME_MANIPULATION = "time_manipulation"
    OFF_BY_ONE = "off_by_one"
    FIRST_DEPOSITOR = "first_depositor"
    DONATION_ATTACK = "donation_attack"

    # Category 10: Upgradability & Proxy
    UNINITIALIZED_PROXY = "uninitialized_proxy"
    STORAGE_COLLISION = "storage_collision"
    FUNCTION_SELECTOR_CLASH = "function_selector_clash"
    DELEGATECALL = "delegatecall"
    UUPS_MISSING_AUTH = "uups_missing_auth"

    # Category 11: Centralization
    CENTRALIZATION = "centralization"
    SINGLE_POINT_FAILURE = "single_point_failure"
    MISSING_TIMELOCK = "missing_timelock"
    FEE_MANIPULATION = "fee_manipulation"
    GOVERNANCE_MANIPULATION = "governance_manipulation"

    # Category 12: Token Issues
    ERC20_RETURN_VALUE = "erc20_return_value"
    ERC721_REENTRANCY = "erc721_reentrancy"
    NON_STANDARD_TOKEN = "non_standard_token"
    FEE_ON_TRANSFER = "fee_on_transfer"
    REBASING_TOKEN = "rebasing_token"

    # Category 13: Cross-Chain
    BRIDGE_REPLAY = "bridge_replay"
    BRIDGE_UNAUTHORIZED_MINT = "bridge_unauthorized_mint"
    L1_L2_MESSAGING = "l1_l2_messaging"

    # Category 14: Solana-Specific
    ACCOUNT_CONFUSION = "account_confusion"
    PDA_VALIDATION = "pda_validation"
    CLOSING_ACCOUNT = "closing_account"
    ARBITRARY_CPI = "arbitrary_cpi"

    # Category 15: Move-Specific
    RESOURCE_LEAK = "resource_leak"
    OBJECT_SAFETY = "object_safety"
    MODULE_REENTRANCY = "module_reentrancy"

    # Category 16: Cairo-Specific
    CAIRO_STORAGE = "cairo_storage"
    HINTS_ABUSE = "hints_abuse"

    # Category 16b: Soroban/Stellar-Specific
    MISSING_REQUIRE_AUTH = "missing_require_auth"
    AUTH_SUBTREE_MISMATCH = "auth_subtree_mismatch"
    STORAGE_TTL_EXPIRY = "storage_ttl_expiry"
    WRONG_STORAGE_TYPE = "wrong_storage_type"  # Temporary/Persistent/Instance misuse
    UNBOUNDED_INSTANCE_STORAGE = "unbounded_instance_storage"
    EXTEND_TTL_GRIEFING = "extend_ttl_griefing"
    UNPROTECTED_WASM_UPGRADE = "unprotected_wasm_upgrade"
    TYPE_ROUNDTRIP_UNSAFE = "type_roundtrip_unsafe"  # Vec<T>/Map round-trip via Val
    SOROBAN_BUDGET_EXHAUSTION = "soroban_budget_exhaustion"  # CPU/memory metering DoS
    UNSAFE_UNWRAP_CRITICAL = "unsafe_unwrap_critical"  # unwrap/expect in state-changing path
    PANIC_ON_CRITICAL_PATH = "panic_on_critical_path"

    # Category 17: Gas (Informational)
    GAS_OPTIMIZATION = "gas_optimization"

    # Fallback
    OTHER = "other"


class AgentRole(Enum):
    """Roles for different agents in the system."""
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    SPEC_ANALYST = "spec_analyst"
    STATIC_ANALYSIS = "static_analysis"
    VULNERABILITY_HUNTER = "vulnerability_hunter"
    INVARIANT = "invariant"
    FUZZER = "fuzzer"
    ATTACKER = "attacker"
    POC_GENERATOR = "poc_generator"
    REPORTER = "reporter"


@dataclass
class ContractInfo:
    """Information about a single contract."""
    name: str
    path: Path
    source: str
    ast: Optional[dict] = None

    # Extracted info
    functions: list["FunctionInfo"] = field(default_factory=list)
    state_variables: list["StateVariable"] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    inheritance: list[str] = field(default_factory=list)

    # Analysis flags
    is_upgradeable: bool = False
    is_proxy: bool = False
    uses_delegatecall: bool = False
    has_external_calls: bool = False

    # 2026-05-04: NatSpec / contract-level doc-comment block, fed to the
    # spec_skeptic thinker.
    documentation: str = ""


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    visibility: str  # public, external, internal, private
    mutability: str  # pure, view, payable, nonpayable
    parameters: list[dict] = field(default_factory=list)
    returns: list[dict] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)

    # Analysis
    external_calls: list["ExternalCall"] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    source_lines: tuple[int, int] = (0, 0)

    # 2026-05-04: thinker-agent inputs. body is the brace-balanced function
    # body verbatim. line_start / line_end are 1-indexed line numbers in the
    # owning contract source. documentation is the NatSpec block immediately
    # preceding the function declaration. All optional; default empty.
    body: str = ""
    line_start: int = 0
    line_end: int = 0
    documentation: str = ""


@dataclass
class StateVariable:
    """Information about a state variable."""
    name: str
    var_type: str
    visibility: str
    is_constant: bool = False
    is_immutable: bool = False
    slot: Optional[int] = None


@dataclass
class ExternalCall:
    """Information about an external call."""
    target: str  # Contract or address being called
    function: str
    value_sent: bool = False
    in_function: str = ""
    line_number: int = 0


@dataclass
class Finding:
    """A security finding."""
    id: str
    title: str
    severity: Severity
    vulnerability_type: VulnerabilityType
    description: str

    # Location
    contract: str
    function: Optional[str] = None
    line_numbers: tuple[int, int] = (0, 0)

    # Details
    impact: str = ""
    root_cause: str = ""
    recommendation: str = ""

    # Validation
    poc: Optional["PoC"] = None
    validated: bool = False
    false_positive: bool = False

    # Metadata
    found_by: AgentRole = AgentRole.VULNERABILITY_HUNTER
    found_by_hunter: str = ""  # Per-hunter class name (set automatically by add_finding)
    confidence: float = 0.0  # 0-1
    timestamp: datetime = field(default_factory=datetime.now)

    # Related
    related_findings: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # Pre-DevilsAdvocate static prefilter signals (intent_check,
    # default_value_check, dupe_check). Populated by src/agents/intent_checker.py,
    # default_value_pruner.py, dupe_scrubber.py. DevilsAdvocate reads these
    # to soften / reinforce its severity calibration without re-running the
    # static analysis. Kept out of the report-facing fields above.
    metadata: dict = field(default_factory=dict)


@dataclass
class PoC:
    """Proof of Concept exploit."""
    finding_id: str
    code: str
    language: str = "solidity"  # solidity or foundry test

    # Execution results
    executed: bool = False
    success: bool = False
    output: str = ""
    profit: Optional[float] = None  # In ETH/USD if applicable

    # Generation metadata
    iterations: int = 0
    gas_used: int = 0
    template_used: str = ""

    # Fork info
    fork_url: Optional[str] = None
    fork_block: Optional[int] = None


@dataclass
class Invariant:
    """A protocol invariant to test."""
    id: str
    description: str
    expression: str  # Solidity expression that should always be true

    # Source
    source: str  # "inferred", "documented", "manual"
    contract: str

    # Testing
    test_code: Optional[str] = None
    violated: bool = False
    violation_input: Optional[dict] = None


@dataclass
class ArchitectureAnalysis:
    """High-level architecture analysis results."""
    # Patterns detected
    is_upgradeable: bool = False
    proxy_type: Optional[str] = None  # "transparent", "uups", "beacon", etc.
    uses_access_control: bool = False
    access_control_type: Optional[str] = None  # "ownable", "roles", "custom"

    # DeFi patterns
    is_defi: bool = False
    defi_type: list[str] = field(default_factory=list)  # "lending", "amm", "vault", etc.
    uses_oracles: bool = False
    oracle_type: list[str] = field(default_factory=list)

    # External interactions
    external_protocols: list[str] = field(default_factory=list)
    token_interactions: list[str] = field(default_factory=list)

    # Trust boundaries
    trusted_contracts: list[str] = field(default_factory=list)
    admin_functions: list[str] = field(default_factory=list)

    # Entry points
    entry_points: list[str] = field(default_factory=list)

    # Notes
    notes: list[str] = field(default_factory=list)


@dataclass
class ProtocolIntent:
    """What the protocol is designed to do — used to distinguish bugs from features."""
    protocol_type: str = ""                                  # "DEX", "Lending", "Governance", "Staking", etc.
    core_invariants: list[str] = field(default_factory=list)  # "total_deposits >= total_shares * price_per_share"
    fund_flows: list[str] = field(default_factory=list)       # "Users deposit TOKEN_A -> mint shares -> earn yield"
    trust_model: dict[str, list[str]] = field(default_factory=dict)  # {"owner": ["upgrade", "pause"], "anyone": ["deposit"]}
    intentional_restrictions: list[str] = field(default_factory=list) # "buOLAS transfers are intentionally disabled"
    critical_state_transitions: list[str] = field(default_factory=list) # "Service state: ACTIVE -> TERMINATED requires multisig"
    admin_capabilities: list[str] = field(default_factory=list)   # "Owner can change slippage params, implementation, managers"
    external_dependencies: list[str] = field(default_factory=list) # "Price depends on Chainlink ETH/USD feed"


@dataclass
class SlitherResult:
    """Parsed Slither analysis result."""
    detector: str
    severity: str
    confidence: str
    description: str
    contract: str
    function: Optional[str] = None
    lines: list[int] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class KnownFinding:
    """A vulnerability already known to the project (audit finding, acknowledged
    bounty issue, etc.). Hunters get this list as a dedupe filter so they stop
    re-discovering issues the team has already paid auditors to find.
    """
    id: str  # e.g. "L02", "TOB-M0V2-1", "Adevar M01"
    title: str
    severity: str = ""  # "Critical"/"High"/"Medium"/"Low"/"Acknowledged"
    status: str = ""  # "Resolved", "Acknowledged", "Fixed", "Open"
    source: str = ""  # "audits/adevar_v2.pdf", "bounty:immunefi/kast", etc.
    description: str = ""  # short blurb if available
    affected_files: list[str] = field(default_factory=list)


@dataclass
class AuditState:
    """Complete state of an ongoing audit."""
    # Target
    target_path: Path
    target_name: str

    # Contracts
    contracts: list[ContractInfo] = field(default_factory=list)

    # Analysis results
    architecture: Optional[ArchitectureAnalysis] = None
    slither_results: list[SlitherResult] = field(default_factory=list)

    # Findings
    findings: list[Finding] = field(default_factory=list)

    # Audit intel (Phase 1.5) - drives hunter dedupe
    audit_dir: Optional[Path] = None
    known_findings: list[KnownFinding] = field(default_factory=list)
    priority_files: list[str] = field(default_factory=list)  # post-audit-changed files
    # X-ray prior context: stated invariants extracted from the x-ray.md
    # report. Consumed by DevilsAdvocate (divergence-confidence boost) and
    # PoC generator (test seeding from documented protocol claims).
    xray_invariants: list[str] = field(default_factory=list)
    # 2026-05 addition: PR-level diff against the audited commit.
    # audit_baseline_commit is the SHA of the commit Pashov/etc. reviewed.
    # pr_diffs maps PR-label to list of changed files in that PR.
    # Used by Scope.POST_AUDIT and Scope.PR scope iterators in scoping.py.
    audit_baseline_commit: Optional[str] = None
    pr_diffs: dict = field(default_factory=dict)

    # Invariants
    invariants: list[Invariant] = field(default_factory=list)

    # PoCs
    pocs: list[PoC] = field(default_factory=list)

    # Cross-contract analysis
    dependency_graph: Optional["ContractDependencyGraph"] = None

    # Protocol intent (design understanding)
    protocol_intent: Optional[ProtocolIntent] = None

    # Vulnerability cheatsheet (Tier 1 knowledge for hunters)
    vulnerability_cheatsheet: str = ""

    # Documentation (if provided)
    documentation: Optional[str] = None

    # Audit depth
    depth: str = "standard"  # "fast", "standard", "deep"

    # No-LLM mode: when set, orchestrator runs only zero-cost phases
    # (audit-intel, recon file scan, slither, audit-diff) and dumps the
    # checkpoint for an external driver to consume. Used by the
    # `sentinel-hunt` Claude Code skill to avoid burning Anthropic credits
    # while still leveraging Sentinel's static-analysis pipeline.
    no_llm: bool = False

    # Metadata
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    api_calls: int = 0
    api_cost: float = 0.0

    # Logs
    logs: list[str] = field(default_factory=list)

    # Per-hunter telemetry — populated post-hunter from LLMClient.per_attribution.
    # Schema per key (hunter name): {calls, input_tokens, output_tokens,
    # thinking_tokens, cost, findings, findings_post_validation,
    # findings_matched_corpus, runtime_seconds}.
    hunter_telemetry: dict = field(default_factory=dict)

    # Thinker hypotheses (Point 1). Hypotheses are NOT findings — they are
    # "what-if" prompts emitted by the mental-operation thinkers in
    # src/agents/thinkers/. The confirmer / FP gate phase decides which ones
    # are promoted to Findings.
    hypotheses: list = field(default_factory=list)

    # Surface tag profile (Point 3). Populated by src/core/surface_tags.py.
    # Drives specialist dispatch: tag-gated specialists are skipped if their
    # required tags are absent, freeing subagent budget for the surface that
    # actually exists.
    surface_profile: dict = field(default_factory=dict)

    # FP gate reports (Point 2). Per-finding deterministic-check verdicts.
    # Schema: list[GateReport.to_dict()].
    fp_gate_reports: list = field(default_factory=list)

    # Auto-PoC validator results (Point 4). Per-finding forge test outcomes.
    # Schema: list[ValidationOutcome.to_dict()].
    auto_poc_results: list = field(default_factory=list)

    def add_log(self, message: str) -> None:
        """Add a timestamped log entry."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, checking for duplicates."""
        # Tag with current hunter attribution if not already set.
        # Lazy import keeps types.py free of llm.py imports.
        if not finding.found_by_hunter:
            try:
                from .llm import current_attribution
                finding.found_by_hunter = current_attribution() or ""
            except Exception:
                pass

        # Simple dedup by title and contract
        for existing in self.findings:
            if existing.title == finding.title and existing.contract == finding.contract:
                return
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_validated_findings(self) -> list[Finding]:
        """Get all validated findings."""
        return [f for f in self.findings if f.validated and not f.false_positive]

    def get_known_findings_prompt(self) -> str:
        """Markdown block listing known findings, ready for hunter prompt injection.

        Hunters that include this in their system prompt will dedupe against the
        listed issues instead of re-reporting them. Empty string when no audit
        intel was loaded.
        """
        if not self.known_findings:
            return ""
        lines = [
            "## Already-Known Findings (DO NOT RE-REPORT)",
            "",
            "These vulnerabilities have already been documented by prior auditors or",
            "acknowledged on the bounty page. Reporting any of these as a finding",
            "wastes triage time and gets the report rejected as a duplicate.",
            "Pivot AWAY from these surfaces toward adjacent unexplored code.",
            "",
        ]
        for kf in self.known_findings:
            sev = f" [{kf.severity}]" if kf.severity else ""
            status = f" ({kf.status})" if kf.status else ""
            src = f" — {kf.source}" if kf.source else ""
            lines.append(f"- **{kf.id}**{sev}{status}: {kf.title}{src}")
            if kf.description:
                lines.append(f"  - {kf.description[:200]}")
            if kf.affected_files:
                lines.append(f"  - files: {', '.join(kf.affected_files[:3])}")
        if self.priority_files:
            lines.append("")
            lines.append("## Priority Files (post-latest-audit changes)")
            lines.append("")
            lines.append("Lines in these files were modified AFTER the latest audit.")
            lines.append("They are the highest-EV targets — auditors have not seen them.")
            lines.append("")
            for pf in self.priority_files[:30]:
                lines.append(f"- {pf}")
        lines.append("")
        return "\n".join(lines)

    def get_few_shot_prompt(self, k_pos: int = 5, k_neg: int = 5) -> str:
        """Render the cross-contest exemplar few-shot block, scoped to this
        codebase's surface tags. Empty string if no exemplars match.

        Reads from sentinel/knowledge_base/exemplars_{accepted,rejected}/.
        Positive examples are prior wins on the same surface; negative
        examples are prior dismissals (with structured rejection reasons)
        that LOOKED filable. Both are useful: positive teaches the shape,
        negative teaches the FP shape.
        """
        try:
            from .exemplar_loop import build_few_shot_for
        except Exception:
            return ""
        tags = list((self.surface_profile or {}).get("tags", []) or [])
        if not tags:
            return ""
        # Best-effort language mapping based on detected files.
        lang = "solidity"
        for c in self.contracts:
            path = str(getattr(c, "path", "")).lower()
            if path.endswith((".rs",)):
                lang = "rust"; break
            if path.endswith((".move",)):
                lang = "move"; break
            if path.endswith((".cairo",)):
                lang = "cairo"; break
        try:
            block = build_few_shot_for(target_tags=tags, target_lang=lang, k_pos=k_pos, k_neg=k_neg)
        except Exception:
            return ""
        return block.strip()

    def get_hunter_prefix(self) -> str:
        """Concatenated prompt prefix for hunters: known-findings dedupe block
        + cross-contest few-shot exemplars. Empty string if neither applies.

        This is the single entry point hunters should call instead of
        `get_known_findings_prompt()` directly. Hunters that already call
        the older method continue to work; new hunters and the post-2026-05
        upgrade should use this one.
        """
        parts: list[str] = []
        kf = self.get_known_findings_prompt()
        if kf:
            parts.append(kf)
        fs = self.get_few_shot_prompt()
        if fs:
            parts.append(fs)
        return ("\n\n---\n\n").join(parts)

    def save_checkpoint(self, path: Path) -> None:
        """Serialize state to JSON for resume after credit exhaustion."""
        def _serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Path):
                return str(obj)
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, set):
                return list(obj)
            raise TypeError(f"Cannot serialize {type(obj)}")

        data = asdict(self)
        path.write_text(json.dumps(data, default=_serialize, indent=2))

    @classmethod
    def load_checkpoint(cls, path: Path) -> "AuditState":
        """Deserialize state from JSON checkpoint."""
        data = json.loads(path.read_text())

        # Reconstruct findings with proper enum types
        findings = []
        for f in data.get("findings", []):
            findings.append(Finding(
                id=f["id"],
                title=f["title"],
                severity=Severity(f["severity"]),
                vulnerability_type=VulnerabilityType(f["vulnerability_type"]),
                description=f["description"],
                contract=f["contract"],
                function=f.get("function"),
                line_numbers=tuple(f.get("line_numbers", (0, 0))),
                impact=f.get("impact", ""),
                root_cause=f.get("root_cause", ""),
                recommendation=f.get("recommendation", ""),
                validated=f.get("validated", False),
                false_positive=f.get("false_positive", False),
                found_by=AgentRole(f.get("found_by", "vulnerability_hunter")),
                confidence=f.get("confidence", 0.0),
                related_findings=f.get("related_findings", []),
                references=f.get("references", []),
            ))

        # Reconstruct contracts (minimal — enough for PoC generation)
        contracts = []
        for c in data.get("contracts", []):
            contracts.append(ContractInfo(
                name=c["name"],
                path=Path(c["path"]),
                source=c["source"],
            ))

        state = cls(
            target_path=Path(data["target_path"]),
            target_name=data["target_name"],
            depth=data.get("depth", "standard"),
        )
        state.contracts = contracts
        state.findings = findings
        state.logs = data.get("logs", [])
        return state


@dataclass
class CrossContractCall:
    """A call from one contract to another."""
    source_contract: str
    source_function: str
    target_contract: str
    target_function: str
    data_passed: list[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class CrossContractFlow:
    """A critical data flow across contracts."""
    flow_type: str  # "oracle->consumer", "balance->pricing", "auth->proxy"
    description: str
    contracts_involved: list[str] = field(default_factory=list)
    calls: list[CrossContractCall] = field(default_factory=list)
    risk_level: str = "medium"  # "low", "medium", "high", "critical"


@dataclass
class ContractDependencyGraph:
    """Dependency graph between contracts."""
    nodes: list[str] = field(default_factory=list)  # Contract names
    edges: list[CrossContractCall] = field(default_factory=list)
    critical_flows: list[CrossContractFlow] = field(default_factory=list)

    def get_dependents(self, contract: str) -> list[str]:
        """Get contracts that depend on (call into) this contract."""
        return list({e.source_contract for e in self.edges if e.target_contract == contract})

    def get_dependencies(self, contract: str) -> list[str]:
        """Get contracts this contract depends on (calls into)."""
        return list({e.target_contract for e in self.edges if e.source_contract == contract})


@dataclass
class ToolResult:
    """Result from a tool execution."""
    tool_name: str
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class AgentMessage:
    """Message passed between agents."""
    from_agent: AgentRole
    to_agent: AgentRole
    message_type: str  # "request", "response", "finding", "status"
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)
