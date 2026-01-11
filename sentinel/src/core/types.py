"""
Core types and data structures for the Sentinel auditing system.
"""

from dataclasses import dataclass, field
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
    confidence: float = 0.0  # 0-1
    timestamp: datetime = field(default_factory=datetime.now)

    # Related
    related_findings: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


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

    # Invariants
    invariants: list[Invariant] = field(default_factory=list)

    # PoCs
    pocs: list[PoC] = field(default_factory=list)

    # Documentation (if provided)
    documentation: Optional[str] = None

    # Metadata
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    api_calls: int = 0
    api_cost: float = 0.0

    # Logs
    logs: list[str] = field(default_factory=list)

    def add_log(self, message: str) -> None:
        """Add a timestamped log entry."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, checking for duplicates."""
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
