"""
Immunefi Web3 Security Taxonomy - Vulnerability Classification & Exploit Patterns

Based on https://github.com/immunefi-team/Web3-Security-Library
Structured vulnerability taxonomy with 14 classes, real-world exploit references,
and SCSVS (Smart Contract Security Verification Standard) integration.

Key sources:
- Immunefi Web3-Security-Library (2.1k stars, community-curated)
- SCSVS: 14-category smart contract security verification standard
- SWC Registry: Smart Contract Weakness Classification
- Secureum Audit Findings 101 & 201
- 101 DeFi hack root cause analyses (Sunsec)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnClass(Enum):
    """Immunefi vulnerability taxonomy - 14 classes."""
    BAD_ARITHMETIC = "bad_arithmetic"
    INTEGER_OVERFLOW = "integer_overflow"
    REENTRANCY = "reentrancy"
    UNINITIALIZED_PROXY = "uninitialized_proxy"
    DELEGATECALL_INJECTION = "delegatecall_injection"
    WEAK_ACCESS_CONTROL = "weak_access_control"
    WRONG_STANDARD_IMPL = "wrong_standard_impl"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    UNCHECKED_RETURN = "unchecked_return"
    MEV_REORG = "mev_reorg"
    BAD_RANDOMNESS = "bad_randomness"
    KNOWN_VULNERABLE_COMPONENTS = "known_vulnerable_components"
    BRIDGE_VULNERABILITY = "bridge_vulnerability"


class SCVSCategory(Enum):
    """SCSVS - Smart Contract Security Verification Standard (14 paths)."""
    ARCHITECTURE = "V1"
    ACCESS_CONTROL = "V2"
    BLOCKCHAIN_DATA = "V3"
    COMMUNICATIONS = "V4"
    ARITHMETIC = "V5"
    MALICIOUS_INPUT = "V6"
    GAS_USAGE = "V7"
    BUSINESS_LOGIC = "V8"
    DENIAL_OF_SERVICE = "V9"
    TOKEN = "V10"
    CODE_CLARITY = "V11"
    TEST_COVERAGE = "V12"
    KNOWN_ATTACKS = "V13"
    DEFI_SPECIFIC = "V14"


@dataclass
class ExploitReference:
    """Real-world exploit reference from Immunefi database."""
    name: str
    date: str
    amount_usd: str
    vuln_class: VulnClass
    root_cause: str
    chain: str = "ethereum"
    post_mortem_url: str = ""


@dataclass
class VulnPattern:
    """A vulnerability pattern with detection guidance."""
    vuln_class: VulnClass
    title: str
    description: str
    detection_hints: list[str]
    swc_id: str = ""  # SWC Registry ID
    scsvs_category: Optional[SCVSCategory] = None
    code_pattern: str = ""  # Regex or keyword pattern
    real_exploits: list[ExploitReference] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"### {self.title}",
            f"**Class**: {self.vuln_class.value}",
            f"**SWC**: {self.swc_id}" if self.swc_id else "",
            f"**SCSVS**: {self.scsvs_category.value}" if self.scsvs_category else "",
            "",
            self.description,
            "",
            "**Detection Hints:**",
        ]
        for h in self.detection_hints:
            lines.append(f"- {h}")
        if self.real_exploits:
            lines.append("")
            lines.append("**Real-World Exploits:**")
            for e in self.real_exploits:
                lines.append(f"- {e.name} ({e.date}) - {e.amount_usd}: {e.root_cause}")
        return "\n".join(lines)


# Major exploit references from Immunefi hack analyses
MAJOR_EXPLOITS = [
    ExploitReference(
        name="Beanstalk",
        date="2022-04",
        amount_usd="$181M",
        vuln_class=VulnClass.FLASH_LOAN,
        root_cause="Flash loan used to gain governance majority and drain funds",
        chain="ethereum",
    ),
    ExploitReference(
        name="Nomad Bridge",
        date="2022-08",
        amount_usd="$190M",
        vuln_class=VulnClass.BRIDGE_VULNERABILITY,
        root_cause="Zero hash accepted as valid Merkle root after upgrade",
        chain="ethereum",
    ),
    ExploitReference(
        name="Binance Bridge",
        date="2022-10",
        amount_usd="$600M",
        vuln_class=VulnClass.BRIDGE_VULNERABILITY,
        root_cause="IAVL Merkle proof verification weakness",
        chain="bnb",
    ),
    ExploitReference(
        name="BonqDAO",
        date="2023-02",
        amount_usd="$120M",
        vuln_class=VulnClass.ORACLE_MANIPULATION,
        root_cause="Direct price oracle manipulation without TWAP protection",
        chain="polygon",
    ),
    ExploitReference(
        name="C.R.E.A.M. Finance",
        date="2021-10",
        amount_usd="$130M",
        vuln_class=VulnClass.ORACLE_MANIPULATION,
        root_cause="Oracle manipulation via uncapped token supply",
        chain="ethereum",
    ),
    ExploitReference(
        name="Platypus Finance",
        date="2023-02",
        amount_usd="$8.5M",
        vuln_class=VulnClass.FLASH_LOAN,
        root_cause="Flash loan exploited solvency check logic flaw",
        chain="avalanche",
    ),
]

# Immunefi vulnerability taxonomy with detection guidance
VULN_TAXONOMY: list[VulnPattern] = [
    VulnPattern(
        vuln_class=VulnClass.BAD_ARITHMETIC,
        title="Bad Arithmetic",
        description="Incorrect decimal assumptions, rounding errors, or arithmetic logic flaws.",
        swc_id="SWC-101",
        scsvs_category=SCVSCategory.ARITHMETIC,
        detection_hints=[
            "Division before multiplication (precision loss)",
            "Hardcoded decimal assumptions (not all ERC20 are 18 decimals)",
            "External function return value used without validation",
            "Fee calculations with rounding in wrong direction",
        ],
        code_pattern=r"(\/ \d+.*\* \d+|decimals\(\)|10\*\*18)",
    ),
    VulnPattern(
        vuln_class=VulnClass.INTEGER_OVERFLOW,
        title="Integer Underflow/Overflow",
        description="Unchecked arithmetic in pre-0.8.0 or in unchecked blocks.",
        swc_id="SWC-101",
        scsvs_category=SCVSCategory.ARITHMETIC,
        detection_hints=[
            "Solidity < 0.8.0 without SafeMath",
            "unchecked {} blocks with user-influenced values",
            "Type casting between different integer sizes",
            "Negative values in unsigned contexts",
        ],
        code_pattern=r"(unchecked\s*\{|uint8|uint16|SafeMath)",
    ),
    VulnPattern(
        vuln_class=VulnClass.REENTRANCY,
        title="Reentrancy",
        description="State changes after external calls allow re-entry and state manipulation.",
        swc_id="SWC-107",
        scsvs_category=SCVSCategory.KNOWN_ATTACKS,
        detection_hints=[
            "External calls before state updates (violates CEI)",
            "Cross-function reentrancy via shared state",
            "Read-only reentrancy through view functions during callbacks",
            "ERC-777 token hooks enabling re-entry",
            "Missing ReentrancyGuard on state-changing functions",
        ],
        code_pattern=r"(\.call\{value|\.transfer\(|\.send\(|onERC721Received|tokensReceived)",
    ),
    VulnPattern(
        vuln_class=VulnClass.UNINITIALIZED_PROXY,
        title="Uninitialized Contracts/Proxies",
        description="Proxy implementation not initialized, allowing attacker to take ownership.",
        swc_id="SWC-109",
        scsvs_category=SCVSCategory.ARCHITECTURE,
        detection_hints=[
            "Implementation contract without initializer call in constructor",
            "Missing _disableInitializers() in implementation constructor",
            "Storage collision between proxy and implementation",
            "Unprotected initialize() function callable by anyone",
        ],
        code_pattern=r"(initialize\(|initializer|_disableInitializers|delegatecall)",
    ),
    VulnPattern(
        vuln_class=VulnClass.DELEGATECALL_INJECTION,
        title="Code Injection via Delegatecall",
        description="User-controlled address in delegatecall target.",
        swc_id="SWC-112",
        scsvs_category=SCVSCategory.MALICIOUS_INPUT,
        detection_hints=[
            "User input flows to delegatecall target address",
            "No allowlist on delegatecall destinations",
            "Proxy pattern without proper access control on upgrade",
        ],
        code_pattern=r"delegatecall\(",
    ),
    VulnPattern(
        vuln_class=VulnClass.WEAK_ACCESS_CONTROL,
        title="Weak Access Control",
        description="Missing or bypassable authorization on privileged functions.",
        swc_id="SWC-115",
        scsvs_category=SCVSCategory.ACCESS_CONTROL,
        detection_hints=[
            "tx.origin used for authentication",
            "Missing onlyOwner/onlyRole modifiers on state-changing functions",
            "Signature replay (missing nonce or chain ID)",
            "msg.value reused in loops (multi-call value duplication)",
        ],
        code_pattern=r"(tx\.origin|onlyOwner|hasRole|ecrecover)",
    ),
    VulnPattern(
        vuln_class=VulnClass.WRONG_STANDARD_IMPL,
        title="Wrong Implementation of Standards",
        description="Deviations from ERC standards causing integration failures.",
        swc_id="",
        scsvs_category=SCVSCategory.TOKEN,
        detection_hints=[
            "ERC20 missing return values (USDT pattern)",
            "Fee-on-transfer tokens not accounted for",
            "ERC721 without safeTransferFrom callback handling",
            "ERC4626 share/asset calculation edge cases",
        ],
        code_pattern=r"(transferFrom|safeTransferFrom|ERC20|ERC721|ERC4626)",
    ),
    VulnPattern(
        vuln_class=VulnClass.FLASH_LOAN,
        title="Flash Loan Attacks",
        description="Single-transaction borrowing exploiting protocol assumptions.",
        swc_id="",
        scsvs_category=SCVSCategory.DEFI_SPECIFIC,
        detection_hints=[
            "Governance voting without time-lock",
            "Price calculations using spot reserves",
            "Solvency checks manipulable within single transaction",
            "Large capital requirements assumed as security measure",
        ],
        code_pattern=r"(flashLoan|flashMint|balanceOf\(address\(this\)\))",
        real_exploits=[e for e in MAJOR_EXPLOITS if e.vuln_class == VulnClass.FLASH_LOAN],
    ),
    VulnPattern(
        vuln_class=VulnClass.ORACLE_MANIPULATION,
        title="Oracle Price Manipulation",
        description="Price feed corruption via AMM manipulation or stale data.",
        swc_id="",
        scsvs_category=SCVSCategory.DEFI_SPECIFIC,
        detection_hints=[
            "Spot price from AMM used without TWAP",
            "No staleness check on Chainlink feeds",
            "Single oracle source without fallback",
            "getReserves() used for price calculation",
        ],
        code_pattern=r"(getReserves|latestRoundData|slot0|observe\()",
        real_exploits=[e for e in MAJOR_EXPLOITS if e.vuln_class == VulnClass.ORACLE_MANIPULATION],
    ),
    VulnPattern(
        vuln_class=VulnClass.UNCHECKED_RETURN,
        title="Unchecked Call Return Values",
        description="Silent failures from ignored return values of external calls.",
        swc_id="SWC-104",
        scsvs_category=SCVSCategory.COMMUNICATIONS,
        detection_hints=[
            "Low-level .call() without checking bool return",
            "ERC20.transfer() return value ignored",
            "send() return value not checked",
        ],
        code_pattern=r"(\.call\(|\.send\(|\.transfer\()",
    ),
    VulnPattern(
        vuln_class=VulnClass.MEV_REORG,
        title="Transaction Reordering / MEV",
        description="Front-running, sandwich attacks, and block reorg exploitation.",
        swc_id="SWC-114",
        scsvs_category=SCVSCategory.KNOWN_ATTACKS,
        detection_hints=[
            "Slippage tolerance set too high or missing",
            "Deadline parameter missing on swap calls",
            "Commit-reveal scheme not implemented for sensitive operations",
            "Block.timestamp or block.number used for critical logic",
        ],
        code_pattern=r"(block\.timestamp|block\.number|deadline|slippage)",
    ),
    VulnPattern(
        vuln_class=VulnClass.BAD_RANDOMNESS,
        title="Bad Randomness",
        description="Predictable random number generation using block variables.",
        swc_id="SWC-120",
        scsvs_category=SCVSCategory.BLOCKCHAIN_DATA,
        detection_hints=[
            "block.timestamp, block.difficulty, blockhash used for randomness",
            "No Chainlink VRF or commit-reveal scheme",
            "Predictable seed in pseudo-random generation",
        ],
        code_pattern=r"(block\.timestamp|block\.difficulty|blockhash|prevrandao)",
    ),
    VulnPattern(
        vuln_class=VulnClass.KNOWN_VULNERABLE_COMPONENTS,
        title="Known Vulnerable Components",
        description="Using outdated compilers or libraries with known vulnerabilities.",
        swc_id="SWC-102",
        scsvs_category=SCVSCategory.CODE_CLARITY,
        detection_hints=[
            "Solidity compiler < 0.8.0",
            "Outdated OpenZeppelin version",
            "Known vulnerable library versions",
            "Unlocked compiler pragma (^0.8.x)",
        ],
        code_pattern=r"(pragma solidity \^|pragma solidity 0\.[0-7])",
    ),
    VulnPattern(
        vuln_class=VulnClass.BRIDGE_VULNERABILITY,
        title="Cross-Chain Bridge Vulnerabilities",
        description="Message validation, replay, and Merkle proof weaknesses in bridges.",
        swc_id="",
        scsvs_category=SCVSCategory.COMMUNICATIONS,
        detection_hints=[
            "Insufficient message validation on receiving chain",
            "Missing replay protection (nonces, chain IDs)",
            "Merkle proof verification flaws",
            "Relayer trust assumptions",
            "Finality assumptions across chains",
        ],
        real_exploits=[e for e in MAJOR_EXPLOITS if e.vuln_class == VulnClass.BRIDGE_VULNERABILITY],
    ),
]

# SCSVS checklist categories with descriptions
SCSVS_STANDARD = {
    SCVSCategory.ARCHITECTURE: "Design patterns, upgradability, dependency management",
    SCVSCategory.ACCESS_CONTROL: "Role-based access, multi-sig, timelocks",
    SCVSCategory.BLOCKCHAIN_DATA: "On-chain data handling, privacy, randomness",
    SCVSCategory.COMMUNICATIONS: "External calls, callbacks, cross-contract",
    SCVSCategory.ARITHMETIC: "Overflow, precision, rounding",
    SCVSCategory.MALICIOUS_INPUT: "Input validation, type checking, boundary conditions",
    SCVSCategory.GAS_USAGE: "Gas optimization, DoS via gas",
    SCVSCategory.BUSINESS_LOGIC: "Protocol invariants, state machine correctness",
    SCVSCategory.DENIAL_OF_SERVICE: "Resource exhaustion, unbounded loops, griefing",
    SCVSCategory.TOKEN: "ERC standard compliance, edge cases",
    SCVSCategory.CODE_CLARITY: "Readability, documentation, compiler settings",
    SCVSCategory.TEST_COVERAGE: "Unit, integration, fuzz, formal verification",
    SCVSCategory.KNOWN_ATTACKS: "Reentrancy, frontrunning, flash loans",
    SCVSCategory.DEFI_SPECIFIC: "Oracle, AMM, lending, yield protocol risks",
}

# Unique security tools from Immunefi library (not commonly listed elsewhere)
IMMUNEFI_TOOLS = {
    "transaction_analysis": [
        {"name": "Phalcon Explorer", "url": "https://explorer.phalcon.xyz/", "desc": "Transaction analysis and trace visualization"},
        {"name": "samczsun Tx Viewer", "url": "https://tx.eth.samczsun.com/", "desc": "Decode and trace Ethereum transactions"},
        {"name": "BlockSec Tools", "url": "https://tools.blocksec.com/", "desc": "Multi-chain transaction analysis"},
    ],
    "threat_intel": [
        {"name": "Codeslaw", "url": "https://www.codeslaw.app/", "desc": "On-chain contract source code search engine"},
        {"name": "Forta Protocol", "url": "https://forta.org/", "desc": "Real-time DeFi threat detection network"},
    ],
    "visualization": [
        {"name": "Solgraph", "url": "https://github.com/raineorshine/solgraph", "desc": "DOT graph of function control flow with vulnerability highlights"},
        {"name": "SOL2UML", "url": "https://github.com/naddison36/sol2uml", "desc": "UML class diagrams from Solidity source"},
        {"name": "Surya", "url": "https://github.com/ConsenSys/surya", "desc": "Contract structure and inheritance visualization"},
    ],
    "standards": [
        {"name": "SCSVS", "url": "https://github.com/ComposableSecurity/SCSVS", "desc": "14-category Smart Contract Security Verification Standard"},
    ],
}


class ImmunefiTaxonomy:
    """
    Immunefi-based vulnerability taxonomy for smart contract auditing.

    Provides:
    - 14-class vulnerability taxonomy with detection hints
    - SCSVS (14-path) security verification standard
    - Major exploit references with root causes
    - SWC Registry mapping
    - Unique tool references for transaction analysis and threat intel
    """

    def __init__(self):
        self.patterns = VULN_TAXONOMY
        self.exploits = MAJOR_EXPLOITS
        self.scsvs = SCSVS_STANDARD

    def get_patterns_by_class(self, vuln_class: VulnClass) -> list[VulnPattern]:
        """Get vulnerability patterns for a specific class."""
        return [p for p in self.patterns if p.vuln_class == vuln_class]

    def get_detection_hints(self, vuln_class: VulnClass) -> list[str]:
        """Get all detection hints for a vulnerability class."""
        hints = []
        for p in self.get_patterns_by_class(vuln_class):
            hints.extend(p.detection_hints)
        return hints

    def get_exploits_by_class(self, vuln_class: VulnClass) -> list[ExploitReference]:
        """Get real-world exploits for a vulnerability class."""
        return [e for e in self.exploits if e.vuln_class == vuln_class]

    def scan_code_patterns(self, source_code: str) -> list[VulnPattern]:
        """Quick scan for vulnerability indicators in source code."""
        import re
        matches = []
        for pattern in self.patterns:
            if pattern.code_pattern and re.search(pattern.code_pattern, source_code):
                matches.append(pattern)
        return matches

    def get_scsvs_checklist(self) -> list[dict]:
        """Get full SCSVS checklist for audit preparation."""
        return [
            {"category": cat.value, "name": cat.name, "description": desc}
            for cat, desc in self.scsvs.items()
        ]

    def generate_report(self, findings: list[VulnPattern]) -> str:
        """Generate taxonomy-based findings report."""
        lines = [
            "# Immunefi Taxonomy Scan Results",
            "",
            f"**Patterns Matched**: {len(findings)}",
            "",
        ]
        by_severity = {}
        for f in findings:
            key = f.vuln_class.value
            by_severity.setdefault(key, []).append(f)

        for cls, patterns in by_severity.items():
            lines.append(f"## {cls}")
            for p in patterns:
                lines.append(p.to_markdown())
                lines.append("")

        return "\n".join(lines)


def create_immunefi_taxonomy() -> ImmunefiTaxonomy:
    """Create a new Immunefi taxonomy instance."""
    return ImmunefiTaxonomy()
