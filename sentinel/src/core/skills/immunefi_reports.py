"""
Immunefi Published Reports Intelligence - Audit Competition & Attackathon Findings

Real-world vulnerability patterns extracted from 1,970+ published bug reports
across Immunefi audit competitions and attackathons. Used to prioritize
Sentinel analysis based on what actually gets found and paid.

Key insights:
- Reward distribution logic is the #1 most vulnerable component in DeFi
- Accounting/calculation errors dominate critical findings
- Reentrancy lock failures cause permanent fund locks
- Oracle integration issues are consistently critical
- Batch processing creates systematic attack surfaces

Source: https://reports.immunefi.com/
Stats: 1,970+ reports, $2.3M paid, 750+ rewarded, largest single payout $112,923
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ReportDomain(Enum):
    """Immunefi report classification domains."""
    SMART_CONTRACT = "SC"
    BLOCKCHAIN = "BC"
    WEB_APP = "W&A"


class FindingSeverity(Enum):
    """Immunefi severity levels (5-tier)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INSIGHT = "insight"


@dataclass
class AuditCompetition:
    """An Immunefi audit competition or attackathon."""
    name: str
    comp_type: str  # "audit_comp", "attackathon", "iop"
    reward_pool: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    insight: int
    url: str = ""
    top_vuln_pattern: str = ""

    @property
    def severity_distribution(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "insight": self.insight,
        }


@dataclass
class NotableFinding:
    """A notable high-severity finding from Immunefi reports."""
    report_id: str
    project: str
    severity: FindingSeverity
    domain: ReportDomain
    title: str
    root_cause: str
    impact: str
    vuln_pattern: str  # Maps to VULN_PATTERN_FREQUENCY keys


# Published audit competition data
COMPETITIONS: list[AuditCompetition] = [
    AuditCompetition(
        name="Plume Attackathon", comp_type="attackathon",
        reward_pool="N/A", total_findings=414,
        critical=11, high=156, medium=55, low=128, insight=64,
        url="https://reports.immunefi.com/plume-or-attackathon",
        top_vuln_pattern="access_control",
    ),
    AuditCompetition(
        name="Alchemix V3", comp_type="audit_comp",
        reward_pool="$100,000", total_findings=188,
        critical=80, high=30, medium=22, low=31, insight=25,
        url="https://reports.immunefi.com/alchemix",
        top_vuln_pattern="unlimited_minting",
    ),
    AuditCompetition(
        name="Movement Labs Attackathon", comp_type="attackathon",
        reward_pool="N/A", total_findings=139,
        critical=36, high=45, medium=14, low=2, insight=42,
        url="https://reports.immunefi.com/movement-labs-attackathon",
        top_vuln_pattern="chain_halt",
    ),
    AuditCompetition(
        name="Yeet", comp_type="audit_comp",
        reward_pool="N/A", total_findings=112,
        critical=33, high=21, medium=11, low=14, insight=38,
        url="https://reports.immunefi.com/yeet",
        top_vuln_pattern="accounting_error",
    ),
    AuditCompetition(
        name="Flare FAssets", comp_type="audit_comp",
        reward_pool="N/A", total_findings=110,
        critical=0, high=17, medium=20, low=32, insight=41,
        url="https://reports.immunefi.com/flare-fassets-or-mainnet-audit-comp",
        top_vuln_pattern="fund_theft",
    ),
    AuditCompetition(
        name="Swaylend IOP", comp_type="iop",
        reward_pool="$45,000", total_findings=25,
        critical=3, high=5, medium=4, low=7, insight=6,
        url="https://reports.immunefi.com/swaylend_iop",
        top_vuln_pattern="oracle_misuse",
    ),
    AuditCompetition(
        name="Fluid Protocol", comp_type="audit_comp",
        reward_pool="N/A", total_findings=20,
        critical=4, high=0, medium=1, low=7, insight=8,
        url="https://reports.immunefi.com/fluid-protocol",
        top_vuln_pattern="reentrancy_lock",
    ),
    AuditCompetition(
        name="Fuel Network Attackathon", comp_type="attackathon",
        reward_pool="$1,000,000", total_findings=0,
        critical=0, high=0, medium=0, low=0, insight=0,
        url="https://reports.immunefi.com/fuel-network-or-attackathon",
        top_vuln_pattern="compiler",
    ),
    AuditCompetition(
        name="Shardeum Ancillaries III", comp_type="audit_comp",
        reward_pool="N/A", total_findings=17,
        critical=7, high=0, medium=4, low=3, insight=3,
        url="https://reports.immunefi.com/shardeum-ancillaries-iii",
        top_vuln_pattern="data_injection",
    ),
    AuditCompetition(
        name="Folks Liquid Staking", comp_type="audit_comp",
        reward_pool="N/A", total_findings=15,
        critical=0, high=8, medium=0, low=1, insight=6,
        url="https://reports.immunefi.com/folks-liquid-staking",
        top_vuln_pattern="staking_logic",
    ),
]

# Notable findings from published reports
NOTABLE_FINDINGS: list[NotableFinding] = [
    NotableFinding(
        report_id="42153", project="Movement Labs",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.BLOCKCHAIN,
        title="Blob Verification Replay Attack",
        root_cause="Incomplete blob ID verification in DA layer",
        impact="Chain split via replayed blobs causing inconsistent state",
        vuln_pattern="replay_attack",
    ),
    NotableFinding(
        report_id="42837", project="Movement Labs",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.BLOCKCHAIN,
        title="Total Network Shutdown",
        root_cause="Deadlock in consensus/transaction processing",
        impact="Complete network halt",
        vuln_pattern="chain_halt",
    ),
    NotableFinding(
        report_id="N/A", project="Alchemix",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.SMART_CONTRACT,
        title="Unlimited FLUX Minting via voterpoke/Merge",
        root_cause="Multiple vectors for unauthorized infinite minting",
        impact="Token hyperinflation, protocol value collapse",
        vuln_pattern="unlimited_minting",
    ),
    NotableFinding(
        report_id="N/A", project="Yeet",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.SMART_CONTRACT,
        title="Protocol Insolvency via StakeV2 Accounting",
        root_cause="accumulatedDeptRewardsYeet counted unstaking/vesting tokens as distributable",
        impact="Protocol insolvency, permanent fund freezing",
        vuln_pattern="accounting_error",
    ),
    NotableFinding(
        report_id="49863", project="Plume",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.SMART_CONTRACT,
        title="DEX Aggregator Token Theft via Partial Fills",
        root_cause="Partial fill swaps did not refund unspent tokens",
        impact="Systematic token loss on every partial fill",
        vuln_pattern="token_routing",
    ),
    NotableFinding(
        report_id="37671", project="Fluid Protocol",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.SMART_CONTRACT,
        title="Permanent Lock of Redemption via Reentrancy Lock",
        root_cause="Reentrancy lock boolean not reset after operation",
        impact="Redemption permanently bricked",
        vuln_pattern="reentrancy_lock",
    ),
    NotableFinding(
        report_id="35684", project="Swaylend",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.SMART_CONTRACT,
        title="Pyth Oracle Price Misprocessing",
        root_cause="Constant value used to check price.confidence instead of actual interval",
        impact="Wrong collateral valuations, potential liquidation failures",
        vuln_pattern="oracle_misuse",
    ),
    NotableFinding(
        report_id="39626", project="Shardeum",
        severity=FindingSeverity.CRITICAL, domain=ReportDomain.BLOCKCHAIN,
        title="Archiver Cycle Data Overwrite",
        root_cause="Malicious validator bypasses signature verification",
        impact="Any cycle data in archiver can be overwritten",
        vuln_pattern="data_injection",
    ),
]

# Vulnerability pattern frequency from 1,970+ reports (ranked by prevalence)
VULN_PATTERN_FREQUENCY = {
    "accounting_error": {
        "rank": 1,
        "description": "Incorrect reward/yield/balance calculations",
        "severity_typical": "critical",
        "examples": [
            "Reward distribution counting unstaked tokens as distributable",
            "Precision loss in fee calculations",
            "Supply/balance desynchronization leading to insolvency",
            "Division-before-multiplication in share price computation",
        ],
        "detection_priority": "highest",
    },
    "access_control": {
        "rank": 2,
        "description": "Missing or bypassable authorization on privileged functions",
        "severity_typical": "high",
        "examples": [
            "Token creators retaining upgrade rights post-deployment",
            "Missing role management on factory contracts",
            "Debug middleware bypass in production",
            "Unprotected initialize() on proxy implementations",
        ],
        "detection_priority": "highest",
    },
    "token_routing": {
        "rank": 3,
        "description": "Funds sent to wrong address or stuck in contracts",
        "severity_typical": "high",
        "examples": [
            "Tokens sent to StakeV2 contract instead of user",
            "Leftover tokens stuck after partial fill swaps",
            "Refund logic missing on failed operations",
            "Fee tokens not forwarded to fee recipient",
        ],
        "detection_priority": "high",
    },
    "reentrancy_lock": {
        "rank": 4,
        "description": "Reentrancy guard failures causing permanent locks",
        "severity_typical": "critical",
        "examples": [
            "Lock boolean not reset after operation completes",
            "Lock not released on revert/exception path",
            "Cross-function reentrancy via shared lock state",
        ],
        "detection_priority": "high",
    },
    "oracle_misuse": {
        "rank": 5,
        "description": "Incorrect oracle integration causing wrong valuations",
        "severity_typical": "critical",
        "examples": [
            "Pyth confidence interval checked against constant instead of actual value",
            "Stale price data used without freshness check",
            "Spot price from AMM without TWAP protection",
            "Incorrect decimal handling on oracle response",
        ],
        "detection_priority": "high",
    },
    "sandwich_mev": {
        "rank": 6,
        "description": "Front-running and sandwich attacks on yield operations",
        "severity_typical": "medium",
        "examples": [
            "Sandwich attack on compound() yield distribution",
            "Front-running large deposits to extract yield",
            "Missing slippage protection on swaps",
            "Missing deadline parameter",
        ],
        "detection_priority": "medium",
    },
    "batch_processing": {
        "rank": 7,
        "description": "Systematic issues in batch/bulk operations",
        "severity_typical": "high",
        "examples": [
            "Batched yield distribution allows double-claiming",
            "Batch processing gas exceeds block limit",
            "Token add/remove during batch creates inconsistent state",
        ],
        "detection_priority": "medium",
    },
    "unlimited_minting": {
        "rank": 8,
        "description": "Unauthorized token minting via multiple vectors",
        "severity_typical": "critical",
        "examples": [
            "Multiple entry points for uncontrolled minting",
            "Merge/split functions bypass supply caps",
            "Governance token inflation via unchecked functions",
        ],
        "detection_priority": "high",
    },
    "replay_attack": {
        "rank": 9,
        "description": "Transaction or message replay across chains or blocks",
        "severity_typical": "critical",
        "examples": [
            "Blob verification missing unique identifiers",
            "Cross-chain message replay without nonce",
            "Signature reuse without expiration",
        ],
        "detection_priority": "high",
    },
    "pause_mechanism": {
        "rank": 10,
        "description": "Incomplete or missing emergency pause functionality",
        "severity_typical": "medium",
        "examples": [
            "Contract inherits Pausable but never exposes pause()",
            "Critical functions not covered by whenNotPaused",
            "No unpause mechanism (permanent freeze risk)",
        ],
        "detection_priority": "medium",
    },
    "chain_halt": {
        "rank": 11,
        "description": "L1/L2 network shutdown or consensus failure",
        "severity_typical": "critical",
        "examples": [
            "Deadlock in transaction processing",
            "OOM via decompression bomb",
            "TCP timeout cascade in validator network",
            "Sequencer crash via malformed input",
        ],
        "detection_priority": "high",
    },
    "data_injection": {
        "rank": 12,
        "description": "Unauthorized data modification via insufficient validation",
        "severity_typical": "critical",
        "examples": [
            "Archiver data overwrite by malicious validator",
            "Forged payment proofs accepted without verification",
            "Collateral value manipulation via injected data",
        ],
        "detection_priority": "high",
    },
}


class ImmunefiReportsIntel:
    """
    Intelligence from 1,970+ Immunefi published bug reports.

    Provides:
    - Vulnerability pattern rankings by real-world prevalence
    - Audit competition severity distributions
    - Notable critical findings with root causes
    - Priority-based scanning guidance

    Usage:
        intel = ImmunefiReportsIntel()

        # Get top patterns to check first
        priorities = intel.get_priority_patterns()

        # Check if code matches common vuln patterns
        patterns = intel.match_code_patterns(source_code)

        # Get competition stats for benchmarking
        stats = intel.get_aggregate_stats()
    """

    def __init__(self):
        self.competitions = COMPETITIONS
        self.findings = NOTABLE_FINDINGS
        self.patterns = VULN_PATTERN_FREQUENCY

    def get_priority_patterns(self, top_n: int = 5) -> list[dict]:
        """Get top N vulnerability patterns ranked by real-world prevalence."""
        sorted_patterns = sorted(
            self.patterns.items(),
            key=lambda x: x[1]["rank"],
        )
        return [
            {"name": name, **data}
            for name, data in sorted_patterns[:top_n]
        ]

    def get_patterns_by_severity(self, severity: str) -> list[dict]:
        """Get vulnerability patterns that typically result in a given severity."""
        return [
            {"name": name, **data}
            for name, data in self.patterns.items()
            if data["severity_typical"] == severity
        ]

    def get_notable_findings(
        self, severity: Optional[FindingSeverity] = None
    ) -> list[NotableFinding]:
        """Get notable findings, optionally filtered by severity."""
        if severity:
            return [f for f in self.findings if f.severity == severity]
        return self.findings

    def get_aggregate_stats(self) -> dict:
        """Get aggregate statistics across all competitions."""
        total = sum(c.total_findings for c in self.competitions)
        critical = sum(c.critical for c in self.competitions)
        high = sum(c.high for c in self.competitions)
        medium = sum(c.medium for c in self.competitions)
        low = sum(c.low for c in self.competitions)
        insight = sum(c.insight for c in self.competitions)

        return {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "insight": insight,
            "critical_rate": f"{(critical / total * 100):.1f}%" if total else "0%",
            "high_rate": f"{(high / total * 100):.1f}%" if total else "0%",
            "competitions_analyzed": len(self.competitions),
            "platform_total_reports": "1,970+",
            "platform_total_paid": "$2.3M",
            "largest_single_payout": "$112,923",
        }

    def match_code_patterns(self, source_code: str) -> list[dict]:
        """Match source code against common vulnerability patterns."""
        import re
        matches = []

        pattern_regexes = {
            "accounting_error": [
                r"(\/\s*\d+.*\*|accum|reward.*distribut|balance.*total)",
                r"(shares?\s*[=+\-]|convertToShares|convertToAssets)",
            ],
            "access_control": [
                r"(onlyOwner|hasRole|tx\.origin|initialize\()",
                r"(Ownable|AccessControl|_checkRole)",
            ],
            "token_routing": [
                r"(transfer\(|transferFrom\(|safeTransfer\()",
                r"(msg\.sender|address\(this\)|recipient)",
            ],
            "reentrancy_lock": [
                r"(nonReentrant|_locked|ReentrancyGuard)",
                r"(\.call\{value|\.call\()",
            ],
            "oracle_misuse": [
                r"(latestRoundData|getPrice|price\.confidence)",
                r"(slot0\(\)|getReserves\(\)|observe\()",
            ],
            "sandwich_mev": [
                r"(slippage|deadline|amountOutMin)",
                r"(block\.timestamp.*\+|swap.*exact)",
            ],
            "pause_mechanism": [
                r"(Pausable|whenNotPaused|_pause\(\)|paused\(\))",
            ],
            "unlimited_minting": [
                r"(_mint\(|mint\(|totalSupply)",
            ],
        }

        for pattern_name, regexes in pattern_regexes.items():
            for regex in regexes:
                if re.search(regex, source_code, re.IGNORECASE):
                    data = self.patterns[pattern_name]
                    matches.append({
                        "pattern": pattern_name,
                        "rank": data["rank"],
                        "severity_typical": data["severity_typical"],
                        "description": data["description"],
                        "detection_priority": data["detection_priority"],
                    })
                    break  # One match per pattern is enough

        return sorted(matches, key=lambda x: x["rank"])

    def generate_scan_plan(self) -> str:
        """Generate a prioritized scanning plan based on real-world data."""
        stats = self.get_aggregate_stats()
        priorities = self.get_priority_patterns(top_n=12)

        lines = [
            "# Immunefi-Informed Scan Plan",
            "",
            f"Based on {stats['platform_total_reports']} published reports, "
            f"{stats['platform_total_paid']} paid out.",
            "",
            "## Priority Order (by real-world prevalence)",
            "",
        ]
        for p in priorities:
            lines.append(
                f"### {p['rank']}. {p['name'].replace('_', ' ').title()} "
                f"[{p['severity_typical'].upper()}]"
            )
            lines.append(f"_{p['description']}_")
            lines.append("")
            lines.append("Check for:")
            for ex in p["examples"]:
                lines.append(f"- {ex}")
            lines.append("")

        return "\n".join(lines)

    def generate_report(self) -> str:
        """Generate intelligence summary report."""
        stats = self.get_aggregate_stats()
        lines = [
            "# Immunefi Reports Intelligence Summary",
            "",
            f"**Reports Analyzed**: {stats['total_findings']} from {stats['competitions_analyzed']} competitions",
            f"**Platform Total**: {stats['platform_total_reports']} reports, {stats['platform_total_paid']} paid",
            f"**Critical Rate**: {stats['critical_rate']}",
            f"**High Rate**: {stats['high_rate']}",
            "",
            "## Severity Distribution",
            f"- Critical: {stats['critical']}",
            f"- High: {stats['high']}",
            f"- Medium: {stats['medium']}",
            f"- Low: {stats['low']}",
            f"- Insight: {stats['insight']}",
            "",
            "## Top Vulnerability Patterns",
            "",
        ]
        for p in self.get_priority_patterns(top_n=5):
            lines.append(f"**{p['rank']}. {p['name']}** ({p['severity_typical']}) - {p['description']}")

        lines.extend(["", "## Notable Critical Findings", ""])
        for f in self.get_notable_findings(FindingSeverity.CRITICAL):
            lines.append(f"- **{f.project}**: {f.title} - {f.root_cause}")

        return "\n".join(lines)


def create_reports_intel() -> ImmunefiReportsIntel:
    """Create a new Immunefi reports intelligence instance."""
    return ImmunefiReportsIntel()
