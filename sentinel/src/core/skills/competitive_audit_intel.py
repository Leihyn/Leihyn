"""
Competitive Audit Intelligence - Code4rena, Sherlock, Immunefi, Secureum

Aggregated intelligence from competitive audit platforms to guide Sentinel's
vulnerability detection priority, severity calibration, and report generation.

Data sources:
- Code4rena: 464 audits, 31,512 submissions (2024), 950+ unique H-severity
- Sherlock: 459+ repos, 200-400 Watsons per contest, H/M only rewards
- Immunefi: $100M+ total payouts, $25B+ user funds saved
- Secureum: 201 audit findings, 201 security pitfalls, CARE methodology

Key insight: Accounting/calculation errors are the #1 critical finding across
ALL platforms. Oracle manipulation, access control, and reentrancy follow.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Platform(Enum):
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    IMMUNEFI = "immunefi"
    SECUREUM = "secureum"


class C4Severity(Enum):
    """Code4rena severity classification."""
    HIGH = "H"
    MEDIUM = "M"
    QA = "QA"       # Low + Non-critical
    GAS = "Gas"


class SherlockSeverity(Enum):
    """Sherlock severity classification (only H/M rewarded)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================
# Secureum 201 Audit Findings (condensed key patterns)
# ============================================================

SECUREUM_FINDINGS_101 = {
    "critical": [
        "Reentrancy via task injection / random execution",
        "Token approval theft via validation bypass",
        "Commitment value overwrites enabling fund theft",
        "Fallback function traps (reverting on failed transfers)",
        "Insufficient proxy implementation allowing takeover",
    ],
    "high": [
        "Transaction execution/cancellation race conditions",
        "Access control separation failures",
        "Front-running initialization and signature validation",
        "External call loops without return value checks",
        "Replay attacks (missing chainID validation)",
        "Flash loan exploitation of governance/oracle",
        "Timelock/admin takeover vectors",
        "ERC20 balance/supply invariant violations",
        "Missing two-step procedures for critical operations",
    ],
    "medium": [
        "Unhandled ERC20 return values (USDT pattern)",
        "Decimal handling (>18 decimals)",
        "Input validation gaps on boundaries",
        "Oracle update front-running",
        "State machine bypass via unexpected paths",
        "Event emission failures (off-chain monitoring blind)",
        "Checks-Effects-Interactions violations",
        "Storage layout mismatches in proxy upgrades",
        "Unsafe arithmetic patterns (divide before multiply)",
    ],
}

SECUREUM_PITFALLS_201 = {
    "token_integration": [
        "ERC20 tokens with no return values (USDT, BNB)",
        "Fee-on-transfer tokens breaking accounting",
        "Rebasing tokens (stETH) changing balances",
        "ERC777 callbacks enabling reentrancy",
        "Flash-mintable tokens manipulating supply",
        "Multiple-address tokens (TUSD) breaking allowances",
    ],
    "guarded_launch": [
        "Asset limits and caps for early deployment",
        "Circuit breakers for anomaly detection",
        "Emergency shutdown (pause) mechanisms",
        "Timelock on admin operations",
        "Rate limiting on sensitive operations",
    ],
    "design_principles": [
        "Least privilege (minimize access rights)",
        "Separation of duty (multi-sig for critical ops)",
        "Fail-safe defaults (deny by default)",
        "Complete mediation (check every access)",
        "Economy of mechanism (keep it simple)",
        "Open design (no security by obscurity)",
    ],
}


# ============================================================
# Cross-Platform Vulnerability Frequency Rankings
# ============================================================

@dataclass
class CrossPlatformPattern:
    """Vulnerability pattern with frequency data across platforms."""
    name: str
    description: str
    rank: int  # Overall cross-platform rank
    c4_frequency: str   # "very_high", "high", "medium", "low"
    sherlock_frequency: str
    immunefi_frequency: str
    typical_severity: str
    detection_hints: list[str]
    real_examples: list[str] = field(default_factory=list)


CROSS_PLATFORM_PATTERNS: list[CrossPlatformPattern] = [
    CrossPlatformPattern(
        name="Accounting / Calculation Errors",
        description="Incorrect reward/yield/balance/share calculations",
        rank=1,
        c4_frequency="very_high",
        sherlock_frequency="very_high",
        immunefi_frequency="very_high",
        typical_severity="critical",
        detection_hints=[
            "Division before multiplication (precision loss)",
            "Share-to-asset conversion edge cases (first depositor attack)",
            "Reward distribution counting unstaked tokens",
            "Fee calculations rounding in wrong direction",
            "Balance desynchronization across mappings",
            "Decimal assumption mismatches between tokens",
        ],
        real_examples=[
            "Yeet: 33 criticals from accumulatedDeptRewardsYeet miscalculation",
            "C4 Panoptic: Premium settlement adds instead of deducts",
            "Sherlock Sentiment-V2: Share math fracturing under manipulation",
        ],
    ),
    CrossPlatformPattern(
        name="Oracle Manipulation / Misuse",
        description="Price feed corruption, stale data, or incorrect integration",
        rank=2,
        c4_frequency="very_high",
        sherlock_frequency="very_high",
        immunefi_frequency="high",
        typical_severity="critical",
        detection_hints=[
            "Spot price from AMM without TWAP",
            "Missing staleness check on Chainlink latestRoundData",
            "Pyth confidence interval checked incorrectly",
            "No fallback oracle on primary failure",
            "getReserves() used for price calculation",
            "Block-scoped oracle updates exploitable via flash loans",
        ],
        real_examples=[
            "Swaylend: Pyth oracle constant vs actual confidence",
            "BonqDAO $120M: Direct oracle manipulation",
            "C4 2024: $403M stolen via oracle attacks in 2022",
        ],
    ),
    CrossPlatformPattern(
        name="Access Control / Authorization",
        description="Missing or bypassable auth on privileged functions",
        rank=3,
        c4_frequency="very_high",
        sherlock_frequency="high",
        immunefi_frequency="very_high",
        typical_severity="high",
        detection_hints=[
            "Missing onlyOwner/onlyRole on state-changing functions",
            "Unprotected initialize() on proxy implementations",
            "tx.origin used for authentication",
            "Signature replay (missing nonce/chainId/expiry)",
            "Upgrade authority not properly restricted",
            "Debug/admin endpoints accessible in production",
        ],
        real_examples=[
            "Plume Attackathon: 156 high findings, many access control",
            "Wormhole $10M bounty: Uninitialized proxy takeover",
            "88mph: Unprotected init() allowing $6.5M theft",
        ],
    ),
    CrossPlatformPattern(
        name="Reentrancy",
        description="State manipulation via recursive calls or callbacks",
        rank=4,
        c4_frequency="high",
        sherlock_frequency="high",
        immunefi_frequency="medium",
        typical_severity="high",
        detection_hints=[
            "External calls before state updates (CEI violation)",
            "Cross-function reentrancy via shared state variables",
            "Read-only reentrancy through view functions",
            "ERC777/ERC721 callback hooks",
            "Lock boolean not reset on revert paths",
            "Missing ReentrancyGuard on functions with external calls",
        ],
        real_examples=[
            "Fluid Protocol: All 4 criticals from lock not resetting",
            "Sherlock: Reentrancy grouped as duplicate category",
            "Secureum: Critical findings from task injection reentrancy",
        ],
    ),
    CrossPlatformPattern(
        name="Flash Loan Exploitation",
        description="Single-tx borrowing to manipulate protocol state",
        rank=5,
        c4_frequency="high",
        sherlock_frequency="high",
        immunefi_frequency="high",
        typical_severity="critical",
        detection_hints=[
            "Governance voting without timelock",
            "Price calculations using spot reserves",
            "Solvency checks manipulable in single tx",
            "Large capital requirements assumed as security",
            "balanceOf(address(this)) used for accounting",
            "Rebalancing functions callable after pool manipulation",
        ],
        real_examples=[
            "Beanstalk $181M: Flash loan governance takeover",
            "Fei Protocol: 60,000 ETH drainable via flash loan",
            "Sherlock: Flash loan + state manipulation combos",
        ],
    ),
    CrossPlatformPattern(
        name="Token Routing / Fund Misdirection",
        description="Funds sent to wrong address or stuck in contracts",
        rank=6,
        c4_frequency="high",
        sherlock_frequency="medium",
        immunefi_frequency="high",
        typical_severity="high",
        detection_hints=[
            "Transfer recipient is contract address instead of user",
            "Missing refund logic on failed/partial operations",
            "Fee tokens not forwarded to intended recipient",
            "Leftover tokens stuck after swap operations",
            "Withdrawal destination hardcoded or miscalculated",
        ],
        real_examples=[
            "Yeet: 10+ high findings of tokens to StakeV2 instead of user",
            "Plume: DEX aggregator partial fill token theft",
        ],
    ),
    CrossPlatformPattern(
        name="Front-running / MEV / Sandwich",
        description="Transaction ordering exploitation",
        rank=7,
        c4_frequency="high",
        sherlock_frequency="high",
        immunefi_frequency="medium",
        typical_severity="medium",
        detection_hints=[
            "Missing slippage protection (amountOutMin = 0)",
            "Missing deadline parameter on swaps",
            "Commit-reveal not used for sensitive operations",
            "Initialization functions front-runnable",
            "Yield compound functions sandwichable",
        ],
        real_examples=[
            "Yeet: 7/11 medium findings were sandwich on compound()",
            "C4: Frontrunning consistently in top vulnerability patterns",
            "Sherlock: Slippage/front-running as grouped duplicate category",
        ],
    ),
    CrossPlatformPattern(
        name="Token Standard Non-Compliance",
        description="Incorrect ERC20/721/4626 implementation or integration",
        rank=8,
        c4_frequency="high",
        sherlock_frequency="medium",
        immunefi_frequency="medium",
        typical_severity="medium",
        detection_hints=[
            "ERC20 missing return values (USDT pattern)",
            "Fee-on-transfer tokens not accounted for",
            "Rebasing tokens changing balances unexpectedly",
            "ERC4626 share/asset rounding edge cases",
            "ERC721 safeTransferFrom callback not handled",
            "approve() race condition (non-zero to non-zero)",
        ],
        real_examples=[
            "Secureum: Top medium-severity pattern across audits",
            "Multiple C4 contests: USDT approval pattern",
        ],
    ),
    CrossPlatformPattern(
        name="Proxy / Upgrade Vulnerabilities",
        description="Storage collisions, unprotected initializers, upgrade issues",
        rank=9,
        c4_frequency="medium",
        sherlock_frequency="medium",
        immunefi_frequency="high",
        typical_severity="critical",
        detection_hints=[
            "Implementation contract without _disableInitializers()",
            "Storage layout mismatch between proxy versions",
            "Function selector collision (proxy vs implementation)",
            "selfdestruct in implementation contract",
            "Importing non-upgradeable contracts in upgradeable context",
        ],
        real_examples=[
            "Wormhole $10M: Uninitialized proxy vulnerability",
            "Secureum: 7 proxy-specific pitfalls documented",
            "Nomad $190M: Zero hash trusted after upgrade",
        ],
    ),
    CrossPlatformPattern(
        name="Denial of Service",
        description="Resource exhaustion, unbounded loops, permanent locks",
        rank=10,
        c4_frequency="medium",
        sherlock_frequency="medium",
        immunefi_frequency="medium",
        typical_severity="medium",
        detection_hints=[
            "Unbounded loops over dynamic arrays",
            "Block gas limit exceeded in batch operations",
            "Griefing via dust deposits preventing withdrawal",
            "Emergency pause without unpause mechanism",
            "External dependency failure bricking protocol",
        ],
        real_examples=[
            "Sherlock: DoS qualifies as Medium if funds locked >1 week",
            "Plume: stakeOnBehalf gas manipulation",
        ],
    ),
]


# ============================================================
# Platform-Specific Judging Intelligence
# ============================================================

@dataclass
class SeverityBoundary:
    """Severity boundary rules for competitive audit platforms."""
    platform: Platform
    h_m_boundary: str
    m_l_boundary: str
    special_rules: list[str]


JUDGING_RULES: list[SeverityBoundary] = [
    SeverityBoundary(
        platform=Platform.CODE4RENA,
        h_m_boundary="Direct fund loss/compromise vs. conditional/hypothetical path",
        m_l_boundary="Protocol function impact vs. code style/clarity issues",
        special_rules=[
            "High: Assets stolen/lost/compromised directly with valid attack path",
            "Medium: Assets not at direct risk but protocol function/availability impacted",
            "QA: Code style, clarity, versioning, minor optimizations",
            "Burden of proof lies with warden (researcher)",
            "Proof increases with submission rarity and severity",
            "Best report per category gets 30% share bonus",
        ],
    ),
    SeverityBoundary(
        platform=Platform.SHERLOCK,
        h_m_boundary="Direct fund loss >1% AND >$10 vs. breaks core functionality",
        m_l_boundary="Fund loss >0.01% AND >$10 vs. no safety compromise",
        special_rules=[
            "Only H/M findings rewarded (no Low/Informational payouts)",
            "Hierarchy of Truth: README > Code comments > Default guidelines",
            "Protocol can define custom severity in README",
            "Breaking stated invariants = Medium even with low/unknown impact",
            "DoS = Medium if funds locked >1 week OR time-sensitive impact",
            "Admins trusted by default unless README restricts",
            "High: 5 points × 0.9^(n-1) / n per finding",
            "Medium: 1 point × 0.9^(n-1) / n per finding",
            "Duplicate penalty: exponential decay as more find same issue",
        ],
    ),
    SeverityBoundary(
        platform=Platform.IMMUNEFI,
        h_m_boundary="Direct fund theft/permanent freeze vs. yield theft/temporary impact",
        m_l_boundary="Protocol misbehavior vs. minor incorrect data",
        special_rules=[
            "5-tier: Critical, High, Medium, Low, Insight",
            "Critical: Direct theft, permanent freeze, protocol insolvency",
            "High: Yield theft, temporary freeze, significant MEV",
            "Medium: Protocol unable to operate, griefing, limited impact",
            "AI-generated/automated scanner reports PROHIBITED",
            "All PoCs must use local forks only (mainnet = permanent ban)",
            "No public disclosure before fix + payment",
        ],
    ),
    SeverityBoundary(
        platform=Platform.SECUREUM,
        h_m_boundary="Fund loss/system failure vs. potential loss under edge conditions",
        m_l_boundary="Edge-case funds impact vs. gas/readability improvements",
        special_rules=[
            "5-tier: High, Medium, Low, Optimization, Perfectionism",
            "OWASP-based: Likelihood × Impact matrix",
            "CARE = pre-audit readiness, not replacement for audit",
            "201 security pitfalls as baseline checklist",
            "201 audit findings as reference patterns",
            "10-step audit process (spec → docs → test → static → fuzz → symbolic → formal → manual → discussion → report)",
        ],
    ),
]


# ============================================================
# Immunefi Top Bug Bounty Payouts (for severity calibration)
# ============================================================

TOP_BOUNTY_PAYOUTS = [
    {"project": "Wormhole", "amount": "$10M", "vuln": "Uninitialized proxy", "whitehat": "satya0x"},
    {"project": "Aurora", "amount": "$6M", "vuln": "Infinite spend bug", "whitehat": "pwning.eth"},
    {"project": "Polygon", "amount": "$2.2M", "vuln": "Missing balance check in MRC20", "whitehat": "Leon Spacewalker"},
    {"project": "Optimism", "amount": "$2.1M", "vuln": "Infinite money duplication", "whitehat": "Jay Freeman (Saurik)"},
    {"project": "Polygon", "amount": "$2M", "vuln": "Double-spend in Plasma Bridge", "whitehat": "Gerhard Wagner"},
    {"project": "ArmorFi", "amount": "$1.5M", "vuln": "Catastrophic drainage via $1 coverage", "whitehat": "Alexander Schlindwein"},
    {"project": "Synthetix", "amount": "$150K", "vuln": "Logic error: wrong variable in rebate calc", "whitehat": "thunderdeep14"},
    {"project": "Immunefi (largest competition)", "amount": "$112,923", "vuln": "Single report payout", "whitehat": "N/A"},
]


# ============================================================
# Main Intelligence Class
# ============================================================

class CompetitiveAuditIntel:
    """
    Aggregated intelligence from Code4rena, Sherlock, Immunefi, and Secureum.

    Provides:
    - Cross-platform vulnerability pattern rankings
    - Platform-specific judging rules and severity calibration
    - Secureum 201 findings/pitfalls as detection baseline
    - Top bounty payouts for impact assessment
    - Prioritized scan plans based on real competitive audit data

    Usage:
        intel = CompetitiveAuditIntel()
        plan = intel.generate_scan_plan()
        rules = intel.get_judging_rules(Platform.SHERLOCK)
        patterns = intel.match_code_patterns(source_code)
    """

    def __init__(self):
        self.patterns = CROSS_PLATFORM_PATTERNS
        self.judging_rules = JUDGING_RULES
        self.secureum_findings = SECUREUM_FINDINGS_101
        self.secureum_pitfalls = SECUREUM_PITFALLS_201
        self.top_payouts = TOP_BOUNTY_PAYOUTS

    def get_top_patterns(self, n: int = 5) -> list[CrossPlatformPattern]:
        """Get top N vulnerability patterns by cross-platform prevalence."""
        return sorted(self.patterns, key=lambda p: p.rank)[:n]

    def get_patterns_by_severity(self, severity: str) -> list[CrossPlatformPattern]:
        """Get patterns that typically result in a given severity."""
        return [p for p in self.patterns if p.typical_severity == severity]

    def get_judging_rules(self, platform: Platform) -> Optional[SeverityBoundary]:
        """Get judging rules for a specific platform."""
        for rule in self.judging_rules:
            if rule.platform == platform:
                return rule
        return None

    def get_all_detection_hints(self) -> list[str]:
        """Get all detection hints across all patterns (flat list)."""
        hints = []
        for p in self.patterns:
            hints.extend(p.detection_hints)
        return hints

    def get_secureum_checklist(self, severity: Optional[str] = None) -> dict:
        """Get Secureum audit findings checklist."""
        if severity:
            return {severity: self.secureum_findings.get(severity, [])}
        return self.secureum_findings

    def match_code_patterns(self, source_code: str) -> list[dict]:
        """Match source code against cross-platform vulnerability patterns."""
        import re
        matches = []

        pattern_indicators = {
            "Accounting / Calculation Errors": [
                r"(\/\s*\d+.*\*|\*\s*\d+.*\/)",  # div before mul
                r"(convertToShares|convertToAssets|shares.*assets)",
                r"(reward.*distribut|accum.*reward|total.*reward)",
                r"(balance.*\-|\.sub\()",
            ],
            "Oracle Manipulation / Misuse": [
                r"(latestRoundData|getPrice|price\.conf)",
                r"(getReserves\(\)|slot0\(\))",
                r"(\.observe\(|twap|TWAP)",
            ],
            "Access Control / Authorization": [
                r"(tx\.origin)",
                r"(initialize\(\)|initializer)",
                r"(onlyOwner|onlyRole|hasRole|_checkRole)",
            ],
            "Reentrancy": [
                r"(\.call\{value|\.call\()",
                r"(nonReentrant|_locked|ReentrancyGuard)",
                r"(onERC721Received|tokensReceived)",
            ],
            "Flash Loan Exploitation": [
                r"(flashLoan|flashMint)",
                r"(balanceOf\(address\(this\)\))",
            ],
            "Front-running / MEV / Sandwich": [
                r"(amountOutMin|slippage|deadline)",
                r"(block\.timestamp\s*\+)",
            ],
            "Token Standard Non-Compliance": [
                r"(\.transfer\(|\.transferFrom\()",
                r"(safeTransfer|SafeERC20)",
                r"(\.approve\()",
            ],
            "Proxy / Upgrade Vulnerabilities": [
                r"(_disableInitializers|Initializable)",
                r"(delegatecall|UUPS|transparent)",
                r"(selfdestruct)",
            ],
        }

        for pattern_name, regexes in pattern_indicators.items():
            for regex in regexes:
                if re.search(regex, source_code, re.IGNORECASE):
                    # Find the matching CrossPlatformPattern
                    for p in self.patterns:
                        if p.name == pattern_name:
                            matches.append({
                                "pattern": p.name,
                                "rank": p.rank,
                                "severity": p.typical_severity,
                                "c4": p.c4_frequency,
                                "sherlock": p.sherlock_frequency,
                                "immunefi": p.immunefi_frequency,
                                "hints": p.detection_hints,
                            })
                            break
                    break

        return sorted(matches, key=lambda x: x["rank"])

    def calibrate_severity(
        self, finding_description: str, platform: Platform
    ) -> str:
        """Suggest severity classification based on platform-specific rules."""
        desc_lower = finding_description.lower()

        # Critical/High indicators
        critical_keywords = [
            "drain", "steal", "theft", "infinite mint", "insolvency",
            "permanent lock", "permanent freeze", "takeover", "proxy",
        ]
        high_keywords = [
            "fund loss", "oracle", "manipulation", "reentrancy",
            "access control", "unauthorized", "bypass", "flash loan",
        ]
        medium_keywords = [
            "dos", "denial of service", "griefing", "front-run",
            "sandwich", "slippage", "rounding", "precision",
        ]

        for kw in critical_keywords:
            if kw in desc_lower:
                return "critical" if platform == Platform.IMMUNEFI else "high"

        for kw in high_keywords:
            if kw in desc_lower:
                return "high"

        for kw in medium_keywords:
            if kw in desc_lower:
                return "medium"

        return "low"

    def generate_scan_plan(self, platform: Optional[Platform] = None) -> str:
        """Generate prioritized scan plan based on competitive audit data."""
        lines = [
            "# Competitive Audit Scan Plan",
            "",
            "Prioritized by cross-platform vulnerability prevalence",
            "(Code4rena + Sherlock + Immunefi + Secureum data)",
            "",
        ]

        if platform:
            rules = self.get_judging_rules(platform)
            if rules:
                lines.append(f"## {platform.value} Judging Context")
                lines.append(f"- H/M boundary: {rules.h_m_boundary}")
                for rule in rules.special_rules[:3]:
                    lines.append(f"- {rule}")
                lines.append("")

        lines.append("## Priority Scan Order")
        lines.append("")

        for p in sorted(self.patterns, key=lambda x: x.rank):
            lines.append(
                f"### {p.rank}. {p.name} [{p.typical_severity.upper()}]"
            )
            lines.append(f"_{p.description}_")
            lines.append(
                f"Frequency: C4={p.c4_frequency} | Sherlock={p.sherlock_frequency} "
                f"| Immunefi={p.immunefi_frequency}"
            )
            lines.append("")
            lines.append("Check for:")
            for h in p.detection_hints:
                lines.append(f"- {h}")
            if p.real_examples:
                lines.append("")
                lines.append("Real examples:")
                for ex in p.real_examples:
                    lines.append(f"- {ex}")
            lines.append("")

        return "\n".join(lines)

    def generate_report(self) -> str:
        """Generate intelligence summary."""
        lines = [
            "# Competitive Audit Intelligence Report",
            "",
            "## Platform Coverage",
            "- Code4rena: 464 audits, 31,512 submissions (2024), 950+ unique H",
            "- Sherlock: 459+ repos, 200-400 Watsons per contest",
            "- Immunefi: $100M+ payouts, $25B+ funds saved, 45K+ researchers",
            "- Secureum: 201 findings + 201 pitfalls baseline",
            "",
            "## Top 5 Cross-Platform Patterns",
            "",
        ]
        for p in self.get_top_patterns(5):
            lines.append(f"**{p.rank}. {p.name}** ({p.typical_severity})")
            lines.append(f"   {p.description}")
            lines.append("")

        lines.append("## Top Bounty Payouts (Severity Calibration)")
        for b in self.top_payouts[:5]:
            lines.append(f"- {b['project']}: {b['amount']} - {b['vuln']}")

        return "\n".join(lines)


def create_competitive_intel() -> CompetitiveAuditIntel:
    """Create a new competitive audit intelligence instance."""
    return CompetitiveAuditIntel()
