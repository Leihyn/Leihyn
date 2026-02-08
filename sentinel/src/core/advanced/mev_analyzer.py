"""
MEV (Maximal Extractable Value) Vulnerability Analyzer

Analyzes contracts for MEV extraction vectors:
1. Sandwich attacks - Front-run + back-run swaps
2. Frontrunning - Copy profitable tx with higher gas
3. JIT Liquidity - Just-in-time liquidity provision
4. Backrunning - Arbitrage after state change
5. Time-bandit attacks - Reorg profitability
6. Liquidation MEV - Racing to liquidate positions

Key patterns that enable MEV:
- Swaps without slippage protection
- Predictable state changes
- On-chain price discovery
- Unprotected liquidations
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class MEVVector(Enum):
    """Types of MEV extraction vectors."""
    SANDWICH = "sandwich"
    FRONTRUN = "frontrun"
    BACKRUN = "backrun"
    JIT_LIQUIDITY = "jit_liquidity"
    LIQUIDATION = "liquidation"
    TIME_BANDIT = "time_bandit"
    ORACLE_UPDATE = "oracle_update"
    GOVERNANCE = "governance"


class MEVSeverity(Enum):
    """Severity based on extractable value."""
    CRITICAL = "critical"    # Unlimited extraction
    HIGH = "high"            # Bounded but significant
    MEDIUM = "medium"        # Limited extraction
    LOW = "low"              # Minimal impact


@dataclass
class MEVFinding:
    """An MEV vulnerability finding."""
    vector: MEVVector
    severity: MEVSeverity
    title: str
    description: str
    affected_code: str
    line_number: int
    extraction_potential: str  # "Unlimited", "Up to X%", etc.
    attack_scenario: str
    mitigation: str
    protected_alternative: str  # Code showing protected version


@dataclass
class MEVConfig:
    """Configuration for MEV analysis."""
    check_sandwich: bool = True
    check_frontrun: bool = True
    check_backrun: bool = True
    check_jit: bool = True
    check_liquidation: bool = True
    min_swap_value_usd: float = 1000  # Minimum swap size to flag


# =============================================================================
# MEV VULNERABILITY PATTERNS
# =============================================================================

MEV_PATTERNS = {
    MEVVector.SANDWICH: {
        "patterns": [
            # Swap with amountOutMin = 0
            r"\.swap\w*\([^)]*,\s*0\s*[,)]",
            r"swapExact\w+\([^)]*,\s*0\s*,",
            r"amountOutMin(?:imum)?\s*[:=]\s*0",
            # Swap without slippage check
            r"function\s+swap\w*\([^)]*\)(?!.*require.*amountOut)(?!.*minAmount)",
            # addLiquidity without min amounts
            r"addLiquidity\([^)]*,\s*0\s*,\s*0\s*[,)]",
        ],
        "description": "Swap vulnerable to sandwich attack",
        "extraction": "Unlimited - attacker extracts all slippage tolerance",
        "mitigation": "Set appropriate amountOutMin based on oracle price",
    },
    MEVVector.FRONTRUN: {
        "patterns": [
            # Approval before action (can frontrun the action)
            r"approve\s*\([^)]*type\(uint256\)\.max",
            # Predictable profitable action
            r"function\s+claim\w*\([^)]*\)\s*external(?!.*deadline)",
            # NFT mint without commit-reveal
            r"function\s+mint\([^)]*\)\s*(?:external|public)(?!.*commit)(?!.*reveal)",
            # First-come-first-serve rewards
            r"function\s+(?:claim|redeem|harvest)\s*\([^)]*\)\s*external(?!.*msg\.sender)",
        ],
        "description": "Transaction can be frontrun for profit",
        "extraction": "Varies - depends on action value",
        "mitigation": "Use commit-reveal, deadlines, or private mempools",
    },
    MEVVector.BACKRUN: {
        "patterns": [
            # Large state change creates arbitrage
            r"function\s+rebalance\s*\(",
            r"function\s+updatePrice\s*\(",
            # Pool state change without atomic arb protection
            r"function\s+sync\s*\(\s*\)",
            # Oracle update creates arb opportunity
            r"function\s+(?:set|update)(?:Price|Rate|Value)\s*\(",
        ],
        "description": "State change creates backrunning opportunity",
        "extraction": "Price difference between old and new state",
        "mitigation": "Batch updates, use TWAP, or atomic arbitrage",
    },
    MEVVector.JIT_LIQUIDITY: {
        "patterns": [
            # Single-block LP possible
            r"function\s+addLiquidity\([^)]*\)(?!.*lockTime)(?!.*minDuration)",
            r"function\s+mint\([^)]*\)\s*external(?!.*lockPeriod)",
            # No LP lock period
            r"function\s+removeLiquidity\([^)]*\)(?!.*require.*block\.number)",
        ],
        "description": "Vulnerable to JIT liquidity attacks",
        "extraction": "Swap fees from large trades",
        "mitigation": "Minimum LP lock period or concentrated liquidity ranges",
    },
    MEVVector.LIQUIDATION: {
        "patterns": [
            # Public liquidation function
            r"function\s+liquidate\w*\([^)]*\)\s*external(?!.*onlyKeeper)(?!.*onlyLiquidator)",
            # Liquidation bonus visible on-chain
            r"liquidationBonus\s*=",
            # No liquidation delay
            r"function\s+liquidate(?!.*require.*lastHealthCheck)",
        ],
        "description": "Liquidation MEV extraction possible",
        "extraction": "Liquidation bonus + potential bad debt extraction",
        "mitigation": "Use keeper network, Dutch auction, or gradual liquidation",
    },
    MEVVector.ORACLE_UPDATE: {
        "patterns": [
            # Oracle update triggers state change
            r"function\s+updateOracle\([^)]*\)\s*external(?!.*onlyOracle)",
            # Price used immediately after fetch
            r"getPrice\(\)[^;]*;[^}]*(?:mint|burn|swap|liquidate)",
            # No oracle freshness check
            r"latestAnswer\(\)(?!.*require.*updatedAt)",
        ],
        "description": "Oracle update creates MEV opportunity",
        "extraction": "Price movement between updates",
        "mitigation": "TWAP oracle, freshness checks, or price bands",
    },
    MEVVector.GOVERNANCE: {
        "patterns": [
            # Immediate proposal execution
            r"function\s+execute\([^)]*\)(?!.*require.*timelock)",
            # Flash loan voting
            r"function\s+(?:vote|castVote)\([^)]*\)(?!.*require.*locked)",
            # No voting delay
            r"votingDelay\s*=\s*0",
        ],
        "description": "Governance MEV extraction possible",
        "extraction": "Protocol control or treasury extraction",
        "mitigation": "Timelock, vote escrow, or snapshot voting",
    },
}


# =============================================================================
# PROTECTED PATTERNS (What secure code looks like)
# =============================================================================

PROTECTED_PATTERNS = {
    MEVVector.SANDWICH: '''
// PROTECTED: Swap with slippage protection
function swapWithProtection(
    uint256 amountIn,
    uint256 amountOutMin,  // Calculated off-chain with oracle + tolerance
    uint256 deadline       // Prevents stale tx execution
) external {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = _swap(amountIn);
    require(amountOut >= amountOutMin, "Slippage exceeded");
}
''',
    MEVVector.FRONTRUN: '''
// PROTECTED: Commit-reveal for fair mint
mapping(address => bytes32) public commits;
mapping(address => uint256) public commitBlock;

function commit(bytes32 hash) external {
    commits[msg.sender] = hash;
    commitBlock[msg.sender] = block.number;
}

function reveal(uint256 nonce) external {
    require(block.number > commitBlock[msg.sender] + 1, "Wait");
    require(keccak256(abi.encode(msg.sender, nonce)) == commits[msg.sender], "Invalid");
    _mint(msg.sender);
}
''',
    MEVVector.LIQUIDATION: '''
// PROTECTED: Dutch auction liquidation
function liquidate(address user) external {
    uint256 discount = _calculateDutchAuctionDiscount(
        liquidationStartTime[user],
        block.timestamp
    );
    // Discount increases over time, removing urgency to frontrun
    uint256 collateralToSeize = debt * (100 + discount) / 100;
    // ...
}
''',
}


class MEVAnalyzer:
    """
    Comprehensive MEV vulnerability analyzer.

    Identifies patterns that enable MEV extraction and suggests mitigations.
    """

    def __init__(self, config: Optional[MEVConfig] = None):
        self.config = config or MEVConfig()
        self.findings: list[MEVFinding] = []

    def analyze(self, source_code: str, contract_name: str = "Contract") -> list[MEVFinding]:
        """
        Analyze contract for MEV vulnerabilities.
        """
        self.findings = []

        # Check each MEV vector
        for vector, info in MEV_PATTERNS.items():
            if self._should_check(vector):
                self._check_vector(source_code, vector, info)

        # Additional heuristic checks
        self._check_swap_patterns(source_code)
        self._check_oracle_usage(source_code)
        self._check_timing_dependencies(source_code)

        return self.findings

    def _should_check(self, vector: MEVVector) -> bool:
        """Check if vector should be analyzed based on config."""
        checks = {
            MEVVector.SANDWICH: self.config.check_sandwich,
            MEVVector.FRONTRUN: self.config.check_frontrun,
            MEVVector.BACKRUN: self.config.check_backrun,
            MEVVector.JIT_LIQUIDITY: self.config.check_jit,
            MEVVector.LIQUIDATION: self.config.check_liquidation,
        }
        return checks.get(vector, True)

    def _check_vector(self, source: str, vector: MEVVector, info: dict) -> None:
        """Check for specific MEV vector."""
        for pattern in info["patterns"]:
            matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
            for match in matches:
                line_num = source[:match.start()].count('\n') + 1
                self.findings.append(MEVFinding(
                    vector=vector,
                    severity=self._determine_severity(vector, match.group(0)),
                    title=f"MEV Vector: {vector.value.replace('_', ' ').title()}",
                    description=info["description"],
                    affected_code=match.group(0)[:200],
                    line_number=line_num,
                    extraction_potential=info["extraction"],
                    attack_scenario=self._generate_attack_scenario(vector),
                    mitigation=info["mitigation"],
                    protected_alternative=PROTECTED_PATTERNS.get(vector, "See documentation"),
                ))

    def _check_swap_patterns(self, source: str) -> None:
        """Deep analysis of swap patterns."""
        # Find all swap-like functions
        swap_funcs = re.finditer(
            r"function\s+(\w*swap\w*)\s*\(([^)]*)\)[^{]*\{([^}]+)\}",
            source,
            re.IGNORECASE | re.DOTALL
        )

        for match in swap_funcs:
            func_name = match.group(1)
            params = match.group(2)
            body = match.group(3)

            # Check for missing slippage protection
            has_min_out = any(x in params.lower() for x in ["minout", "minamount", "amountoutmin"])
            has_deadline = "deadline" in params.lower()
            checks_slippage = "require" in body and any(
                x in body.lower() for x in ["amountout", "minout", "received"]
            )

            if not has_min_out and not checks_slippage:
                self.findings.append(MEVFinding(
                    vector=MEVVector.SANDWICH,
                    severity=MEVSeverity.CRITICAL,
                    title=f"Swap Without Slippage Protection: {func_name}",
                    description="Swap function has no minimum output amount parameter or check",
                    affected_code=f"function {func_name}({params[:100]}...)",
                    line_number=source[:match.start()].count('\n') + 1,
                    extraction_potential="Unlimited - 100% of swap value extractable",
                    attack_scenario=(
                        "1. Attacker sees swap in mempool\n"
                        "2. Front-runs with large swap in same direction\n"
                        "3. Victim's swap executes at worse price\n"
                        "4. Attacker back-runs, profiting from price impact"
                    ),
                    mitigation="Add amountOutMin parameter and require check",
                    protected_alternative=PROTECTED_PATTERNS[MEVVector.SANDWICH],
                ))

            if not has_deadline:
                self.findings.append(MEVFinding(
                    vector=MEVVector.FRONTRUN,
                    severity=MEVSeverity.MEDIUM,
                    title=f"Swap Without Deadline: {func_name}",
                    description="Swap can be held by validators and executed at unfavorable time",
                    affected_code=f"function {func_name}({params[:100]}...)",
                    line_number=source[:match.start()].count('\n') + 1,
                    extraction_potential="Time-based price movement",
                    attack_scenario="Validator holds tx until price moves unfavorably",
                    mitigation="Add deadline parameter with require(block.timestamp <= deadline)",
                    protected_alternative="require(block.timestamp <= deadline, 'Expired');",
                ))

    def _check_oracle_usage(self, source: str) -> None:
        """Check oracle usage patterns for MEV."""
        # Chainlink oracle without freshness check
        if re.search(r"latestRoundData\(\)", source):
            if not re.search(r"require\s*\([^)]*updatedAt", source):
                self.findings.append(MEVFinding(
                    vector=MEVVector.ORACLE_UPDATE,
                    severity=MEVSeverity.HIGH,
                    title="Oracle Without Freshness Check",
                    description="Using oracle price without checking staleness",
                    affected_code="latestRoundData() without updatedAt check",
                    line_number=0,
                    extraction_potential="Stale price arbitrage",
                    attack_scenario="Use stale price to arbitrage real market price",
                    mitigation="Check updatedAt is recent: require(block.timestamp - updatedAt < MAX_DELAY)",
                    protected_alternative=(
                        "(,int256 price,,uint256 updatedAt,) = priceFeed.latestRoundData();\n"
                        "require(block.timestamp - updatedAt < 3600, 'Stale price');"
                    ),
                ))

        # TWAP too short
        twap_match = re.search(r"(?:twap|observe)\s*\([^)]*(\d+)[^)]*\)", source)
        if twap_match:
            period = int(twap_match.group(1))
            if period < 1800:  # Less than 30 minutes
                self.findings.append(MEVFinding(
                    vector=MEVVector.ORACLE_UPDATE,
                    severity=MEVSeverity.MEDIUM,
                    title=f"Short TWAP Period ({period}s)",
                    description="TWAP period too short for manipulation resistance",
                    affected_code=twap_match.group(0),
                    line_number=source[:twap_match.start()].count('\n') + 1,
                    extraction_potential="Price manipulation over short period",
                    attack_scenario="Manipulate price, wait TWAP period, exploit",
                    mitigation="Use TWAP period of at least 30 minutes",
                    protected_alternative="uint32 twapPeriod = 1800; // 30 minutes",
                ))

    def _check_timing_dependencies(self, source: str) -> None:
        """Check for timing-based MEV opportunities."""
        # Block.timestamp usage in critical logic
        if re.search(r"block\.timestamp\s*[<>=]", source):
            # Check if used for rewards/unlocks
            if re.search(r"block\.timestamp[^;]*(?:reward|unlock|vest|claim)", source, re.IGNORECASE):
                self.findings.append(MEVFinding(
                    vector=MEVVector.TIME_BANDIT,
                    severity=MEVSeverity.LOW,
                    title="Time-Dependent Rewards",
                    description="Rewards based on block.timestamp can be manipulated by validators",
                    affected_code="block.timestamp used for reward calculation",
                    line_number=0,
                    extraction_potential="Minor timestamp manipulation (±15s)",
                    attack_scenario="Validator manipulates timestamp to maximize own rewards",
                    mitigation="Use block.number or accept ±15s variance",
                    protected_alternative="// Accept that block.timestamp has ±15s variance",
                ))

    def _determine_severity(self, vector: MEVVector, code: str) -> MEVSeverity:
        """Determine severity based on vector and context."""
        # Critical: unlimited extraction
        if vector == MEVVector.SANDWICH and "0" in code:
            return MEVSeverity.CRITICAL

        # High: significant extraction
        if vector in (MEVVector.LIQUIDATION, MEVVector.GOVERNANCE):
            return MEVSeverity.HIGH

        # Medium: bounded extraction
        if vector in (MEVVector.JIT_LIQUIDITY, MEVVector.ORACLE_UPDATE):
            return MEVSeverity.MEDIUM

        return MEVSeverity.MEDIUM

    def _generate_attack_scenario(self, vector: MEVVector) -> str:
        """Generate attack scenario for vector."""
        scenarios = {
            MEVVector.SANDWICH: (
                "1. Monitor mempool for large swap\n"
                "2. Calculate optimal front-run amount\n"
                "3. Submit front-run tx with higher gas\n"
                "4. Let victim tx execute (worse price)\n"
                "5. Back-run to capture profit"
            ),
            MEVVector.FRONTRUN: (
                "1. Monitor mempool for profitable tx\n"
                "2. Copy tx with higher gas price\n"
                "3. Attacker tx executes first\n"
                "4. Original tx fails or gets worse execution"
            ),
            MEVVector.JIT_LIQUIDITY: (
                "1. See large swap incoming\n"
                "2. Add concentrated liquidity at expected price\n"
                "3. Earn swap fees from large trade\n"
                "4. Remove liquidity in same block"
            ),
            MEVVector.LIQUIDATION: (
                "1. Monitor for underwater positions\n"
                "2. Race to submit liquidation tx\n"
                "3. Extract liquidation bonus\n"
                "4. Potentially create bad debt for extra profit"
            ),
        }
        return scenarios.get(vector, "Attack scenario depends on specific implementation")

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = {s.value: 0 for s in MEVSeverity}
        vector_counts = {v.value: 0 for v in MEVVector}

        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            vector_counts[finding.vector.value] += 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_vector": vector_counts,
            "estimated_risk": self._estimate_total_risk(),
        }

    def _estimate_total_risk(self) -> str:
        """Estimate total MEV risk level."""
        critical = sum(1 for f in self.findings if f.severity == MEVSeverity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == MEVSeverity.HIGH)

        if critical > 0:
            return "CRITICAL - Unlimited MEV extraction possible"
        elif high > 2:
            return "HIGH - Significant MEV extraction vectors"
        elif high > 0:
            return "MEDIUM - Some MEV exposure"
        else:
            return "LOW - Minimal MEV risk"


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_mev(source_code: str) -> list[MEVFinding]:
    """Quick MEV analysis."""
    analyzer = MEVAnalyzer()
    return analyzer.analyze(source_code)


def check_sandwich_vulnerability(source_code: str) -> bool:
    """Check if contract has sandwich attack vulnerability."""
    analyzer = MEVAnalyzer(MEVConfig(
        check_sandwich=True,
        check_frontrun=False,
        check_backrun=False,
        check_jit=False,
        check_liquidation=False,
    ))
    findings = analyzer.analyze(source_code)
    return any(f.vector == MEVVector.SANDWICH for f in findings)
