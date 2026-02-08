"""
Economic Invariant Analyzer for DeFi Protocols

Pattern matching finds code bugs.
Economic analysis finds VALUE EXTRACTION bugs.

This module models:
1. Token flows and conservation laws
2. Price manipulation vectors
3. Flash loan attack profitability
4. MEV extraction opportunities
5. Protocol composability risks

The attacker's goal: profit > cost
We model all paths to achieve this.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class TokenType(Enum):
    ETH = "ETH"
    ERC20 = "ERC20"
    ERC721 = "ERC721"
    ERC1155 = "ERC1155"
    LP_TOKEN = "LP_TOKEN"
    DEBT_TOKEN = "DEBT_TOKEN"
    COLLATERAL = "COLLATERAL"


class FlowType(Enum):
    DEPOSIT = "deposit"
    WITHDRAW = "withdraw"
    SWAP = "swap"
    BORROW = "borrow"
    REPAY = "repay"
    LIQUIDATE = "liquidate"
    MINT = "mint"
    BURN = "burn"
    TRANSFER = "transfer"
    FLASH_LOAN = "flash_loan"


@dataclass
class TokenFlow:
    """A single token movement."""
    token: str
    token_type: TokenType
    flow_type: FlowType
    from_entity: str  # address or "protocol"
    to_entity: str
    amount_expr: str  # Expression for amount (may be symbolic)
    conditions: list[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class EconomicInvariant:
    """An economic property that must hold."""
    name: str
    category: str  # conservation, bounds, ratio, ordering
    expression: str  # Mathematical expression
    violated_by: str  # What type of attack violates this
    severity: str


@dataclass
class AttackPath:
    """A profitable attack sequence."""
    name: str
    steps: list[dict]
    profit_expression: str
    required_capital: str
    complexity: str  # LOW, MEDIUM, HIGH
    flash_loan_compatible: bool
    mev_extractable: bool


class EconomicInvariants:
    """
    Standard DeFi economic invariants.

    These MUST hold for protocol security:
    1. Conservation: tokens in = tokens out (plus fees)
    2. Solvency: assets >= liabilities
    3. Price bounds: prices within reasonable ranges
    4. Access: only authorized flows
    """

    INVARIANTS = {
        # =====================================================================
        # CONSERVATION INVARIANTS
        # =====================================================================
        "token_conservation": EconomicInvariant(
            name="Token Conservation",
            category="conservation",
            expression="sum(token_in) == sum(token_out) + fees",
            violated_by="Inflation bug, mint without backing",
            severity="CRITICAL",
        ),

        "lp_backing": EconomicInvariant(
            name="LP Token Backing",
            category="conservation",
            expression="lp_supply * lp_value == reserve0 * price0 + reserve1 * price1",
            violated_by="First depositor attack, share inflation",
            severity="CRITICAL",
        ),

        "debt_collateral_ratio": EconomicInvariant(
            name="Debt Collateral Ratio",
            category="ratio",
            expression="collateral_value >= debt_value * min_ratio",
            violated_by="Oracle manipulation, bad debt",
            severity="CRITICAL",
        ),

        # =====================================================================
        # SOLVENCY INVARIANTS
        # =====================================================================
        "protocol_solvency": EconomicInvariant(
            name="Protocol Solvency",
            category="solvency",
            expression="total_assets >= total_liabilities",
            violated_by="Bank run, cascading liquidations",
            severity="CRITICAL",
        ),

        "reserve_ratio": EconomicInvariant(
            name="Reserve Ratio",
            category="solvency",
            expression="available_liquidity >= min_reserve_ratio * total_deposits",
            violated_by="Utilization attack, liquidity drain",
            severity="HIGH",
        ),

        # =====================================================================
        # PRICE INVARIANTS
        # =====================================================================
        "price_bounds": EconomicInvariant(
            name="Price Bounds",
            category="bounds",
            expression="min_price <= current_price <= max_price",
            violated_by="Oracle manipulation, stale price",
            severity="HIGH",
        ),

        "price_freshness": EconomicInvariant(
            name="Price Freshness",
            category="bounds",
            expression="block.timestamp - price_timestamp < max_staleness",
            violated_by="Stale oracle, sequencer downtime",
            severity="HIGH",
        ),

        "slippage_bounds": EconomicInvariant(
            name="Slippage Bounds",
            category="bounds",
            expression="abs(execution_price - quoted_price) <= max_slippage",
            violated_by="Sandwich attack, front-running",
            severity="MEDIUM",
        ),

        # =====================================================================
        # ORDERING INVARIANTS
        # =====================================================================
        "withdrawal_ordering": EconomicInvariant(
            name="Withdrawal Ordering",
            category="ordering",
            expression="withdrawal_amount <= deposited_amount",
            violated_by="Reentrancy, share calculation bug",
            severity="CRITICAL",
        ),

        "fee_extraction_limit": EconomicInvariant(
            name="Fee Extraction Limit",
            category="bounds",
            expression="fees_extracted <= max_fee_rate * volume",
            violated_by="Fee manipulation, governance attack",
            severity="MEDIUM",
        ),
    }

    @classmethod
    def get_invariants_for_protocol(cls, protocol_type: str) -> list[EconomicInvariant]:
        """Get relevant invariants for a protocol type."""
        if protocol_type == "amm":
            return [
                cls.INVARIANTS["token_conservation"],
                cls.INVARIANTS["lp_backing"],
                cls.INVARIANTS["slippage_bounds"],
            ]
        elif protocol_type == "lending":
            return [
                cls.INVARIANTS["debt_collateral_ratio"],
                cls.INVARIANTS["protocol_solvency"],
                cls.INVARIANTS["price_bounds"],
                cls.INVARIANTS["price_freshness"],
            ]
        elif protocol_type == "vault":
            return [
                cls.INVARIANTS["token_conservation"],
                cls.INVARIANTS["withdrawal_ordering"],
                cls.INVARIANTS["reserve_ratio"],
            ]
        return list(cls.INVARIANTS.values())


class TokenFlowAnalyzer:
    """
    Analyze token flows in smart contracts.

    Traces:
    - Where tokens come from
    - Where tokens go
    - What conditions control flow
    - What the net effect is
    """

    def __init__(self, language: str = "solidity"):
        self.language = language
        self.flows: list[TokenFlow] = []

    def extract_flows(self, code: str) -> list[TokenFlow]:
        """Extract all token flows from code."""
        self.flows = []

        if self.language == "solidity":
            self._extract_solidity_flows(code)

        return self.flows

    def _extract_solidity_flows(self, code: str) -> None:
        """Extract token flows from Solidity code."""
        lines = code.split('\n')

        # ERC20 transfers
        transfer_pattern = r'(\w+)\.transfer\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)'
        for i, line in enumerate(lines):
            for match in re.finditer(transfer_pattern, line):
                self.flows.append(TokenFlow(
                    token=match.group(1),
                    token_type=TokenType.ERC20,
                    flow_type=FlowType.TRANSFER,
                    from_entity="contract",
                    to_entity=match.group(2),
                    amount_expr=match.group(3),
                    line_number=i + 1,
                ))

        # transferFrom
        transfer_from_pattern = r'(\w+)\.transferFrom\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)'
        for i, line in enumerate(lines):
            for match in re.finditer(transfer_from_pattern, line):
                self.flows.append(TokenFlow(
                    token=match.group(1),
                    token_type=TokenType.ERC20,
                    flow_type=FlowType.TRANSFER,
                    from_entity=match.group(2),
                    to_entity=match.group(3),
                    amount_expr=match.group(4),
                    line_number=i + 1,
                ))

        # ETH transfers via call
        eth_call_pattern = r'(\w+)\.call\{value:\s*(\w+)\}'
        for i, line in enumerate(lines):
            for match in re.finditer(eth_call_pattern, line):
                self.flows.append(TokenFlow(
                    token="ETH",
                    token_type=TokenType.ETH,
                    flow_type=FlowType.TRANSFER,
                    from_entity="contract",
                    to_entity=match.group(1),
                    amount_expr=match.group(2),
                    line_number=i + 1,
                ))

        # Minting
        mint_pattern = r'_mint\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)'
        for i, line in enumerate(lines):
            for match in re.finditer(mint_pattern, line):
                self.flows.append(TokenFlow(
                    token="shares",
                    token_type=TokenType.LP_TOKEN,
                    flow_type=FlowType.MINT,
                    from_entity="protocol",
                    to_entity=match.group(1),
                    amount_expr=match.group(2),
                    line_number=i + 1,
                ))

        # Burning
        burn_pattern = r'_burn\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)'
        for i, line in enumerate(lines):
            for match in re.finditer(burn_pattern, line):
                self.flows.append(TokenFlow(
                    token="shares",
                    token_type=TokenType.LP_TOKEN,
                    flow_type=FlowType.BURN,
                    from_entity=match.group(1),
                    to_entity="protocol",
                    amount_expr=match.group(2),
                    line_number=i + 1,
                ))

    def check_conservation(self) -> list[dict]:
        """Check if token flows are conserved."""
        issues = []

        # Group flows by token
        by_token: dict[str, list[TokenFlow]] = {}
        for flow in self.flows:
            if flow.token not in by_token:
                by_token[flow.token] = []
            by_token[flow.token].append(flow)

        for token, flows in by_token.items():
            mints = [f for f in flows if f.flow_type == FlowType.MINT]
            burns = [f for f in flows if f.flow_type == FlowType.BURN]
            transfers_in = [f for f in flows if f.flow_type == FlowType.TRANSFER and f.to_entity == "contract"]
            transfers_out = [f for f in flows if f.flow_type == FlowType.TRANSFER and f.from_entity == "contract"]

            # Check: mints should have corresponding deposits
            if mints and not transfers_in:
                issues.append({
                    "type": "ECON-CONSERV-001",
                    "title": "Unbacked Minting",
                    "severity": "CRITICAL",
                    "description": f"Token {token} is minted without corresponding deposit",
                    "lines": [m.line_number for m in mints],
                    "attack": "Call mint without depositing, extract value",
                })

            # Check: burns should have corresponding withdrawals
            if burns and not transfers_out:
                issues.append({
                    "type": "ECON-CONSERV-002",
                    "title": "Burn Without Redemption",
                    "severity": "HIGH",
                    "description": f"Token {token} is burned without corresponding withdrawal",
                    "lines": [b.line_number for b in burns],
                    "attack": "Force burns to extract value from others",
                })

        return issues


class FlashLoanAnalyzer:
    """
    Analyze flash loan attack vectors.

    Models:
    1. What can be borrowed
    2. What can be manipulated during the loan
    3. What profit can be extracted
    4. Is profit > loan fee?
    """

    FLASH_LOAN_PROVIDERS = {
        "aave": {"fee": 0.0009, "max_borrow": "unlimited"},
        "uniswap": {"fee": 0.003, "max_borrow": "pool_liquidity"},
        "balancer": {"fee": 0.0, "max_borrow": "pool_liquidity"},
        "dydx": {"fee": 0.0, "max_borrow": "pool_liquidity"},
        "maker": {"fee": 0.0, "max_borrow": "dai_liquidity"},
    }

    def analyze_attack_surface(self, code: str) -> list[AttackPath]:
        """Identify potential flash loan attack paths."""
        attacks = []

        # Check for price dependencies
        if self._uses_spot_price(code):
            attacks.append(AttackPath(
                name="Flash Loan Price Manipulation",
                steps=[
                    {"action": "flash_loan", "asset": "ETH/USDC", "amount": "large"},
                    {"action": "swap", "direction": "manipulate_price_up"},
                    {"action": "exploit", "target": "price_dependent_function"},
                    {"action": "swap", "direction": "reverse"},
                    {"action": "repay", "loan": "original + fee"},
                ],
                profit_expression="extracted_value - flash_loan_fee - gas",
                required_capital="0 (flash loan)",
                complexity="MEDIUM",
                flash_loan_compatible=True,
                mev_extractable=True,
            ))

        # Check for liquidity dependencies
        if self._has_liquidity_check(code):
            attacks.append(AttackPath(
                name="Liquidity Manipulation Attack",
                steps=[
                    {"action": "flash_loan", "asset": "pool_assets", "amount": "drain_pool"},
                    {"action": "exploit", "target": "liquidity_dependent_function"},
                    {"action": "repay", "loan": "original + fee"},
                ],
                profit_expression="exploit_profit - flash_loan_fee",
                required_capital="0 (flash loan)",
                complexity="HIGH",
                flash_loan_compatible=True,
                mev_extractable=False,
            ))

        # Check for share/token ratio manipulation
        if self._has_share_calculation(code):
            attacks.append(AttackPath(
                name="Share Inflation Attack",
                steps=[
                    {"action": "deposit", "amount": "1 wei", "timing": "first"},
                    {"action": "donate", "asset": "underlying", "amount": "large"},
                    {"action": "wait", "for": "victim_deposit"},
                    {"action": "withdraw", "shares": "attacker_shares"},
                ],
                profit_expression="(victim_deposit * attacker_share_ratio) - initial_deposit - donation",
                required_capital="donation_amount",
                complexity="LOW",
                flash_loan_compatible=True,
                mev_extractable=True,
            ))

        return attacks

    def _uses_spot_price(self, code: str) -> bool:
        """Check if code uses manipulable spot prices."""
        patterns = [
            r"\.slot0\(\)",
            r"getReserves\(\)",
            r"balanceOf\([^)]+\)\s*/\s*totalSupply",
            r"price\s*=.*balanceOf",
        ]
        return any(re.search(p, code) for p in patterns)

    def _has_liquidity_check(self, code: str) -> bool:
        """Check if code depends on liquidity levels."""
        patterns = [
            r"availableLiquidity",
            r"getAvailable",
            r"liquidity\s*[<>=]",
        ]
        return any(re.search(p, code) for p in patterns)

    def _has_share_calculation(self, code: str) -> bool:
        """Check if code has share/asset calculations."""
        patterns = [
            r"totalSupply\s*==\s*0",
            r"shares\s*=.*totalSupply",
            r"assets\s*/\s*shares",
            r"_mint.*amount",
        ]
        return any(re.search(p, code) for p in patterns)


class MEVAnalyzer:
    """
    Analyze MEV (Maximal Extractable Value) opportunities.

    Identifies:
    - Sandwich attack vectors
    - Front-running opportunities
    - Back-running opportunities
    - Just-in-time liquidity
    """

    def find_mev_vectors(self, code: str) -> list[dict]:
        """Find MEV extraction opportunities."""
        vectors = []

        # Sandwich attack vectors (trades without slippage protection)
        if self._has_unprotected_swap(code):
            vectors.append({
                "type": "MEV-SANDWICH-001",
                "title": "Sandwich Attack Vector",
                "severity": "HIGH",
                "description": "Swap without slippage protection can be sandwiched",
                "attack": "Front-run with large swap, back-run to profit from price impact",
                "profit": "victim_slippage - 2 * gas_cost",
                "protection": "Add minAmountOut parameter with reasonable value",
            })

        # Front-running vectors (predictable profitable transactions)
        if self._has_frontrunnable_action(code):
            vectors.append({
                "type": "MEV-FRONT-001",
                "title": "Front-Running Vector",
                "severity": "MEDIUM",
                "description": "Profitable action can be front-run",
                "attack": "Monitor mempool, copy transaction with higher gas",
                "protection": "Use commit-reveal or private mempool",
            })

        # Liquidation MEV
        if self._has_liquidation(code):
            vectors.append({
                "type": "MEV-LIQ-001",
                "title": "Liquidation MEV",
                "severity": "INFO",
                "description": "Liquidations are competitive MEV",
                "attack": "Monitor positions, liquidate profitably",
                "note": "This is expected behavior but affects protocol dynamics",
            })

        return vectors

    def _has_unprotected_swap(self, code: str) -> bool:
        """Check for swaps without slippage protection."""
        # Has swap but minAmountOut is 0 or missing
        has_swap = bool(re.search(r'swap|exchange', code, re.IGNORECASE))
        no_slippage = bool(re.search(r'minAmount\w*\s*[:=]\s*0|amountOutMin\s*[:=]\s*0', code))
        return has_swap and no_slippage

    def _has_frontrunnable_action(self, code: str) -> bool:
        """Check for front-runnable actions."""
        patterns = [
            r"arbitrage",
            r"liquidate",
            r"claim.*reward",
            r"withdraw.*profit",
        ]
        return any(re.search(p, code, re.IGNORECASE) for p in patterns)

    def _has_liquidation(self, code: str) -> bool:
        """Check for liquidation functionality."""
        return bool(re.search(r'liquidat', code, re.IGNORECASE))


class EconomicAnalyzer:
    """
    Master economic analysis orchestrator.

    Combines:
    - Token flow analysis
    - Invariant checking
    - Flash loan attack modeling
    - MEV analysis
    """

    def __init__(self, language: str = "solidity"):
        self.language = language
        self.flow_analyzer = TokenFlowAnalyzer(language)
        self.flash_analyzer = FlashLoanAnalyzer()
        self.mev_analyzer = MEVAnalyzer()

    def full_analysis(self, code: str, protocol_type: str = "generic") -> dict:
        """
        Run complete economic analysis.

        Args:
            code: Smart contract source code
            protocol_type: Type of protocol (amm, lending, vault, generic)

        Returns:
            Complete economic analysis results
        """
        results = {
            "token_flows": [],
            "conservation_issues": [],
            "invariant_checks": [],
            "flash_loan_attacks": [],
            "mev_vectors": [],
            "total_risk_score": 0,
        }

        # Analyze token flows
        flows = self.flow_analyzer.extract_flows(code)
        results["token_flows"] = [
            {
                "token": f.token,
                "type": f.flow_type.value,
                "from": f.from_entity,
                "to": f.to_entity,
                "amount": f.amount_expr,
                "line": f.line_number,
            }
            for f in flows
        ]

        # Check conservation
        results["conservation_issues"] = self.flow_analyzer.check_conservation()

        # Check invariants
        invariants = EconomicInvariants.get_invariants_for_protocol(protocol_type)
        for inv in invariants:
            check_result = self._check_invariant(code, inv)
            results["invariant_checks"].append({
                "name": inv.name,
                "category": inv.category,
                "status": check_result["status"],
                "details": check_result.get("details", ""),
            })

        # Find flash loan attack paths
        results["flash_loan_attacks"] = [
            {
                "name": a.name,
                "steps": a.steps,
                "profit": a.profit_expression,
                "capital_required": a.required_capital,
                "complexity": a.complexity,
            }
            for a in self.flash_analyzer.analyze_attack_surface(code)
        ]

        # Find MEV vectors
        results["mev_vectors"] = self.mev_analyzer.find_mev_vectors(code)

        # Calculate risk score
        results["total_risk_score"] = self._calculate_risk_score(results)

        return results

    def _check_invariant(self, code: str, invariant: EconomicInvariant) -> dict:
        """Check if code maintains an invariant."""
        # This is a heuristic check - full verification would use formal methods
        status = "UNKNOWN"
        details = ""

        if invariant.category == "conservation":
            issues = self.flow_analyzer.check_conservation()
            if issues:
                status = "VIOLATED"
                details = f"Found {len(issues)} conservation issues"
            else:
                status = "LIKELY_HOLDS"

        elif invariant.category == "bounds":
            # Check for bound checks in code
            if re.search(r'require\s*\([^)]*<|assert\s*\([^)]*<', code):
                status = "LIKELY_HOLDS"
            else:
                status = "NEEDS_VERIFICATION"
                details = "No explicit bound checks found"

        elif invariant.category == "ratio":
            # Check for ratio calculations
            if re.search(r'collateral.*>=.*debt|health.*factor', code, re.IGNORECASE):
                status = "LIKELY_HOLDS"
            else:
                status = "NEEDS_VERIFICATION"

        return {"status": status, "details": details}

    def _calculate_risk_score(self, results: dict) -> int:
        """Calculate overall economic risk score (0-100)."""
        score = 0

        # Conservation issues are critical
        score += len(results["conservation_issues"]) * 25

        # Flash loan attacks
        for attack in results["flash_loan_attacks"]:
            if attack["complexity"] == "LOW":
                score += 20
            elif attack["complexity"] == "MEDIUM":
                score += 15
            else:
                score += 10

        # MEV vectors
        for vector in results["mev_vectors"]:
            if vector.get("severity") == "HIGH":
                score += 15
            elif vector.get("severity") == "MEDIUM":
                score += 10
            else:
                score += 5

        return min(100, score)


def analyze_economics(code: str, protocol_type: str = "generic") -> dict:
    """
    Analyze economic security of smart contract.

    Args:
        code: Source code to analyze
        protocol_type: Protocol type (amm, lending, vault, generic)

    Returns:
        Economic analysis results
    """
    analyzer = EconomicAnalyzer()
    return analyzer.full_analysis(code, protocol_type)
