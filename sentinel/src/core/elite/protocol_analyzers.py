"""
SENTINEL Elite - Protocol-Specific Analyzers

Deep analysis modules for major DeFi protocols with protocol-specific
invariants, attack vectors, and security patterns.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from abc import ABC, abstractmethod
from enum import Enum
import re


class ProtocolType(Enum):
    UNISWAP_V3 = "uniswap_v3"
    UNISWAP_V4 = "uniswap_v4"
    AAVE_V3 = "aave_v3"
    CURVE = "curve"
    GMX_V2 = "gmx_v2"
    COMPOUND_V3 = "compound_v3"
    MAKER = "maker"
    LIDO = "lido"
    EIGENLAYER = "eigenlayer"
    MORPHO = "morpho"


@dataclass
class ProtocolVulnerability:
    """Protocol-specific vulnerability finding"""
    protocol: ProtocolType
    category: str
    severity: str
    title: str
    description: str
    affected_component: str
    invariant_violated: Optional[str]
    similar_exploits: List[str]
    remediation: str
    code_location: Optional[str] = None


@dataclass
class InvariantCheck:
    """Protocol invariant verification"""
    name: str
    description: str
    expression: str  # Solidity expression
    critical: bool
    violated: bool = False
    violation_context: Optional[str] = None


class BaseProtocolAnalyzer(ABC):
    """Base class for protocol-specific analyzers"""

    @property
    @abstractmethod
    def protocol_type(self) -> ProtocolType:
        pass

    @property
    @abstractmethod
    def invariants(self) -> List[InvariantCheck]:
        pass

    @abstractmethod
    def analyze(self, code: str, context: Dict) -> List[ProtocolVulnerability]:
        pass

    @abstractmethod
    def get_integration_patterns(self) -> Dict[str, str]:
        """Return safe integration patterns"""
        pass


class UniswapV4Analyzer(BaseProtocolAnalyzer):
    """
    Uniswap V4 Hook Security Analyzer

    Analyzes custom hooks for:
    - Callback validation
    - Reentrancy in hook callbacks
    - Fee manipulation
    - Liquidity theft
    - MEV vulnerabilities
    """

    HOOK_FLAGS = {
        "BEFORE_INITIALIZE": 1 << 13,
        "AFTER_INITIALIZE": 1 << 12,
        "BEFORE_ADD_LIQUIDITY": 1 << 11,
        "AFTER_ADD_LIQUIDITY": 1 << 10,
        "BEFORE_REMOVE_LIQUIDITY": 1 << 9,
        "AFTER_REMOVE_LIQUIDITY": 1 << 8,
        "BEFORE_SWAP": 1 << 7,
        "AFTER_SWAP": 1 << 6,
        "BEFORE_DONATE": 1 << 5,
        "AFTER_DONATE": 1 << 4,
        "BEFORE_SWAP_RETURNS_DELTA": 1 << 3,
        "AFTER_SWAP_RETURNS_DELTA": 1 << 2,
        "AFTER_ADD_LIQUIDITY_RETURNS_DELTA": 1 << 1,
        "AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA": 1 << 0,
    }

    # Critical V4 vulnerabilities
    V4_VULNS = {
        "hook_address_collision": {
            "pattern": r"address\s+hook\s*=",
            "description": "Hook address may not match required flag prefix",
            "severity": "HIGH",
            "remediation": "Ensure hook address has correct flag bits set"
        },
        "missing_pool_manager_check": {
            "pattern": r"function\s+(beforeSwap|afterSwap|beforeAdd|afterAdd)",
            "anti_pattern": r"msg\.sender\s*==\s*poolManager",
            "description": "Hook callback missing PoolManager sender validation",
            "severity": "CRITICAL",
            "remediation": "Add require(msg.sender == address(poolManager))"
        },
        "delta_manipulation": {
            "pattern": r"return\s+.*BalanceDelta",
            "description": "Hook returns delta without proper validation",
            "severity": "HIGH",
            "remediation": "Validate delta calculations prevent fund loss"
        },
        "hook_reentrancy": {
            "pattern": r"(beforeSwap|afterSwap).*external",
            "anti_pattern": r"nonReentrant|lock",
            "description": "Hook callbacks may be vulnerable to reentrancy",
            "severity": "HIGH",
            "remediation": "Add reentrancy guards to hook callbacks"
        },
        "unsafe_sqrtprice": {
            "pattern": r"sqrtPriceX96",
            "description": "Direct sqrtPriceX96 manipulation without bounds",
            "severity": "MEDIUM",
            "remediation": "Validate price within acceptable range"
        },
        "tick_spacing_mismatch": {
            "pattern": r"tickSpacing",
            "description": "Hook may not handle all tick spacing values",
            "severity": "MEDIUM",
            "remediation": "Support dynamic tick spacing from pool"
        }
    }

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.UNISWAP_V4

    @property
    def invariants(self) -> List[InvariantCheck]:
        return [
            InvariantCheck(
                name="hook_address_flags",
                description="Hook address must encode enabled callbacks",
                expression="address(hook) & FLAGS == expectedFlags",
                critical=True
            ),
            InvariantCheck(
                name="delta_conservation",
                description="BalanceDelta must conserve total value",
                expression="delta0 + delta1 == 0 || fee_accounted",
                critical=True
            ),
            InvariantCheck(
                name="pool_manager_only",
                description="Only PoolManager can call hook callbacks",
                expression="msg.sender == address(poolManager)",
                critical=True
            ),
            InvariantCheck(
                name="no_unauthorized_unlock",
                description="Hooks cannot bypass lock mechanism",
                expression="poolManager.isUnlocked() during callback",
                critical=True
            ),
        ]

    def analyze(self, code: str, context: Dict) -> List[ProtocolVulnerability]:
        vulns = []

        for vuln_name, vuln_info in self.V4_VULNS.items():
            if re.search(vuln_info["pattern"], code, re.IGNORECASE):
                # Check if anti-pattern (mitigation) is present
                if "anti_pattern" in vuln_info:
                    if re.search(vuln_info["anti_pattern"], code, re.IGNORECASE):
                        continue  # Mitigation present

                vulns.append(ProtocolVulnerability(
                    protocol=self.protocol_type,
                    category="hook_security",
                    severity=vuln_info["severity"],
                    title=vuln_name.replace("_", " ").title(),
                    description=vuln_info["description"],
                    affected_component="Hook Contract",
                    invariant_violated=self._get_violated_invariant(vuln_name),
                    similar_exploits=self._get_similar_exploits(vuln_name),
                    remediation=vuln_info["remediation"]
                ))

        # Check for dynamic fee manipulation
        if "getFee" in code or "dynamicFee" in code:
            vulns.extend(self._analyze_fee_logic(code))

        return vulns

    def _analyze_fee_logic(self, code: str) -> List[ProtocolVulnerability]:
        """Analyze dynamic fee implementation for vulnerabilities"""
        vulns = []

        # Check for unbounded fees
        if not re.search(r"fee\s*[<>=]+\s*\d+", code):
            vulns.append(ProtocolVulnerability(
                protocol=self.protocol_type,
                category="fee_manipulation",
                severity="HIGH",
                title="Unbounded Dynamic Fee",
                description="Dynamic fee has no upper bound check",
                affected_component="getFee function",
                invariant_violated="fee <= MAX_FEE",
                similar_exploits=["Dynamic fee manipulation attacks"],
                remediation="Add require(fee <= MAX_FEE) check"
            ))

        return vulns

    def _get_violated_invariant(self, vuln_name: str) -> Optional[str]:
        mapping = {
            "missing_pool_manager_check": "pool_manager_only",
            "delta_manipulation": "delta_conservation",
            "hook_address_collision": "hook_address_flags",
        }
        return mapping.get(vuln_name)

    def _get_similar_exploits(self, vuln_name: str) -> List[str]:
        return []  # V4 is new, no known exploits yet

    def get_integration_patterns(self) -> Dict[str, str]:
        return {
            "safe_hook_base": '''
abstract contract SafeHook is IHook {
    IPoolManager public immutable poolManager;

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "Not PoolManager");
        _;
    }

    modifier onlyValidPools(PoolKey calldata key) {
        require(isValidPool(key), "Invalid pool");
        _;
    }
}
''',
            "safe_before_swap": '''
function beforeSwap(
    address sender,
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    bytes calldata hookData
) external override onlyPoolManager onlyValidPools(key) returns (bytes4, BeforeSwapDelta, uint24) {
    // Your logic here
    return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
}
'''
        }


class AaveV3Analyzer(BaseProtocolAnalyzer):
    """
    Aave V3 Integration Security Analyzer

    Analyzes integrations for:
    - Flash loan callback security
    - Liquidation logic
    - Interest rate manipulation
    - Collateral factor issues
    - E-mode misconfiguration
    """

    AAVE_VULNS = {
        "flash_loan_callback_unprotected": {
            "pattern": r"executeOperation\s*\(",
            "anti_pattern": r"POOL\.flashLoan.*msg\.sender\s*==.*POOL",
            "description": "Flash loan callback may be callable by anyone",
            "severity": "CRITICAL"
        },
        "missing_health_factor_check": {
            "pattern": r"(borrow|withdraw)\s*\(",
            "anti_pattern": r"healthFactor|getHealthFactor",
            "description": "Missing health factor check before borrow/withdraw",
            "severity": "HIGH"
        },
        "oracle_price_stale": {
            "pattern": r"getAssetPrice\s*\(",
            "anti_pattern": r"(timestamp|updatedAt|freshness)",
            "description": "Using oracle price without staleness check",
            "severity": "HIGH"
        },
        "liquidation_bonus_abuse": {
            "pattern": r"liquidation",
            "description": "Potential liquidation bonus manipulation",
            "severity": "MEDIUM"
        },
        "emode_misconfiguration": {
            "pattern": r"setUserEMode|eMode",
            "description": "E-mode configuration may allow excessive leverage",
            "severity": "MEDIUM"
        },
        "supply_cap_bypass": {
            "pattern": r"supply\s*\(",
            "anti_pattern": r"supplyCap|getReserveCaps",
            "description": "Supply without checking reserve caps",
            "severity": "LOW"
        }
    }

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.AAVE_V3

    @property
    def invariants(self) -> List[InvariantCheck]:
        return [
            InvariantCheck(
                name="health_factor_above_one",
                description="User health factor must stay above 1",
                expression="healthFactor >= 1e18",
                critical=True
            ),
            InvariantCheck(
                name="flash_loan_repayment",
                description="Flash loans must be repaid with premium",
                expression="balance_after >= amount + premium",
                critical=True
            ),
            InvariantCheck(
                name="collateral_not_exceeded",
                description="Borrow cannot exceed collateral value",
                expression="totalDebt <= totalCollateral * LTV",
                critical=True
            ),
            InvariantCheck(
                name="reserve_not_paused",
                description="Operations fail on paused reserves",
                expression="!reserve.paused",
                critical=False
            ),
        ]

    def analyze(self, code: str, context: Dict) -> List[ProtocolVulnerability]:
        vulns = []

        for vuln_name, vuln_info in self.AAVE_VULNS.items():
            if re.search(vuln_info["pattern"], code, re.IGNORECASE):
                if "anti_pattern" in vuln_info:
                    if re.search(vuln_info["anti_pattern"], code, re.IGNORECASE):
                        continue

                vulns.append(ProtocolVulnerability(
                    protocol=self.protocol_type,
                    category="aave_integration",
                    severity=vuln_info["severity"],
                    title=vuln_name.replace("_", " ").title(),
                    description=vuln_info["description"],
                    affected_component="Aave Integration",
                    invariant_violated=None,
                    similar_exploits=self._get_aave_exploits(vuln_name),
                    remediation=self._get_remediation(vuln_name)
                ))

        return vulns

    def _get_aave_exploits(self, vuln_name: str) -> List[str]:
        exploits = {
            "flash_loan_callback_unprotected": ["Multiple flash loan callback exploits"],
            "oracle_price_stale": ["Mango Markets oracle manipulation", "CREAM Finance oracle attack"],
        }
        return exploits.get(vuln_name, [])

    def _get_remediation(self, vuln_name: str) -> str:
        remediations = {
            "flash_loan_callback_unprotected": "Verify initiator address in executeOperation",
            "missing_health_factor_check": "Check health factor > 1 before operations",
            "oracle_price_stale": "Verify price timestamp freshness",
            "emode_misconfiguration": "Validate E-mode category parameters",
        }
        return remediations.get(vuln_name, "Review and fix the identified issue")

    def get_integration_patterns(self) -> Dict[str, str]:
        return {
            "safe_flash_loan": '''
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external override returns (bool) {
    // CRITICAL: Verify this was initiated by us
    require(msg.sender == address(POOL), "Not Aave Pool");
    require(initiator == address(this), "Not initiated by this contract");

    // Your flash loan logic here

    // Approve repayment
    for (uint i = 0; i < assets.length; i++) {
        uint256 amountOwed = amounts[i] + premiums[i];
        IERC20(assets[i]).approve(address(POOL), amountOwed);
    }

    return true;
}
''',
            "safe_supply": '''
function safeSupply(address asset, uint256 amount) internal {
    // Check reserve is active and not frozen
    DataTypes.ReserveData memory reserve = POOL.getReserveData(asset);
    require(!reserve.configuration.getFrozen(), "Reserve frozen");
    require(reserve.configuration.getActive(), "Reserve not active");

    // Check supply cap
    (uint256 supplyCap,) = POOL.getReserveCaps(asset);
    if (supplyCap > 0) {
        uint256 currentSupply = IERC20(reserve.aTokenAddress).totalSupply();
        require(currentSupply + amount <= supplyCap * 1e18, "Supply cap exceeded");
    }

    IERC20(asset).approve(address(POOL), amount);
    POOL.supply(asset, amount, address(this), 0);
}
'''
        }


class CurveAnalyzer(BaseProtocolAnalyzer):
    """
    Curve Finance Security Analyzer

    Analyzes for:
    - Read-only reentrancy
    - Virtual price manipulation
    - Imbalanced pool attacks
    - Admin key risks
    - Gauge manipulation
    """

    CURVE_VULNS = {
        "read_only_reentrancy": {
            "pattern": r"get_virtual_price|virtualPrice",
            "anti_pattern": r"(ReentrancyGuard|nonReentrant|lock)",
            "description": "Vulnerable to read-only reentrancy via get_virtual_price",
            "severity": "CRITICAL",
            "exploits": ["Curve/Vyper reentrancy 2023 - $70M+"]
        },
        "virtual_price_oracle": {
            "pattern": r"get_virtual_price.*oracle|price.*get_virtual_price",
            "description": "Using virtual price as oracle without protection",
            "severity": "HIGH",
            "exploits": ["Multiple LP token pricing exploits"]
        },
        "imbalanced_add_liquidity": {
            "pattern": r"add_liquidity.*\[.*0.*\]|single.*sided",
            "description": "Single-sided liquidity vulnerable to sandwich",
            "severity": "MEDIUM",
            "exploits": []
        },
        "remove_liquidity_imbalance": {
            "pattern": r"remove_liquidity_imbalance",
            "description": "Imbalanced removal may be sandwiched",
            "severity": "MEDIUM",
            "exploits": []
        },
        "unchecked_slippage": {
            "pattern": r"exchange\s*\(|swap\s*\(",
            "anti_pattern": r"min_dy|minAmount|slippage",
            "description": "Swap without slippage protection",
            "severity": "HIGH",
            "exploits": ["Countless sandwich attacks"]
        },
        "admin_key_risk": {
            "pattern": r"admin|owner.*kill|emergency",
            "description": "Admin can rug or pause the pool",
            "severity": "MEDIUM",
            "exploits": []
        }
    }

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.CURVE

    @property
    def invariants(self) -> List[InvariantCheck]:
        return [
            InvariantCheck(
                name="virtual_price_monotonic",
                description="Virtual price should only increase (per LP token)",
                expression="new_virtual_price >= old_virtual_price",
                critical=True
            ),
            InvariantCheck(
                name="balanced_pool",
                description="Pool should maintain reasonable balance ratios",
                expression="max(balances) / min(balances) < threshold",
                critical=False
            ),
            InvariantCheck(
                name="no_reentrancy_virtual_price",
                description="Virtual price read protected during state changes",
                expression="!locked when reading virtual_price",
                critical=True
            ),
            InvariantCheck(
                name="a_parameter_bounded",
                description="Amplification parameter within safe range",
                expression="A >= MIN_A && A <= MAX_A",
                critical=False
            ),
        ]

    def analyze(self, code: str, context: Dict) -> List[ProtocolVulnerability]:
        vulns = []

        for vuln_name, vuln_info in self.CURVE_VULNS.items():
            if re.search(vuln_info["pattern"], code, re.IGNORECASE):
                if "anti_pattern" in vuln_info:
                    if re.search(vuln_info["anti_pattern"], code, re.IGNORECASE):
                        continue

                vulns.append(ProtocolVulnerability(
                    protocol=self.protocol_type,
                    category="curve_integration",
                    severity=vuln_info["severity"],
                    title=vuln_name.replace("_", " ").title(),
                    description=vuln_info["description"],
                    affected_component="Curve Integration",
                    invariant_violated=None,
                    similar_exploits=vuln_info.get("exploits", []),
                    remediation=self._get_curve_remediation(vuln_name)
                ))

        return vulns

    def _get_curve_remediation(self, vuln_name: str) -> str:
        remediations = {
            "read_only_reentrancy": "Use reentrancy guards or check pool lock state",
            "virtual_price_oracle": "Use TWAP or Chainlink instead of spot virtual price",
            "unchecked_slippage": "Always specify min_dy parameter",
            "imbalanced_add_liquidity": "Add liquidity in balanced proportions when possible",
        }
        return remediations.get(vuln_name, "Review and fix the identified issue")

    def get_integration_patterns(self) -> Dict[str, str]:
        return {
            "safe_virtual_price": '''
// Check Curve pool is not in callback (reentrancy protection)
function getSafeVirtualPrice(ICurvePool pool) internal view returns (uint256) {
    // For Curve pools with reentrancy lock
    // The pool reverts if called during reentrancy
    try pool.get_virtual_price() returns (uint256 price) {
        return price;
    } catch {
        revert("Pool in reentrancy");
    }
}
''',
            "safe_exchange": '''
function safeExchange(
    ICurvePool pool,
    int128 i,
    int128 j,
    uint256 dx,
    uint256 minDy
) internal returns (uint256) {
    require(minDy > 0, "Must specify min output");

    // Calculate expected with slippage
    uint256 expected = pool.get_dy(i, j, dx);
    require(minDy >= expected * 99 / 100, "Slippage too high");

    return pool.exchange(i, j, dx, minDy);
}
'''
        }


class GMXv2Analyzer(BaseProtocolAnalyzer):
    """
    GMX V2 Security Analyzer

    Analyzes for:
    - Position manipulation
    - Price impact exploitation
    - Keeper manipulation
    - Funding rate attacks
    - Liquidation MEV
    """

    GMX_VULNS = {
        "price_impact_manipulation": {
            "pattern": r"(createOrder|executeOrder).*market",
            "description": "Large orders may be exploited via price impact",
            "severity": "MEDIUM"
        },
        "keeper_front_running": {
            "pattern": r"keeper|executor",
            "description": "Order execution vulnerable to keeper MEV",
            "severity": "MEDIUM"
        },
        "funding_rate_attack": {
            "pattern": r"fundingRate|funding",
            "description": "Funding rate may be manipulated with large positions",
            "severity": "MEDIUM"
        },
        "oracle_delay_exploitation": {
            "pattern": r"(minPrice|maxPrice).*oracle",
            "description": "Oracle delay may allow profitable trading",
            "severity": "HIGH"
        },
        "position_size_limit": {
            "pattern": r"increasePosition|openPosition",
            "anti_pattern": r"maxPosition|sizeLimit",
            "description": "No position size limits may allow market manipulation",
            "severity": "MEDIUM"
        },
        "callback_reentrancy": {
            "pattern": r"afterOrderExecution|callback",
            "anti_pattern": r"nonReentrant",
            "description": "Order callback may be reentrant",
            "severity": "HIGH"
        }
    }

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.GMX_V2

    @property
    def invariants(self) -> List[InvariantCheck]:
        return [
            InvariantCheck(
                name="position_collateral_ratio",
                description="Position must maintain minimum collateral ratio",
                expression="collateral >= size * minCollateralRatio",
                critical=True
            ),
            InvariantCheck(
                name="market_balanced",
                description="Long/short open interest should be balanced",
                expression="abs(longOI - shortOI) <= maxImbalance",
                critical=False
            ),
            InvariantCheck(
                name="oracle_price_bounded",
                description="Oracle price within acceptable range",
                expression="abs(oraclePrice - refPrice) <= maxDeviation",
                critical=True
            ),
        ]

    def analyze(self, code: str, context: Dict) -> List[ProtocolVulnerability]:
        vulns = []

        for vuln_name, vuln_info in self.GMX_VULNS.items():
            if re.search(vuln_info["pattern"], code, re.IGNORECASE):
                if "anti_pattern" in vuln_info:
                    if re.search(vuln_info["anti_pattern"], code, re.IGNORECASE):
                        continue

                vulns.append(ProtocolVulnerability(
                    protocol=self.protocol_type,
                    category="gmx_integration",
                    severity=vuln_info["severity"],
                    title=vuln_name.replace("_", " ").title(),
                    description=vuln_info["description"],
                    affected_component="GMX Integration",
                    invariant_violated=None,
                    similar_exploits=[],
                    remediation=self._get_gmx_remediation(vuln_name)
                ))

        return vulns

    def _get_gmx_remediation(self, vuln_name: str) -> str:
        remediations = {
            "price_impact_manipulation": "Use limit orders and split large trades",
            "keeper_front_running": "Use acceptable price limits in orders",
            "oracle_delay_exploitation": "Validate prices against multiple sources",
            "callback_reentrancy": "Add reentrancy guards to callbacks",
        }
        return remediations.get(vuln_name, "Review and fix the identified issue")

    def get_integration_patterns(self) -> Dict[str, str]:
        return {
            "safe_market_order": '''
function createSafeMarketOrder(
    address market,
    bool isLong,
    uint256 sizeDelta,
    uint256 acceptablePrice
) internal returns (bytes32) {
    // Set acceptable price with slippage
    uint256 currentPrice = oracle.getPrice(market);
    uint256 slippage = isLong ? 100 : 99; // 1% slippage

    acceptablePrice = isLong
        ? currentPrice * 101 / 100  // Max buy price
        : currentPrice * 99 / 100;  // Min sell price

    return orderHandler.createOrder(
        market,
        isLong,
        sizeDelta,
        acceptablePrice,
        block.timestamp + 300  // 5 min expiry
    );
}
'''
        }


class ProtocolAnalyzerRegistry:
    """Registry of all protocol analyzers"""

    def __init__(self):
        self.analyzers: Dict[ProtocolType, BaseProtocolAnalyzer] = {
            ProtocolType.UNISWAP_V4: UniswapV4Analyzer(),
            ProtocolType.AAVE_V3: AaveV3Analyzer(),
            ProtocolType.CURVE: CurveAnalyzer(),
            ProtocolType.GMX_V2: GMXv2Analyzer(),
        }

    def get_analyzer(self, protocol: ProtocolType) -> Optional[BaseProtocolAnalyzer]:
        return self.analyzers.get(protocol)

    def detect_protocols(self, code: str) -> List[ProtocolType]:
        """Detect which protocols are used in the code"""
        detected = []

        protocol_signatures = {
            ProtocolType.UNISWAP_V4: [
                r"IPoolManager", r"PoolKey", r"beforeSwap", r"afterSwap",
                r"BalanceDelta", r"hookAddress"
            ],
            ProtocolType.AAVE_V3: [
                r"IPool", r"executeOperation", r"flashLoan", r"aToken",
                r"healthFactor", r"getUserAccountData"
            ],
            ProtocolType.CURVE: [
                r"get_virtual_price", r"ICurvePool", r"add_liquidity",
                r"exchange\s*\(.*int128", r"StableSwap"
            ],
            ProtocolType.GMX_V2: [
                r"IOrderHandler", r"IPositionRouter", r"createIncreasePosition",
                r"executionFee", r"afterOrderExecution"
            ],
        }

        for protocol, signatures in protocol_signatures.items():
            for sig in signatures:
                if re.search(sig, code, re.IGNORECASE):
                    detected.append(protocol)
                    break

        return detected

    def analyze_all(self, code: str, context: Dict = None) -> List[ProtocolVulnerability]:
        """Analyze code against all detected protocols"""
        context = context or {}
        all_vulns = []

        detected_protocols = self.detect_protocols(code)

        for protocol in detected_protocols:
            analyzer = self.get_analyzer(protocol)
            if analyzer:
                vulns = analyzer.analyze(code, context)
                all_vulns.extend(vulns)

        return all_vulns


# Convenience function
def analyze_protocol_integrations(code: str) -> List[ProtocolVulnerability]:
    """Analyze code for protocol-specific vulnerabilities"""
    registry = ProtocolAnalyzerRegistry()
    return registry.analyze_all(code)
