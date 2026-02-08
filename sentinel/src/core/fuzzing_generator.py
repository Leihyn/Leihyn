"""
Stateful Fuzzing Test Generator - Chimera-Compatible Suite Generation

Based on Recon Magic methodology for achieving high standardized line coverage.
Generates:
- Target functions (functions of interest)
- Clamped handlers (reduced search space)
- Shortcut functions (multi-step state transitions)
- Chimera-compatible test scaffolding for Echidna/Medusa

Key Concepts:
- Standardized Line Coverage: Focus only on state-changing functions
- Clamped Handlers: Restrict inputs using system state or setup values
- Shortcut Functions: Combine multiple handlers for deep state exploration

Reference: https://getrecon.xyz/blog/recon-magic
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class ClampingStrategy(Enum):
    """How to clamp handler inputs."""
    STATIC = "static"      # Use values from test setup
    DYNAMIC = "dynamic"    # Use values from system state
    BOUNDED = "bounded"    # Use min/max bounds
    ACTOR = "actor"        # Use actor-specific values


class FunctionMutability(Enum):
    """Solidity function mutability."""
    PURE = "pure"
    VIEW = "view"
    NONPAYABLE = "nonpayable"
    PAYABLE = "payable"


@dataclass
class SolidityFunction:
    """Parsed Solidity function."""
    name: str
    visibility: str
    mutability: FunctionMutability
    parameters: list[tuple[str, str]]  # (type, name)
    returns: list[str]
    modifiers: list[str]
    body: str
    line_number: int

    @property
    def is_state_changing(self) -> bool:
        """True if function can modify state."""
        return self.mutability not in (FunctionMutability.PURE, FunctionMutability.VIEW)

    @property
    def is_external(self) -> bool:
        """True if function is externally callable."""
        return self.visibility in ("external", "public")


@dataclass
class StateVariable:
    """Parsed state variable."""
    name: str
    var_type: str
    visibility: str
    initial_value: Optional[str] = None


@dataclass
class ClampedHandler:
    """A clamped handler with reduced search space."""
    original_function: str
    handler_name: str
    clamping_strategy: ClampingStrategy
    clamped_params: dict[str, str]  # param_name -> clamping_expression
    code: str
    rationale: str


@dataclass
class ShortcutFunction:
    """A shortcut function combining multiple state changes."""
    name: str
    handlers_called: list[str]
    description: str
    code: str


@dataclass
class FuzzingConfig:
    """Configuration for fuzzing suite generation."""
    contract_name: str
    actors: list[str] = field(default_factory=lambda: ["actor1", "actor2", "actor3"])
    setup_tokens: list[str] = field(default_factory=list)
    initial_balances: dict[str, str] = field(default_factory=dict)
    max_clamped_handlers: int = 50
    include_shortcuts: bool = True
    include_unclamped: bool = True  # Keep unclamped for full search space
    framework: str = "chimera"  # chimera, foundry-invariant


@dataclass
class FuzzingSuite:
    """Complete fuzzing test suite."""
    setup_code: str
    target_functions: list[str]
    unclamped_handlers: list[str]
    clamped_handlers: list[ClampedHandler]
    shortcut_functions: list[ShortcutFunction]
    invariants: list[str]
    config: FuzzingConfig


class ContractAnalyzer:
    """Analyze Solidity contracts for fuzzing generation."""

    def __init__(self, source: str, contract_name: str):
        self.source = source
        self.contract_name = contract_name
        self.functions: list[SolidityFunction] = []
        self.state_variables: list[StateVariable] = []
        self._parse()

    def _parse(self) -> None:
        """Parse contract source."""
        self._parse_functions()
        self._parse_state_variables()

    def _parse_functions(self) -> None:
        """Extract all functions from contract."""
        # Regex for function signatures
        func_pattern = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*'
            r'(public|external|internal|private)?\s*'
            r'(pure|view|payable)?\s*'
            r'(?:returns\s*\(([^)]*)\))?\s*'
            r'(?:(\w+(?:\s*,\s*\w+)*))?\s*'
            r'\{',
            re.MULTILINE
        )

        for i, match in enumerate(func_pattern.finditer(self.source)):
            name = match.group(1)
            params_str = match.group(2) or ""
            visibility = match.group(3) or "public"
            mutability_str = match.group(4) or "nonpayable"
            returns_str = match.group(5) or ""
            modifiers_str = match.group(6) or ""

            # Parse parameters
            params = []
            if params_str.strip():
                for param in params_str.split(","):
                    parts = param.strip().split()
                    if len(parts) >= 2:
                        params.append((parts[0], parts[-1]))
                    elif len(parts) == 1:
                        params.append((parts[0], f"param{len(params)}"))

            # Parse mutability
            mutability_map = {
                "pure": FunctionMutability.PURE,
                "view": FunctionMutability.VIEW,
                "payable": FunctionMutability.PAYABLE,
            }
            mutability = mutability_map.get(mutability_str, FunctionMutability.NONPAYABLE)

            # Parse returns
            returns = [r.strip() for r in returns_str.split(",") if r.strip()]

            # Parse modifiers
            modifiers = [m.strip() for m in modifiers_str.split(",") if m.strip()]

            self.functions.append(SolidityFunction(
                name=name,
                visibility=visibility,
                mutability=mutability,
                parameters=params,
                returns=returns,
                modifiers=modifiers,
                body="",  # Would need brace matching for full body
                line_number=self.source[:match.start()].count('\n') + 1,
            ))

    def _parse_state_variables(self) -> None:
        """Extract state variables."""
        # Simple regex for state variables
        var_pattern = re.compile(
            r'^\s*(mapping|uint\d*|int\d*|address|bool|bytes\d*|string)'
            r'(?:\[.*?\])*\s+'
            r'(public|private|internal)?\s*'
            r'(\w+)\s*(?:=\s*([^;]+))?;',
            re.MULTILINE
        )

        for match in var_pattern.finditer(self.source):
            self.state_variables.append(StateVariable(
                var_type=match.group(1),
                visibility=match.group(2) or "internal",
                name=match.group(3),
                initial_value=match.group(4),
            ))

    def get_functions_of_interest(self) -> list[SolidityFunction]:
        """
        Get functions of interest for fuzzing (state-changing, external).
        This is the core of standardized line coverage.
        """
        return [
            f for f in self.functions
            if f.is_state_changing and f.is_external
        ]

    def get_view_functions(self) -> list[SolidityFunction]:
        """Get view/pure functions (excluded from standardized coverage)."""
        return [f for f in self.functions if not f.is_state_changing]


class ClampingEngine:
    """Generate clamped handlers with intelligent input restriction."""

    def __init__(self, analyzer: ContractAnalyzer, config: FuzzingConfig):
        self.analyzer = analyzer
        self.config = config

    def generate_clamped_handler(
        self,
        func: SolidityFunction,
    ) -> ClampedHandler:
        """Generate a clamped handler for a function."""
        clamped_params = {}
        strategy = ClampingStrategy.DYNAMIC

        for param_type, param_name in func.parameters:
            clamping = self._determine_clamping(param_type, param_name, func)
            if clamping:
                clamped_params[param_name] = clamping

        handler_code = self._generate_handler_code(func, clamped_params)

        return ClampedHandler(
            original_function=func.name,
            handler_name=f"handler_{func.name}_clamped",
            clamping_strategy=strategy,
            clamped_params=clamped_params,
            code=handler_code,
            rationale=self._generate_rationale(func, clamped_params),
        )

    def _determine_clamping(
        self,
        param_type: str,
        param_name: str,
        func: SolidityFunction,
    ) -> Optional[str]:
        """Determine appropriate clamping expression for parameter."""

        # Amount parameters - clamp to actor's balance
        if "amount" in param_name.lower() or param_name in ("value", "qty", "shares"):
            if "uint" in param_type:
                return self._get_balance_clamp(param_name)

        # Address parameters - use known actors
        if param_type == "address":
            if "recipient" in param_name.lower() or "to" in param_name.lower():
                return "_getRandomActor()"
            if "token" in param_name.lower():
                return "_getRandomToken()"

        # ID parameters - use existing IDs from state
        if "id" in param_name.lower() or param_name.endswith("Id"):
            return self._get_id_clamp(param_name)

        # Boolean - no clamping needed, small search space
        if param_type == "bool":
            return None

        # Generic uint - bound to reasonable range
        if "uint" in param_type:
            return f"_bound({param_name}, 1, type(uint128).max)"

        return None

    def _get_balance_clamp(self, param_name: str) -> str:
        """Get clamping expression for balance-related parameters."""
        return f"_bound({param_name}, 1, _getActorBalance(currentActor))"

    def _get_id_clamp(self, param_name: str) -> str:
        """Get clamping expression for ID parameters."""
        return f"_bound({param_name}, 0, _getMaxId())"

    def _generate_handler_code(
        self,
        func: SolidityFunction,
        clamped_params: dict[str, str],
    ) -> str:
        """Generate Solidity code for clamped handler."""
        params = ", ".join([
            f"{ptype} {pname}" for ptype, pname in func.parameters
        ])

        clamping_lines = []
        for param_name, clamp_expr in clamped_params.items():
            clamping_lines.append(f"        {param_name} = {clamp_expr};")

        clamping_code = "\n".join(clamping_lines)

        call_params = ", ".join([pname for _, pname in func.parameters])

        return f'''    function handler_{func.name}_clamped({params}) external {{
        // Clamping: reduce search space while maintaining coverage
{clamping_code}

        // Call unclamped handler with clamped values
        this.handler_{func.name}({call_params});
    }}'''

    def _generate_rationale(
        self,
        func: SolidityFunction,
        clamped_params: dict[str, str],
    ) -> str:
        """Generate rationale for clamping decisions."""
        if not clamped_params:
            return "No clamping applied - function has simple parameters"

        rationales = []
        for param, clamp in clamped_params.items():
            if "balance" in clamp.lower():
                rationales.append(f"{param}: clamped to actor's available balance")
            elif "_bound" in clamp:
                rationales.append(f"{param}: bounded to reasonable range")
            elif "Actor" in clamp:
                rationales.append(f"{param}: restricted to known actors")

        return "; ".join(rationales)


class ShortcutGenerator:
    """Generate shortcut functions for deep state exploration."""

    def __init__(self, analyzer: ContractAnalyzer, config: FuzzingConfig):
        self.analyzer = analyzer
        self.config = config

    def generate_shortcuts(self) -> list[ShortcutFunction]:
        """Generate shortcut functions based on common patterns."""
        shortcuts = []

        functions_of_interest = self.analyzer.get_functions_of_interest()
        func_names = [f.name for f in functions_of_interest]

        # Pattern: deposit -> borrow (lending protocols)
        if "deposit" in func_names and "borrow" in func_names:
            shortcuts.append(self._generate_deposit_borrow_shortcut())

        # Pattern: approve -> transferFrom (tokens)
        if "approve" in func_names and "transferFrom" in func_names:
            shortcuts.append(self._generate_approve_transfer_shortcut())

        # Pattern: stake -> claim (staking)
        if "stake" in func_names and ("claim" in func_names or "withdraw" in func_names):
            shortcuts.append(self._generate_stake_claim_shortcut())

        # Pattern: mint -> swap (DEX)
        if any("mint" in n or "addLiquidity" in n for n in func_names):
            if any("swap" in n for n in func_names):
                shortcuts.append(self._generate_liquidity_swap_shortcut())

        # Pattern: open position -> modify -> close (perps)
        if "openPosition" in func_names or "open" in func_names:
            shortcuts.append(self._generate_position_lifecycle_shortcut())

        return shortcuts

    def _generate_deposit_borrow_shortcut(self) -> ShortcutFunction:
        """Shortcut: deposit collateral then borrow."""
        return ShortcutFunction(
            name="shortcut_depositAndBorrow",
            handlers_called=["deposit", "borrow"],
            description="Deposit collateral and immediately borrow - tests collateralization",
            code='''    function shortcut_depositAndBorrow(
        uint256 depositAmount,
        uint256 borrowAmount
    ) external {
        // Step 1: Deposit collateral
        depositAmount = _bound(depositAmount, 1e18, _getActorBalance(currentActor));
        this.handler_deposit(depositAmount);

        // Step 2: Borrow against collateral
        uint256 maxBorrow = _getMaxBorrowAmount(currentActor);
        borrowAmount = _bound(borrowAmount, 1, maxBorrow);
        this.handler_borrow(borrowAmount);
    }''',
        )

    def _generate_approve_transfer_shortcut(self) -> ShortcutFunction:
        """Shortcut: approve then transfer."""
        return ShortcutFunction(
            name="shortcut_approveAndTransfer",
            handlers_called=["approve", "transferFrom"],
            description="Approve spender then execute transferFrom",
            code='''    function shortcut_approveAndTransfer(
        address spender,
        address recipient,
        uint256 amount
    ) external {
        // Step 1: Approve
        spender = _getRandomActor();
        amount = _bound(amount, 1, _getActorBalance(currentActor));
        this.handler_approve(spender, amount);

        // Step 2: TransferFrom as spender
        _setCurrentActor(spender);
        recipient = _getRandomActor();
        this.handler_transferFrom(currentActor, recipient, amount);
    }''',
        )

    def _generate_stake_claim_shortcut(self) -> ShortcutFunction:
        """Shortcut: stake, wait, claim."""
        return ShortcutFunction(
            name="shortcut_stakeAndClaim",
            handlers_called=["stake", "claim"],
            description="Stake tokens, advance time, then claim rewards",
            code='''    function shortcut_stakeAndClaim(
        uint256 stakeAmount,
        uint256 timeSkip
    ) external {
        // Step 1: Stake
        stakeAmount = _bound(stakeAmount, 1e18, _getActorBalance(currentActor));
        this.handler_stake(stakeAmount);

        // Step 2: Advance time for rewards to accrue
        timeSkip = _bound(timeSkip, 1 days, 365 days);
        vm.warp(block.timestamp + timeSkip);

        // Step 3: Claim rewards
        this.handler_claim();
    }''',
        )

    def _generate_liquidity_swap_shortcut(self) -> ShortcutFunction:
        """Shortcut: add liquidity then swap."""
        return ShortcutFunction(
            name="shortcut_addLiquidityAndSwap",
            handlers_called=["addLiquidity", "swap"],
            description="Add liquidity then perform swap - tests AMM invariants",
            code='''    function shortcut_addLiquidityAndSwap(
        uint256 liquidityAmount,
        uint256 swapAmount
    ) external {
        // Step 1: Add liquidity
        liquidityAmount = _bound(liquidityAmount, 1e18, _getActorBalance(currentActor) / 2);
        this.handler_addLiquidity(liquidityAmount, liquidityAmount);

        // Step 2: Swap
        swapAmount = _bound(swapAmount, 1e15, liquidityAmount / 10);
        this.handler_swap(swapAmount, 0, currentActor);
    }''',
        )

    def _generate_position_lifecycle_shortcut(self) -> ShortcutFunction:
        """Shortcut: open position -> modify -> close."""
        return ShortcutFunction(
            name="shortcut_positionLifecycle",
            handlers_called=["openPosition", "modifyPosition", "closePosition"],
            description="Full position lifecycle - tests position accounting",
            code='''    function shortcut_positionLifecycle(
        uint256 margin,
        uint256 size,
        bool isLong
    ) external {
        // Step 1: Open position
        margin = _bound(margin, 1e18, _getActorBalance(currentActor));
        size = _bound(size, margin, margin * 10);  // Up to 10x leverage
        this.handler_openPosition(margin, size, isLong);

        // Step 2: Price moves, modify position
        vm.warp(block.timestamp + 1 hours);
        uint256 additionalMargin = _bound(margin / 10, 1e17, margin);
        this.handler_addMargin(additionalMargin);

        // Step 3: Close position
        vm.warp(block.timestamp + 1 days);
        this.handler_closePosition();
    }''',
        )


class ChimeraGenerator:
    """Generate Chimera-compatible test suites."""

    def __init__(self, config: FuzzingConfig):
        self.config = config

    def generate_suite(
        self,
        analyzer: ContractAnalyzer,
        clamped_handlers: list[ClampedHandler],
        shortcuts: list[ShortcutFunction],
    ) -> str:
        """Generate complete Chimera test suite."""
        functions_of_interest = analyzer.get_functions_of_interest()

        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{BaseTargetFunctions}} from "@chimera/BaseTargetFunctions.sol";
import {{Properties}} from "./Properties.sol";
import {{vm}} from "@chimera/Hevm.sol";

/**
 * @title {self.config.contract_name} Target Functions
 * @notice Generated by Sentinel Fuzzing Generator
 *
 * Methodology: Recon Magic - Standardized Line Coverage
 * - Target functions: {len(functions_of_interest)} state-changing functions
 * - Clamped handlers: {len(clamped_handlers)} (reduced search space)
 * - Shortcut functions: {len(shortcuts)} (deep state exploration)
 *
 * Run:
 *   echidna . --contract {self.config.contract_name}Test --config echidna.yaml
 *   medusa fuzz --config medusa.json
 */
abstract contract TargetFunctions is BaseTargetFunctions, Properties {{

    // =========================================================================
    // ACTOR MANAGEMENT
    // =========================================================================

    address[] internal actors;
    address internal currentActor;

    modifier useActor(uint256 actorSeed) {{
        currentActor = actors[_bound(actorSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }}

    function _getRandomActor() internal view returns (address) {{
        return actors[uint256(keccak256(abi.encode(block.timestamp))) % actors.length];
    }}

    function _setCurrentActor(address actor) internal {{
        vm.stopPrank();
        currentActor = actor;
        vm.startPrank(currentActor);
    }}

    // =========================================================================
    // UNCLAMPED HANDLERS - Full search space
    // =========================================================================

{self._generate_unclamped_handlers(functions_of_interest)}

    // =========================================================================
    // CLAMPED HANDLERS - Reduced search space for better coverage
    // =========================================================================

{self._generate_clamped_handlers_code(clamped_handlers)}

    // =========================================================================
    // SHORTCUT FUNCTIONS - Multi-step state transitions
    // =========================================================================

{self._generate_shortcuts_code(shortcuts)}

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    function _getActorBalance(address actor) internal view returns (uint256) {{
        // Override in setup to return actual balance
        return actor.balance;
    }}

    function _getMaxBorrowAmount(address actor) internal view returns (uint256) {{
        // Override based on protocol logic
        return type(uint128).max;
    }}

    function _getMaxId() internal view returns (uint256) {{
        // Override based on protocol state
        return 1000;
    }}

    function _bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {{
        if (min > max) return min;
        if (x < min) return min;
        if (x > max) return max;
        return x;
    }}
}}
'''

    def _generate_unclamped_handlers(
        self,
        functions: list[SolidityFunction],
    ) -> str:
        """Generate unclamped handler functions."""
        handlers = []
        for func in functions:
            params = ", ".join([
                f"{ptype} {pname}" for ptype, pname in func.parameters
            ])
            call_params = ", ".join([pname for _, pname in func.parameters])

            value_str = ""
            if func.mutability == FunctionMutability.PAYABLE:
                value_str = "{{value: msg.value}}"

            handlers.append(f'''    function handler_{func.name}({params}) external {{
        target.{func.name}{value_str}({call_params});
    }}''')

        return "\n\n".join(handlers)

    def _generate_clamped_handlers_code(
        self,
        handlers: list[ClampedHandler],
    ) -> str:
        """Generate clamped handler code."""
        return "\n\n".join([h.code for h in handlers])

    def _generate_shortcuts_code(
        self,
        shortcuts: list[ShortcutFunction],
    ) -> str:
        """Generate shortcut function code."""
        return "\n\n".join([s.code for s in shortcuts])


class StandardizedCoverageAnalyzer:
    """
    Analyze standardized line coverage.

    Standardized coverage = coverage over functions of interest only,
    excluding view/pure functions that don't contribute to state exploration.
    """

    def __init__(self, analyzer: ContractAnalyzer):
        self.analyzer = analyzer

    def get_standardized_functions(self) -> list[SolidityFunction]:
        """Get functions that count toward standardized coverage."""
        return self.analyzer.get_functions_of_interest()

    def get_excluded_functions(self) -> list[SolidityFunction]:
        """Get functions excluded from standardized coverage."""
        return self.analyzer.get_view_functions()

    def calculate_standardized_coverage(
        self,
        covered_functions: set[str],
    ) -> float:
        """
        Calculate standardized line coverage percentage.

        Args:
            covered_functions: Set of function names that were covered

        Returns:
            Coverage percentage (0-100)
        """
        target_functions = self.get_standardized_functions()
        if not target_functions:
            return 100.0

        covered_count = sum(
            1 for f in target_functions if f.name in covered_functions
        )
        return (covered_count / len(target_functions)) * 100


def generate_fuzzing_suite(
    source: str,
    contract_name: str,
    config: Optional[FuzzingConfig] = None,
) -> str:
    """
    Generate complete Chimera-compatible fuzzing test suite.

    Args:
        source: Solidity source code
        contract_name: Name of the contract to fuzz
        config: Optional configuration

    Returns:
        Generated Solidity test suite code
    """
    config = config or FuzzingConfig(contract_name=contract_name)

    # Analyze contract
    analyzer = ContractAnalyzer(source, contract_name)

    # Generate clamped handlers
    clamping_engine = ClampingEngine(analyzer, config)
    clamped_handlers = [
        clamping_engine.generate_clamped_handler(f)
        for f in analyzer.get_functions_of_interest()
    ]

    # Generate shortcuts
    shortcut_gen = ShortcutGenerator(analyzer, config)
    shortcuts = shortcut_gen.generate_shortcuts() if config.include_shortcuts else []

    # Generate Chimera suite
    chimera_gen = ChimeraGenerator(config)
    return chimera_gen.generate_suite(analyzer, clamped_handlers, shortcuts)


def analyze_standardized_coverage(
    source: str,
    contract_name: str,
) -> dict:
    """
    Analyze a contract for standardized coverage metrics.

    Returns dict with:
    - functions_of_interest: List of state-changing external functions
    - excluded_functions: List of view/pure functions
    - total_standardized: Number of functions in standardized coverage
    """
    analyzer = ContractAnalyzer(source, contract_name)
    coverage_analyzer = StandardizedCoverageAnalyzer(analyzer)

    foi = coverage_analyzer.get_standardized_functions()
    excluded = coverage_analyzer.get_excluded_functions()

    return {
        "functions_of_interest": [f.name for f in foi],
        "excluded_functions": [f.name for f in excluded],
        "total_standardized": len(foi),
        "total_excluded": len(excluded),
        "standardized_ratio": len(foi) / max(len(foi) + len(excluded), 1),
    }
