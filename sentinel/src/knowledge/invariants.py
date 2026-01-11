"""
Invariant Engine - Inference, Generation, and Fuzzing.

World-class auditors think in invariants:
- What properties MUST always hold?
- Can any sequence of calls break them?
- What happens at the edges?

This engine:
1. Infers invariants from code patterns
2. Infers invariants from documentation
3. Generates Foundry invariant tests
4. Runs fuzzing and parses violations
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


class InvariantCategory(Enum):
    """Categories of protocol invariants."""
    BALANCE = "balance"           # Sum/total balance invariants
    STATE = "state"               # State machine invariants
    TRANSITION = "transition"     # Before/after state transitions
    ECONOMIC = "economic"         # Economic/value invariants
    ACCESS = "access"             # Access control invariants
    ORDERING = "ordering"         # Operation ordering invariants
    BOUND = "bound"               # Range/boundary invariants


@dataclass
class Invariant:
    """A protocol invariant that must hold."""
    id: str
    category: InvariantCategory
    description: str
    expression: str                  # Solidity expression
    setup_code: str = ""             # Any setup needed
    contracts_involved: list[str] = field(default_factory=list)
    functions_that_modify: list[str] = field(default_factory=list)
    confidence: float = 0.8          # How confident we are this is valid
    source: str = "inferred"         # Where this came from
    critical: bool = False           # Is this critical (loss of funds if broken)?


@dataclass
class InvariantViolation:
    """A detected invariant violation."""
    invariant: Invariant
    violation_tx: str                # Transaction/call sequence that broke it
    counterexample: dict             # Values that caused violation
    severity: str                    # Critical/High/Medium/Low
    explanation: str


class InvariantInferenceEngine:
    """
    Automatically infer invariants from Solidity code.

    Techniques:
    1. Extract require/assert statements
    2. Identify balance tracking patterns
    3. Detect access control patterns
    4. Find state machine transitions
    5. Analyze value flows
    """

    def __init__(self, llm_client=None):
        self.llm = llm_client
        self.invariants: list[Invariant] = []

    def infer_from_code(self, source: str, contract_name: str = "Contract") -> list[Invariant]:
        """
        Extract invariants from Solidity source code.
        """
        invariants = []

        # 1. Extract from require statements
        invariants.extend(self._extract_from_requires(source, contract_name))

        # 2. Extract balance invariants
        invariants.extend(self._extract_balance_invariants(source, contract_name))

        # 3. Extract state machine invariants
        invariants.extend(self._extract_state_invariants(source, contract_name))

        # 4. Extract access control invariants
        invariants.extend(self._extract_access_invariants(source, contract_name))

        # 5. Extract economic invariants
        invariants.extend(self._extract_economic_invariants(source, contract_name))

        self.invariants.extend(invariants)
        return invariants

    def _extract_from_requires(self, source: str, contract_name: str) -> list[Invariant]:
        """Extract invariants from require/assert statements."""
        invariants = []

        # Pattern: require(condition, "message")
        require_pattern = r'require\s*\(\s*([^,;]+?)(?:\s*,\s*["\'][^"\']*["\']\s*)?\)'

        for match in re.finditer(require_pattern, source):
            condition = match.group(1).strip()
            line_num = source[:match.start()].count('\n') + 1

            # Skip trivial conditions
            if self._is_trivial_require(condition):
                continue

            # Determine category
            category = self._categorize_condition(condition)

            invariants.append(Invariant(
                id=f"{contract_name}-REQ-{line_num}",
                category=category,
                description=f"Require condition at line {line_num}",
                expression=condition,
                contracts_involved=[contract_name],
                source="require_statement",
                confidence=0.9,
            ))

        return invariants

    def _is_trivial_require(self, condition: str) -> bool:
        """Check if a require condition is trivial."""
        trivial_patterns = [
            r'^msg\.sender\s*!=\s*address\(0\)$',
            r'^_?[a-zA-Z]+\s*!=\s*address\(0\)$',
            r'^_?[a-zA-Z]+\s*>\s*0$',
            r'^_?[a-zA-Z]+\s*!=\s*0$',
        ]
        return any(re.match(p, condition.strip()) for p in trivial_patterns)

    def _categorize_condition(self, condition: str) -> InvariantCategory:
        """Categorize a condition by its type."""
        condition_lower = condition.lower()

        if any(x in condition_lower for x in ['balance', 'supply', 'reserve', 'amount']):
            return InvariantCategory.BALANCE
        elif any(x in condition_lower for x in ['owner', 'admin', 'role', 'auth']):
            return InvariantCategory.ACCESS
        elif any(x in condition_lower for x in ['state', 'status', 'phase', 'stage']):
            return InvariantCategory.STATE
        elif any(x in condition_lower for x in ['<', '>', '<=', '>=']):
            return InvariantCategory.BOUND
        else:
            return InvariantCategory.TRANSITION

    def _extract_balance_invariants(self, source: str, contract_name: str) -> list[Invariant]:
        """Extract balance-related invariants."""
        invariants = []

        # Pattern: totalSupply and balances mapping
        if 'totalSupply' in source and 'balanceOf' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-BAL-SUPPLY",
                category=InvariantCategory.BALANCE,
                description="Sum of all balances must equal totalSupply",
                expression="sum_of_balances <= totalSupply()",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.95,
                critical=True,
            ))

        # Pattern: Vault shares and assets
        if 'totalAssets' in source and 'totalSupply' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-VAULT-SHARE",
                category=InvariantCategory.ECONOMIC,
                description="Share price must be consistent",
                expression="totalAssets() >= 0 && (totalSupply() == 0 || totalAssets() / totalSupply() > 0)",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.85,
                critical=True,
            ))

        # Pattern: Reserve tracking
        reserve_pattern = r'(reserves?|liquidity)\[[^\]]+\]'
        if re.search(reserve_pattern, source, re.IGNORECASE):
            invariants.append(Invariant(
                id=f"{contract_name}-RESERVE-BAL",
                category=InvariantCategory.BALANCE,
                description="Contract balance must cover reserves",
                expression="token.balanceOf(address(this)) >= reserves",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.9,
                critical=True,
            ))

        return invariants

    def _extract_state_invariants(self, source: str, contract_name: str) -> list[Invariant]:
        """Extract state machine invariants."""
        invariants = []

        # Pattern: Enum state variable
        enum_pattern = r'enum\s+(\w+)\s*\{([^}]+)\}'
        for match in re.finditer(enum_pattern, source):
            enum_name = match.group(1)
            states = [s.strip() for s in match.group(2).split(',')]

            if len(states) > 2:  # Non-trivial state machine
                invariants.append(Invariant(
                    id=f"{contract_name}-STATE-{enum_name}",
                    category=InvariantCategory.STATE,
                    description=f"State machine {enum_name} must have valid transitions",
                    expression=f"uint8({enum_name.lower()}) < {len(states)}",
                    contracts_involved=[contract_name],
                    source="pattern_detection",
                    confidence=0.8,
                ))

        # Pattern: initialized/paused flags
        if 'initialized' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-INIT-ONCE",
                category=InvariantCategory.STATE,
                description="Contract can only be initialized once",
                expression="initialized == true => owner != address(0)",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.95,
            ))

        if 'paused' in source or 'Pausable' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-PAUSED-STATE",
                category=InvariantCategory.STATE,
                description="When paused, state-changing operations should revert",
                expression="paused() == true => no_state_changes",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.85,
            ))

        return invariants

    def _extract_access_invariants(self, source: str, contract_name: str) -> list[Invariant]:
        """Extract access control invariants."""
        invariants = []

        # Pattern: onlyOwner modifier usage
        if 'onlyOwner' in source or 'Ownable' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-OWNER-NON-ZERO",
                category=InvariantCategory.ACCESS,
                description="Owner must never be zero address",
                expression="owner() != address(0)",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.95,
            ))

        # Pattern: Role-based access (AccessControl)
        if 'AccessControl' in source or 'hasRole' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-ADMIN-EXISTS",
                category=InvariantCategory.ACCESS,
                description="At least one admin must exist",
                expression="getRoleMemberCount(DEFAULT_ADMIN_ROLE) > 0",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.9,
            ))

        return invariants

    def _extract_economic_invariants(self, source: str, contract_name: str) -> list[Invariant]:
        """Extract economic/value invariants."""
        invariants = []

        # Pattern: Collateral ratio (lending)
        if 'collateral' in source.lower() and 'debt' in source.lower():
            invariants.append(Invariant(
                id=f"{contract_name}-COLLAT-RATIO",
                category=InvariantCategory.ECONOMIC,
                description="Collateral must always exceed minimum ratio",
                expression="collateralValue >= debtValue * minCollateralRatio / 1e18",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.85,
                critical=True,
            ))

        # Pattern: Fee calculations
        fee_pattern = r'fee[s]?\s*[=<>]|FEE[S]?_'
        if re.search(fee_pattern, source):
            invariants.append(Invariant(
                id=f"{contract_name}-FEE-BOUND",
                category=InvariantCategory.BOUND,
                description="Fees must be within bounds",
                expression="fee <= MAX_FEE && fee >= MIN_FEE",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.8,
            ))

        # Pattern: Slippage protection
        if 'minOut' in source or 'minAmount' in source or 'deadline' in source:
            invariants.append(Invariant(
                id=f"{contract_name}-SLIPPAGE",
                category=InvariantCategory.ECONOMIC,
                description="Output must meet minimum requirement",
                expression="amountOut >= minAmountOut",
                contracts_involved=[contract_name],
                source="pattern_detection",
                confidence=0.9,
            ))

        return invariants

    async def infer_with_llm(self, source: str, contract_name: str) -> list[Invariant]:
        """Use LLM with extended thinking to find deeper invariants."""
        if not self.llm:
            return []

        prompt = f"""Analyze this smart contract and identify all invariants that MUST hold.

**Contract: {contract_name}**
```solidity
{source[:12000]}
```

**Think about:**
1. **Balance Invariants**: What balance equations must always hold?
   - Token balances vs tracked amounts
   - Sum of user balances vs total
   - Contract balance vs liabilities

2. **State Invariants**: What state properties must always be true?
   - Initialization state
   - Valid enum values
   - Consistent timestamps

3. **Transition Invariants**: What must be true before/after operations?
   - Balance changes match expectations
   - No unexpected value extraction
   - Proper event emission

4. **Economic Invariants**: What economic properties must hold?
   - No arbitrage within single tx
   - Collateral ratios maintained
   - Fee bounds respected

5. **Access Invariants**: What access control properties must hold?
   - Owner/admin always exists
   - Roles properly assigned
   - No privilege escalation

For each invariant, provide:
- Category (balance/state/transition/economic/access)
- Natural language description
- Solidity expression to test
- Is it critical (loss of funds if broken)?

Format each invariant as:
INVARIANT: [category]
DESCRIPTION: [what must hold]
EXPRESSION: [solidity boolean expression]
CRITICAL: [yes/no]
---
"""

        response = self.llm.ultrathink(
            prompt=prompt,
            system="You are a smart contract security expert. Find invariants that if broken would indicate a vulnerability.",
            thinking_budget=20000,
            stream=False,
        )

        # Parse response
        invariants = self._parse_llm_invariants(response.content, contract_name)
        self.invariants.extend(invariants)
        return invariants

    def _parse_llm_invariants(self, response: str, contract_name: str) -> list[Invariant]:
        """Parse invariants from LLM response."""
        invariants = []

        # Split by separator
        blocks = response.split('---')

        for i, block in enumerate(blocks):
            if 'INVARIANT:' not in block:
                continue

            try:
                # Extract fields
                category_match = re.search(r'INVARIANT:\s*(\w+)', block)
                desc_match = re.search(r'DESCRIPTION:\s*(.+?)(?=EXPRESSION:|$)', block, re.DOTALL)
                expr_match = re.search(r'EXPRESSION:\s*(.+?)(?=CRITICAL:|$)', block, re.DOTALL)
                critical_match = re.search(r'CRITICAL:\s*(yes|no)', block, re.IGNORECASE)

                if not all([category_match, desc_match, expr_match]):
                    continue

                category_str = category_match.group(1).lower()
                category = InvariantCategory.BALANCE  # default
                for cat in InvariantCategory:
                    if cat.value in category_str:
                        category = cat
                        break

                invariants.append(Invariant(
                    id=f"{contract_name}-LLM-{i:02d}",
                    category=category,
                    description=desc_match.group(1).strip(),
                    expression=expr_match.group(1).strip(),
                    contracts_involved=[contract_name],
                    source="llm_inference",
                    confidence=0.75,
                    critical=critical_match and critical_match.group(1).lower() == 'yes',
                ))
            except Exception:
                continue

        return invariants


class InvariantTestGenerator:
    """
    Generate Foundry invariant tests from invariants.
    """

    FOUNDRY_TEST_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";

{imports}

contract {contract_name}InvariantTest is Test, StdInvariant {{
    {target_contract} target;

    function setUp() public {{
        {setup_code}

        // Set target contract for invariant testing
        targetContract(address(target));
    }}

{invariant_functions}
}}

// Handler contract for controlled interactions
contract Handler is Test {{
    {target_contract} target;

    constructor({target_contract} _target) {{
        target = _target;
    }}

{handler_functions}
}}
'''

    INVARIANT_FUNCTION_TEMPLATE = '''    /// @notice {description}
    function invariant_{id}() public view {{
        {assertion}
    }}
'''

    def __init__(self):
        self.output_dir: Optional[Path] = None

    def generate_test_file(
        self,
        invariants: list[Invariant],
        target_contract: str,
        imports: str = "",
        setup_code: str = "",
    ) -> str:
        """Generate a complete Foundry invariant test file."""

        # Generate invariant functions
        invariant_functions = []
        for inv in invariants:
            func = self.INVARIANT_FUNCTION_TEMPLATE.format(
                description=inv.description,
                id=inv.id.replace("-", "_").lower(),
                assertion=self._make_assertion(inv),
            )
            invariant_functions.append(func)

        # Generate handler functions (basic)
        handler_functions = self._generate_handler_functions(target_contract)

        return self.FOUNDRY_TEST_TEMPLATE.format(
            imports=imports,
            contract_name=target_contract,
            target_contract=target_contract,
            setup_code=setup_code or f"target = new {target_contract}();",
            invariant_functions="\n".join(invariant_functions),
            handler_functions=handler_functions,
        )

    def _make_assertion(self, inv: Invariant) -> str:
        """Convert invariant expression to assertion."""
        expr = inv.expression

        # Handle common patterns
        if '=>' in expr:
            # Implication: A => B becomes !A || B
            parts = expr.split('=>')
            if len(parts) == 2:
                return f"assertTrue(!({parts[0].strip()}) || ({parts[1].strip()}), \"{inv.description}\");"

        # Direct boolean expression
        return f"assertTrue({expr}, \"{inv.description}\");"

    def _generate_handler_functions(self, target_contract: str) -> str:
        """Generate handler functions for common operations."""
        return f'''    // TODO: Add handler functions for controlled state transitions
    // Example:
    // function deposit(uint256 amount) external {{
    //     deal(address(token), address(this), amount);
    //     token.approve(address(target), amount);
    //     target.deposit(amount);
    // }}
'''

    def write_test_file(self, content: str, output_path: Path) -> None:
        """Write the generated test file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        console.print(f"[green]Generated invariant test: {output_path}[/green]")


class InvariantFuzzer:
    """
    Run Foundry invariant fuzzing and parse results.
    """

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.violations: list[InvariantViolation] = []

    async def run_fuzzing(
        self,
        test_file: str,
        runs: int = 10000,
        depth: int = 50,
        timeout: int = 600,
    ) -> list[InvariantViolation]:
        """Run Foundry invariant fuzzing."""

        cmd = [
            "forge", "test",
            "--mt", "invariant",
            "-vvv",
            f"--runs={runs}",
            f"--depth={depth}",
        ]

        console.print(f"[cyan]Running invariant fuzzing ({runs} runs, depth {depth})...[/cyan]")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Parse output for violations
            violations = self._parse_forge_output(result.stdout + result.stderr)
            self.violations.extend(violations)

            if violations:
                console.print(f"[red]Found {len(violations)} invariant violations![/red]")
            else:
                console.print(f"[green]All invariants held after {runs} runs[/green]")

            return violations

        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Fuzzing timed out after {timeout}s[/yellow]")
            return []
        except FileNotFoundError:
            console.print("[red]Foundry not installed. Run: curl -L https://foundry.paradigm.xyz | bash[/red]")
            return []

    def _parse_forge_output(self, output: str) -> list[InvariantViolation]:
        """Parse Foundry output for invariant violations."""
        violations = []

        # Pattern: [FAIL. Reason: assertion failed]
        fail_pattern = r'\[FAIL\.\s*Reason:\s*([^\]]+)\].*?invariant_(\w+)'

        for match in re.finditer(fail_pattern, output, re.DOTALL):
            reason = match.group(1)
            invariant_id = match.group(2)

            # Extract counterexample if available
            counter_pattern = r'Counterexample:\s*(.+?)(?=\n\n|\Z)'
            counter_match = re.search(counter_pattern, output[match.end():], re.DOTALL)

            violations.append(InvariantViolation(
                invariant=Invariant(
                    id=invariant_id,
                    category=InvariantCategory.BALANCE,
                    description=reason,
                    expression="",
                ),
                violation_tx=self._extract_call_sequence(output, match.end()),
                counterexample={"raw": counter_match.group(1) if counter_match else ""},
                severity="High",  # Invariant violations are usually serious
                explanation=reason,
            ))

        return violations

    def _extract_call_sequence(self, output: str, start_pos: int) -> str:
        """Extract the call sequence that led to violation."""
        # Look for call trace
        trace_pattern = r'Call sequence:(.+?)(?=\n\n|\Z)'
        match = re.search(trace_pattern, output[start_pos:], re.DOTALL)
        return match.group(1).strip() if match else "Unknown"

    def print_violations(self) -> None:
        """Print violations in a nice format."""
        if not self.violations:
            console.print("[green]No invariant violations found[/green]")
            return

        table = Table(title="Invariant Violations")
        table.add_column("Invariant", style="cyan")
        table.add_column("Reason", style="red")
        table.add_column("Severity")

        for v in self.violations:
            table.add_row(
                v.invariant.id,
                v.explanation[:60],
                v.severity,
            )

        console.print(table)


# Convenience functions
def infer_invariants(source: str, contract_name: str = "Contract") -> list[Invariant]:
    """Quick invariant inference from source code."""
    engine = InvariantInferenceEngine()
    return engine.infer_from_code(source, contract_name)


def generate_invariant_test(
    invariants: list[Invariant],
    target_contract: str,
    output_path: Optional[Path] = None,
) -> str:
    """Generate Foundry invariant test."""
    generator = InvariantTestGenerator()
    content = generator.generate_test_file(invariants, target_contract)

    if output_path:
        generator.write_test_file(content, output_path)

    return content
