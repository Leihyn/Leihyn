"""
Math Verification Hunter Agent - Deep algebraic verification of smart contract formulas.

Detects:
- TWAP tautologies (formula simplifies to spot price)
- Interest rate model errors
- Fee calculation precision loss
- AMM invariant violations
- Cumulative price accumulator bugs
- Token distribution formula errors
- Division-before-multiplication truncation
- Rounding direction exploits

This is the hunter that would catch bugs like:
    (cPriceLast + spot*dt - cPriceLast)/dt = spot
where the "time-weighted" average is actually just the instantaneous price.

Supports: Solidity, Rust/Solana, Move, Cairo
"""

import re
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an expert mathematician and smart contract auditor specializing in
algebraic verification of DeFi formulas. You find bugs by doing the algebra, not just
reading the code.

You verify: TWAP implementations, interest rate models, fee calculations, AMM invariant math,
cumulative price accumulators, and reward distribution formulas.
Consult the vulnerability cheatsheet below for known patterns, and use the
`get_vulnerability_reference` tool with category="math_verification" for detailed formula
classes, verification approach, code examples, and false-positive conditions.

## Core Method: Algebraic Simplification
For each formula: extract symbolic expression -> simplify step by step -> check if variables
cancel out (tautology) -> check boundary values (0, 1, max) -> check precision loss.

## Analysis Approach
1. Use find_math_functions to locate ALL functions with mathematical logic
2. For each, use extract_formula to get the symbolic expression
3. Use verify_formula_algebraically for deep algebraic verification
4. Use check_precision_loss to find division-before-multiplication and truncation
5. Report findings with the formula, what it simplifies to, and what it should compute

## Reporting
- ALWAYS SHOW YOUR ALGEBRA. Prove every simplification step by step.
- Rate: CRITICAL (tautology/broken invariant), HIGH (precision loss), MEDIUM (edge case), LOW (rounding)
"""


class MathVerificationHunter(AnalysisAgent):
    """
    Hunts for algebraic and mathematical bugs in smart contract formulas.

    Uses deep algebraic reasoning to:
    - Simplify formulas and detect tautologies
    - Verify TWAP implementations actually compute time-weighted averages
    - Check precision loss in fee and interest calculations
    - Validate AMM invariant math
    - Find division-before-multiplication truncation
    """

    role = "hunter"
    name = "math_verification_hunter"
    description = "Specialized agent for algebraic verification of math implementations"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    def __init__(self, state: AuditState, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        super().__init__(state=state, **kwargs)
        self.findings = []
        self.tools = self._build_tools()

    def _build_tools(self) -> list[Tool]:
        """Build tools available to this hunter."""
        return [
            Tool(
                name="read_file",
                description="Read a source code file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="find_math_functions",
                description=(
                    "Find functions containing mathematical logic in the codebase. "
                    "Searches for TWAP calculations, cumulative price logic, fee calculations, "
                    "interest rate computations, AMM math, and custom math implementations. "
                    "Returns file:line and the function name/snippet for each match."
                ),
                input_schema={"type": "object", "properties": {}},
                handler=self._find_math_functions,
            ),
            Tool(
                name="extract_formula",
                description=(
                    "Given a file path and function name, extract the mathematical formula "
                    "from the code. Reads the function source, identifies mathematical "
                    "expressions, and returns them in a readable symbolic form. "
                    "Example: `result = (cPriceLast + spotPrice * timeDelta - cPriceLast) / timeDelta` "
                    "-> `result = spotPrice` (simplified)."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the source file",
                        },
                        "function_name": {
                            "type": "string",
                            "description": "Name of the function to extract the formula from",
                        },
                    },
                    "required": ["file_path", "function_name"],
                },
                handler=self._extract_formula,
            ),
            Tool(
                name="verify_formula_algebraically",
                description=(
                    "The key verification tool. Takes a formula string and context about what "
                    "it is supposed to compute. Performs deep algebraic analysis: simplifies "
                    "the expression step by step, checks for tautologies (variables canceling out), "
                    "checks if it reduces to a trivial form, analyzes boundary behavior, and for "
                    "TWAP formulas verifies it ACTUALLY weights by time. Returns detailed analysis."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "formula": {
                            "type": "string",
                            "description": "The mathematical formula/expression to verify",
                        },
                        "context": {
                            "type": "string",
                            "description": (
                                "What this formula is supposed to compute "
                                "(e.g., 'TWAP price over a window', 'compound interest', "
                                "'swap output amount')"
                            ),
                        },
                    },
                    "required": ["formula"],
                },
                handler=self._verify_formula_algebraically,
            ),
            Tool(
                name="check_precision_loss",
                description=(
                    "Check for precision loss patterns in a file: division before multiplication, "
                    "integer division truncation in fee calculations, rounding errors in "
                    "share/pool math, and loss of precision with large numbers."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the source file to check",
                        },
                    },
                    "required": ["file_path"],
                },
                handler=self._check_precision_loss,
            ),
            Tool(
                name="report_finding",
                description="Report a mathematical verification finding",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "description": {"type": "string"},
                        "location": {"type": "string"},
                        "formula": {
                            "type": "string",
                            "description": "The problematic formula",
                        },
                        "simplified": {
                            "type": "string",
                            "description": "What the formula simplifies to",
                        },
                        "expected": {
                            "type": "string",
                            "description": "What the formula should compute",
                        },
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "vulnerability_type": {
                            "type": "string",
                            "description": "Specific vulnerability type if not generic arithmetic",
                        },
                    },
                    "required": ["title", "severity", "description", "location"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run mathematical verification analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        # Build context
        contracts_info = self._format_contracts_info()
        math_context = self._get_math_context()

        initial_prompt = f"""Analyze this {self.language.value} codebase for mathematical and algebraic bugs.

## Mathematical Context
{math_context}

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture
{self._format_architecture()}

Your analysis should follow this process:

1. Use find_math_functions to locate ALL functions with mathematical logic
2. For each math function found, use extract_formula to get the symbolic expression
3. For each formula, use verify_formula_algebraically to perform deep algebraic verification
4. Use check_precision_loss on files with significant math to find truncation/rounding bugs
5. Report all findings with report_finding, including the formula, what it simplifies to, and what it should compute

## Priority targets (check these first):

### TWAP / Cumulative Price Logic
Look for any formula that claims to compute a time-weighted average price.
Check: does it ACTUALLY weight by time, or does it simplify to just the spot price?
The classic bug: (cPriceLast + spot*dt - cPriceLast)/dt = spot (tautology!)

### Interest Rate / Compounding
Look for accrual, compound interest, rate-per-block calculations.
Check: is linear approximation used where compounding is needed?

### Fee Calculations
Look for fee = amount * rate / denominator patterns.
Check: division before multiplication? Truncation to zero for small amounts?

### AMM Math
Look for getAmountOut, swap calculations, invariant computations.
Check: does the invariant hold? Is the output formula correct?

### Share/Pool Token Math
Look for deposit/withdraw share calculations.
Check: first depositor attack? Donation attack? Rounding direction?

Be thorough. Show your algebra. Every formula gets verified.
"""

        # Use extended thinking for deep mathematical reasoning
        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            extended_thinking=True,
            thinking_budget=32000,
        )

        if self.verbose:
            print(f"  Math Verification Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _get_math_context(self) -> str:
        """Get language-specific mathematical context."""
        contexts = {
            Language.SOLIDITY: """
## Solidity Math Patterns

### TWAP (Time-Weighted Average Price)
```solidity
// Uniswap V2 style cumulative price
// Accumulator update (in _update):
price0CumulativeLast += uint(UQ112x112.encode(reserve1).uqdiv(reserve0)) * timeElapsed;

// TWAP calculation:
uint price0Average = (price0Cumulative - price0CumulativeOld) / timeElapsed;
```

### Common TWAP Bug (Tautology)
```solidity
// WRONG - this simplifies to just spotPrice!
function getTWAP() returns (uint256) {
    uint256 timeDelta = block.timestamp - lastTimestamp;
    uint256 cumulativeDelta = cumulativePriceLast + spotPrice * timeDelta - cumulativePriceLast;
    return cumulativeDelta / timeDelta;
    // = (cumulativePriceLast + spotPrice * timeDelta - cumulativePriceLast) / timeDelta
    // = (spotPrice * timeDelta) / timeDelta
    // = spotPrice  <-- NOT a TWAP!
}
```

### Interest Rate Models
```solidity
// Compound interest (correct)
uint256 compoundedRate = rpow(ratePerSecond, timeElapsed, RAY);
uint256 newDebt = principalDebt * compoundedRate / RAY;

// Linear approximation (only valid for short periods)
uint256 interest = principal * rate * timeElapsed / SECONDS_PER_YEAR / 1e18;
```

### Fee Calculations
```solidity
// WRONG - division before multiplication
uint256 fee = amount / 10000 * feeRate;  // Truncates for amount < 10000!

// CORRECT
uint256 fee = amount * feeRate / 10000;
```

### AMM Math
```solidity
// Constant product: x * y = k
// getAmountOut for constant product:
function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) {
    uint amountInWithFee = amountIn * 997;
    uint numerator = amountInWithFee * reserveOut;
    uint denominator = reserveIn * 1000 + amountInWithFee;
    return numerator / denominator;
}
```

### Precision and Rounding
- uint256 division always truncates (rounds toward zero)
- Multiply before divide to preserve precision
- Use WAD (1e18) or RAY (1e27) for fixed-point arithmetic
- Check: does rounding favor the protocol or the user?
""",
            Language.RUST: """
## Rust/Solana Math Patterns

### Fixed-Point Arithmetic
```rust
// SPL math with u128 precision
let result = (amount as u128)
    .checked_mul(rate as u128)?
    .checked_div(RATE_DENOMINATOR as u128)?;
```

### TWAP on Solana
```rust
// Oracle price accumulator
pub cumulative_price: u128,
pub last_update_slot: u64,

// TWAP calculation
let time_elapsed = current_slot - last_update_slot;
let twap = (current_cumulative - last_cumulative) / time_elapsed;
```

### Common Precision Issues
- checked_div truncates (no rounding)
- u64 overflow for large token amounts * price
- Decimal mismatch between tokens (6 vs 9 vs 18)

### Fee Patterns
```rust
let fee = amount
    .checked_mul(fee_bps)?
    .checked_div(10_000)?;
// Risk: returns 0 for small amounts
```
""",
            Language.MOVE: """
## Move Math Patterns

### Fixed-Point Libraries
```move
// Common pattern with u128 for intermediate calculations
let result = ((amount as u128) * (rate as u128) / (DENOMINATOR as u128)) as u64;
```

### AMM Math in Move
```move
// Constant product swap
public fun get_amount_out(
    amount_in: u64, reserve_in: u64, reserve_out: u64
): u64 {
    let amount_in_with_fee = (amount_in as u128) * 997;
    let numerator = amount_in_with_fee * (reserve_out as u128);
    let denominator = (reserve_in as u128) * 1000 + amount_in_with_fee;
    ((numerator / denominator) as u64)
}
```

### Common Issues
- u64 overflow without u128 intermediate
- Truncation in coin splitting
- Precision loss in LP token calculations
""",
            Language.CAIRO: """
## Cairo Math Patterns

### Felt Arithmetic
```cairo
// felt252 wraps on overflow - no automatic checks
let result = amount * rate / denominator;
```

### Fixed-Point in Cairo
```cairo
const WAD: u256 = 1_000_000_000_000_000_000;

fn mul_wad(a: u256, b: u256) -> u256 {
    a * b / WAD
}
```

### Common Issues
- felt252 overflow wraps silently
- No native fixed-point types
- Division truncation in u256 arithmetic
- Bit-shifting for fast division can introduce errors
""",
        }
        return contexts.get(self.language, contexts[Language.SOLIDITY])

    def _format_contracts_info(self) -> str:
        """Format contract info for the prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:10]:
            lines.append(f"- {contract.name}")
            if hasattr(contract, "functions") and contract.functions:
                for func in contract.functions[:5]:
                    lines.append(f"  - {func.name}()")
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture info."""
        if not self.state.architecture:
            return "No architecture analysis."

        notes = []
        if self.state.architecture.is_defi:
            notes.append("- DeFi protocol detected")
        if self.state.architecture.defi_type:
            notes.append(f"- DeFi type: {', '.join(self.state.architecture.defi_type)}")
        if self.state.architecture.uses_oracles:
            notes.append(f"- Uses oracles: {', '.join(self.state.architecture.oracle_type)}")
        if self.state.architecture.external_protocols:
            notes.append(
                f"- External protocols: {', '.join(self.state.architecture.external_protocols)}"
            )
        return "\n".join(notes) if notes else "Standard architecture"

    # -------------------------------------------------------------------------
    # Tool handlers
    # -------------------------------------------------------------------------

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            return file_path.read_text()
        except Exception as e:
            return f"Error: {e}"

    async def _find_math_functions(self) -> str:
        """Find functions containing mathematical logic in the codebase."""
        results = []
        extensions = self._get_file_extensions()

        # Patterns that indicate mathematical logic worth verifying
        math_patterns = self._get_math_patterns()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    rel_path = str(file_path.relative_to(self.state.target_path))

                    for pattern_name, pattern in math_patterns.items():
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches[:5]:
                            line_num = content[: match.start()].count("\n") + 1

                            # Try to extract the enclosing function name
                            func_name = self._extract_enclosing_function(
                                content, match.start()
                            )

                            # Get a few lines of context around the match
                            start = max(0, match.start() - 40)
                            end = min(len(content), match.end() + 60)
                            snippet = content[start:end].replace("\n", " ").strip()

                            results.append(
                                {
                                    "file": rel_path,
                                    "line": line_num,
                                    "type": pattern_name,
                                    "function": func_name or "unknown",
                                    "snippet": snippet[:120],
                                }
                            )
                except Exception:
                    continue

        if not results:
            return "No mathematical functions found in codebase."

        # Deduplicate by (file, function) keeping first occurrence
        seen = set()
        unique_results = []
        for r in results:
            key = (r["file"], r["function"], r["type"])
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        output = "Mathematical Functions Found:\n\n"
        for r in unique_results[:40]:
            output += (
                f"[{r['type']}] {r['file']}:{r['line']} "
                f"in {r['function']}()\n"
                f"  {r['snippet']}\n\n"
            )

        return output

    async def _extract_formula(self, file_path: str, function_name: str) -> str:
        """Extract the mathematical formula from a specific function."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        # Find the function in the source
        func_source = self._get_function_source(content, function_name)
        if not func_source:
            return f"Function '{function_name}' not found in {file_path}."

        # Extract mathematical expressions from the function body
        expressions = self._extract_math_expressions(func_source)

        if not expressions:
            return (
                f"No mathematical expressions found in {function_name}.\n\n"
                f"Function source:\n```\n{func_source[:500]}\n```"
            )

        output = f"Formulas extracted from {function_name}():\n\n"
        output += f"### Function Source\n```\n{func_source[:800]}\n```\n\n"
        output += "### Mathematical Expressions\n\n"

        for i, expr in enumerate(expressions, 1):
            output += f"{i}. `{expr['raw']}`\n"
            if expr.get("lhs"):
                output += f"   Assignment: {expr['lhs']} = {expr['rhs']}\n"
            output += "\n"

        return output

    async def _verify_formula_algebraically(
        self, formula: str, context: str = ""
    ) -> str:
        """Perform algebraic verification of a formula using the LLM."""
        return await self._verify_formula(formula, context)

    async def _verify_formula(self, formula: str, context: str = "") -> str:
        """
        Use the LLM with extended thinking to perform deep algebraic verification
        of a smart contract formula.
        """
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        prompt = f"""Perform algebraic verification of this smart contract formula.

Formula: {formula}
Context: {context}

Analyze step by step:
1. Simplify the expression algebraically. Show each step.
2. Check: does any input variable cancel out? If a variable appears in both positive and negative form, it may cancel. This is a TAUTOLOGY - the formula doesn't actually depend on that input.
3. Check: can the expression simplify to a trivial form? For TWAP, if it simplifies to just the spot price, the "time-weighting" is fake.
4. Check boundary cases: what happens at t=0, t=max, negative values?
5. For TWAP/cumulative formulas: does it ACTUALLY compute a time-weighted average? A real TWAP should not be equivalent to the instantaneous price.
6. Check for overflow/underflow potential with uint256 arithmetic.
7. Check for precision loss: is there division before multiplication? Integer division truncation?
8. Check rounding direction: does truncation favor the protocol or the user? Is this intentional?

BE PRECISE. Show the algebra. If you find a bug, explain exactly why the formula is wrong and what the correct formula should be.

Format your response as:

## Algebraic Simplification
[Show step-by-step simplification]

## Tautology Check
[Does any variable cancel out?]

## Boundary Analysis
[What happens at edge cases?]

## Precision Analysis
[Division truncation, overflow risks]

## Verdict
[SAFE / BUG FOUND / NEEDS REVIEW]
[If bug: explain what's wrong and the correct formula]"""

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=(
                "You are a mathematician specializing in algebraic verification of "
                "DeFi smart contract formulas. You are meticulous and always show "
                "your work. You never claim a formula is wrong without proving it "
                "algebraically, and you never claim a formula is safe without "
                "verifying each simplification step."
            ),
            extended_thinking=True,
            thinking_budget=16000,
            max_tokens=4096,
        )
        return response.content

    async def _check_precision_loss(self, file_path: str) -> str:
        """Check for precision loss patterns in a file."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        issues = []

        if self.language == Language.SOLIDITY:
            issues.extend(self._check_solidity_precision(content))
        elif self.language == Language.RUST:
            issues.extend(self._check_rust_precision(content))
        elif self.language == Language.MOVE:
            issues.extend(self._check_move_precision(content))
        elif self.language == Language.CAIRO:
            issues.extend(self._check_cairo_precision(content))

        if not issues:
            return "No precision loss patterns detected."

        output = f"Precision Loss Analysis for {file_path}:\n\n"
        for issue in issues:
            output += f"- [{issue['severity']}] {issue['issue']}\n"
            if issue.get("line"):
                output += f"  Line: ~{issue['line']}\n"
            output += f"  Details: {issue['details']}\n"
            if issue.get("snippet"):
                output += f"  Code: `{issue['snippet']}`\n"
            output += "\n"

        return output

    def _report_finding(self, params: dict) -> str:
        """Report a mathematical verification finding."""
        title = params["title"]
        severity = params["severity"]
        description = params["description"]
        location = params["location"]
        formula = params.get("formula", "")
        simplified = params.get("simplified", "")
        expected = params.get("expected", "")
        impact = params.get("impact", "")
        recommendation = params.get("recommendation", "")
        vulnerability_type = params.get("vulnerability_type", "")

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        vuln_type_map = {
            "precision_loss": VulnerabilityType.PRECISION_LOSS,
            "rounding_error": VulnerabilityType.ROUNDING_ERROR,
            "integer_overflow": VulnerabilityType.INTEGER_OVERFLOW,
            "integer_underflow": VulnerabilityType.INTEGER_UNDERFLOW,
            "oracle_manipulation": VulnerabilityType.ORACLE_MANIPULATION,
            "invariant_violation": VulnerabilityType.INVARIANT_VIOLATION,
            "incorrect_accounting": VulnerabilityType.INCORRECT_ACCOUNTING,
            "business_logic": VulnerabilityType.BUSINESS_LOGIC,
        }
        vuln = vuln_type_map.get(vulnerability_type, VulnerabilityType.ARITHMETIC)

        # Build detailed description with formula analysis
        full_description = description
        if formula:
            full_description += f"\n\n**Formula:**\n```\n{formula}\n```"
        if simplified:
            full_description += f"\n\n**Simplifies to:**\n```\n{simplified}\n```"
        if expected:
            full_description += f"\n\n**Expected behavior:**\n{expected}"

        finding = Finding(
            id=f"MATH-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            vulnerability_type=vuln,
            description=full_description,
            contract=location,
            impact=impact,
            recommendation=recommendation,
            confidence=0.90,
            found_by=AgentRole.VULNERABILITY_HUNTER,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity}] {title}"

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _get_math_patterns(self) -> dict[str, str]:
        """Get patterns that indicate mathematical logic worth verifying."""
        # Common patterns across all languages
        common = {
            "cumulative_price": (
                r"cumulative\s*[Pp]rice|price\s*[Cc]umulative|"
                r"price\s*[Aa]ccumulator|cumulativeLast"
            ),
            "twap": (
                r"twap|TWAP|time\s*[Ww]eighted|timeWeighted|"
                r"[Oo]bserve|getAveragePrice|averagePrice"
            ),
            "fee_calc": (
                r"fee\s*[=*]|feeRate|feeBps|FEE_DENOMINATOR|"
                r"fee\s*=\s*\w+\s*[*/]|protocolFee|swapFee"
            ),
            "interest_rate": (
                r"compound\s*[Ii]nterest|accrueInterest|accrue\s*\(|"
                r"getRatePerBlock|ratePerSecond|borrowRate|supplyRate|"
                r"interestRate|calculateInterest"
            ),
            "amm_math": (
                r"getAmountOut|getAmountIn|calculateSwap|swapExact|"
                r"invariant|constant\s*[Pp]roduct|x\s*\*\s*y\s*=|"
                r"reserveIn\s*\*|reserveOut\s*\*"
            ),
            "share_calc": (
                r"totalShares|totalAssets|previewDeposit|previewMint|"
                r"previewWithdraw|previewRedeem|convertToShares|"
                r"convertToAssets|pricePerShare"
            ),
            "reward_math": (
                r"rewardPerToken|rewardRate|earned\(|"
                r"accRewardPerShare|pendingReward"
            ),
        }

        if self.language == Language.SOLIDITY:
            common.update(
                {
                    "mul_div": r"mulDiv|FullMath|PRBMath|wadMul|wadDiv|rayMul|rayDiv",
                    "power": r"rpow|pow\(|exp\(|sqrt\(",
                    "fixed_point": r"1e18|1e27|WAD|RAY|PRECISION|SCALE_FACTOR",
                }
            )
        elif self.language == Language.RUST:
            common.update(
                {
                    "checked_math": (
                        r"checked_mul|checked_div|checked_add|checked_sub|"
                        r"saturating_mul|saturating_div"
                    ),
                    "spl_math": r"Decimal|Rate|U128|try_mul|try_div",
                }
            )
        elif self.language == Language.MOVE:
            common.update(
                {
                    "math_lib": r"math::|fixed_point|FixedPoint",
                    "safe_math": r"safe_mul|safe_div|checked_",
                }
            )
        elif self.language == Language.CAIRO:
            common.update(
                {
                    "felt_math": r"felt252\s*[*/]|u256\s*[*/]",
                    "wad_ray": r"wad_mul|wad_div|ray_mul|ray_div|WAD|RAY",
                }
            )

        return common

    def _extract_enclosing_function(self, content: str, position: int) -> Optional[str]:
        """Extract the name of the function that encloses a given position."""
        # Look backward from position to find the function declaration
        text_before = content[:position]

        if self.language == Language.SOLIDITY:
            # Match Solidity function declarations
            pattern = r"function\s+(\w+)\s*\("
        elif self.language == Language.RUST:
            pattern = r"(?:pub\s+)?fn\s+(\w+)\s*[<(]"
        elif self.language == Language.MOVE:
            pattern = r"(?:public\s+)?(?:entry\s+)?fun\s+(\w+)\s*[<(]"
        elif self.language == Language.CAIRO:
            pattern = r"fn\s+(\w+)\s*\("
        else:
            pattern = r"function\s+(\w+)\s*\("

        matches = list(re.finditer(pattern, text_before))
        if matches:
            return matches[-1].group(1)
        return None

    def _get_function_source(self, content: str, function_name: str) -> Optional[str]:
        """Extract the full source of a function from file content."""
        if self.language == Language.SOLIDITY:
            pattern = rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{"
        elif self.language == Language.RUST:
            pattern = rf"(?:pub\s+)?fn\s+{re.escape(function_name)}\s*[<(][^{{]*\{{"
        elif self.language == Language.MOVE:
            pattern = (
                rf"(?:public\s+)?(?:entry\s+)?fun\s+{re.escape(function_name)}"
                r"\s*[<(][^{]*\{"
            )
        elif self.language == Language.CAIRO:
            pattern = rf"fn\s+{re.escape(function_name)}\s*\([^{{]*\{{"
        else:
            pattern = rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{"

        match = re.search(pattern, content, re.DOTALL)
        if not match:
            return None

        # Find the matching closing brace
        brace_start = match.end() - 1  # Position of the opening brace
        brace_count = 1
        pos = brace_start + 1

        while pos < len(content) and brace_count > 0:
            if content[pos] == "{":
                brace_count += 1
            elif content[pos] == "}":
                brace_count -= 1
            pos += 1

        if brace_count == 0:
            return content[match.start() : pos]

        # If we can't find the closing brace, return what we have
        return content[match.start() : min(match.start() + 1000, len(content))]

    def _extract_math_expressions(self, func_source: str) -> list[dict]:
        """Extract mathematical expressions from function source code."""
        expressions = []

        # Pattern for assignments with arithmetic operations
        # Matches: variable = expr with *, /, +, - operations
        assignment_pattern = (
            r"(?:uint\d*|int\d*|let\s+(?:mut\s+)?)\s*(\w+)\s*=\s*([^;]+[*/+-][^;]+);"
        )

        for match in re.finditer(assignment_pattern, func_source):
            lhs = match.group(1)
            rhs = match.group(2).strip()
            expressions.append(
                {
                    "raw": f"{lhs} = {rhs}",
                    "lhs": lhs,
                    "rhs": rhs,
                }
            )

        # Also catch return statements with math
        return_pattern = r"return\s+([^;]+[*/+-][^;]+);"
        for match in re.finditer(return_pattern, func_source):
            expr = match.group(1).strip()
            expressions.append(
                {
                    "raw": f"return {expr}",
                    "lhs": None,
                    "rhs": expr,
                }
            )

        # Catch expressions using library functions (mulDiv, wadMul, etc.)
        lib_pattern = r"(\w+)\s*=\s*(\w+\.(?:mul|div|mulDiv|wadMul|wadDiv|rayMul|rayDiv)\([^)]+\))"
        for match in re.finditer(lib_pattern, func_source):
            lhs = match.group(1)
            rhs = match.group(2)
            expressions.append(
                {
                    "raw": f"{lhs} = {rhs}",
                    "lhs": lhs,
                    "rhs": rhs,
                }
            )

        # Catch accumulator updates (+=, -=, *=)
        accum_pattern = r"(\w+)\s*([+\-*/])=\s*([^;]+);"
        for match in re.finditer(accum_pattern, func_source):
            var = match.group(1)
            op = match.group(2)
            rhs = match.group(3).strip()
            expressions.append(
                {
                    "raw": f"{var} {op}= {rhs}",
                    "lhs": var,
                    "rhs": f"{var} {op} ({rhs})",
                }
            )

        return expressions

    def _check_solidity_precision(self, content: str) -> list[dict]:
        """Check for precision loss in Solidity code."""
        issues = []

        # Pattern 1: Division before multiplication
        # e.g., amount / X * Y  or  (amount / X) * Y
        div_then_mul_pattern = r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)"
        for match in re.finditer(div_then_mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = match.group()
            # Exclude comments
            line_start = content.rfind("\n", 0, match.start())
            line_content = content[line_start : match.end()]
            if "//" in line_content[:line_content.find(match.group())]:
                continue
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Division before multiplication",
                    "line": line_num,
                    "details": (
                        "Integer division truncates. Reorder to multiply before dividing "
                        "to preserve precision."
                    ),
                    "snippet": snippet,
                }
            )

        # Pattern 2: Fee calculation that truncates to zero
        fee_pattern = r"(\w*[Ff]ee\w*)\s*=\s*(\w+)\s*/\s*(\d+)\s*\*\s*(\w+)"
        for match in re.finditer(fee_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            denominator = match.group(3)
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": f"Fee calculation divides by {denominator} before multiplying",
                    "line": line_num,
                    "details": (
                        f"For amounts less than {denominator}, "
                        "the fee will truncate to zero."
                    ),
                    "snippet": match.group(),
                }
            )

        # Pattern 3: Share calculation without rounding check
        share_patterns = [
            r"amount\s*\*\s*totalShares\s*/\s*totalAssets",
            r"shares\s*\*\s*totalAssets\s*/\s*totalShares",
            r"amount\s*\*\s*totalSupply\s*/\s*totalBalance",
        ]
        for pattern in share_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                # Check if there's rounding logic nearby
                context_start = max(0, match.start() - 100)
                context_end = min(len(content), match.end() + 100)
                context = content[context_start:context_end]
                if "round" not in context.lower() and "Math.ceil" not in context:
                    issues.append(
                        {
                            "severity": "MEDIUM",
                            "issue": "Share calculation without explicit rounding direction",
                            "line": line_num,
                            "details": (
                                "Truncation in share math can be exploited. "
                                "Consider rounding up for deposits (shares) and "
                                "rounding down for withdrawals (assets)."
                            ),
                            "snippet": match.group(),
                        }
                    )

        # Pattern 4: Multiplication that could overflow
        mul_pattern = r"(\w+)\s*\*\s*(\w+)\s*\*\s*(\w+)"
        for match in re.finditer(mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            # Only flag if not using SafeMath or unchecked
            line_start = content.rfind("\n", 0, match.start())
            context_start = max(0, match.start() - 200)
            context = content[context_start : match.end()]
            if "unchecked" in context or "SafeMath" in context:
                continue
            issues.append(
                {
                    "severity": "LOW",
                    "issue": "Triple multiplication - check for intermediate overflow",
                    "line": line_num,
                    "details": (
                        "Chained multiplications can overflow uint256 with large values. "
                        "Consider using mulDiv or intermediate uint256 checks."
                    ),
                    "snippet": match.group(),
                }
            )

        # Pattern 5: Hardcoded precision without checking token decimals
        if "1e18" in content and "decimals()" not in content:
            for match in re.finditer(r"1e18|10\s*\*\*\s*18", content):
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "severity": "MEDIUM",
                        "issue": "Hardcoded 1e18 precision without checking token decimals",
                        "line": line_num,
                        "details": (
                            "Not all tokens use 18 decimals. USDC/USDT use 6, "
                            "WBTC uses 8. Hardcoding 1e18 may cause incorrect "
                            "calculations for non-18-decimal tokens."
                        ),
                        "snippet": match.group(),
                    }
                )

        return issues

    def _check_rust_precision(self, content: str) -> list[dict]:
        """Check for precision loss in Rust/Solana code."""
        issues = []

        # Division before multiplication
        div_mul_pattern = r"checked_div\([^)]+\)\?\s*\.\s*checked_mul"
        for match in re.finditer(div_mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Division before multiplication in checked math",
                    "line": line_num,
                    "details": "checked_div truncates. Reorder to checked_mul first.",
                    "snippet": match.group()[:80],
                }
            )

        # u64 multiplication that could overflow
        u64_mul_pattern = r"\((\w+)\s+as\s+u64\)\s*\*"
        for match in re.finditer(u64_mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue": "u64 multiplication - potential overflow",
                    "line": line_num,
                    "details": "Cast to u128 before multiplying to avoid overflow.",
                    "snippet": match.group()[:80],
                }
            )

        # Unchecked arithmetic (no checked_ prefix)
        if "checked_" not in content and ("*" in content or "/" in content):
            arithmetic_pattern = r"(\w+)\s*[*/]\s*(\w+)"
            unchecked_count = 0
            for match in re.finditer(arithmetic_pattern, content):
                # Skip if inside a comment
                line_start = content.rfind("\n", 0, match.start())
                line = content[line_start : match.end()]
                if "//" not in line[:line.find(match.group())]:
                    unchecked_count += 1

            if unchecked_count > 3:
                issues.append(
                    {
                        "severity": "MEDIUM",
                        "issue": f"Found {unchecked_count} unchecked arithmetic operations",
                        "line": 0,
                        "details": (
                            "Consider using checked_mul/checked_div for safety. "
                            "Rust panics on overflow in debug but wraps in release."
                        ),
                        "snippet": "",
                    }
                )

        return issues

    def _check_move_precision(self, content: str) -> list[dict]:
        """Check for precision loss in Move code."""
        issues = []

        # u64 multiplication without u128 intermediate
        u64_mul_pattern = r"(\w+)\s*\*\s*(\w+)\s*/"
        for match in re.finditer(u64_mul_pattern, content):
            # Check if there's a u128 cast
            context_start = max(0, match.start() - 50)
            context = content[context_start : match.end()]
            if "as u128" not in context and "u128" not in context:
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": "Multiplication without u128 intermediate",
                        "line": line_num,
                        "details": "u64 * u64 can overflow. Cast to u128 before multiplying.",
                        "snippet": match.group()[:80],
                    }
                )

        # Division before multiplication
        div_mul_pattern = r"/\s*\w+\s*\)\s*\*|\s*/\s*\w+\s*\*"
        for match in re.finditer(div_mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Division before multiplication in Move",
                    "line": line_num,
                    "details": "Integer division truncates. Reorder operations.",
                    "snippet": match.group()[:80],
                }
            )

        return issues

    def _check_cairo_precision(self, content: str) -> list[dict]:
        """Check for precision loss in Cairo code."""
        issues = []

        # felt252 arithmetic (wraps on overflow!)
        if "felt252" in content:
            felt_arith_pattern = r"felt252.*[*/]|[*/].*felt252"
            for match in re.finditer(felt_arith_pattern, content):
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": "Arithmetic on felt252 type",
                        "line": line_num,
                        "details": (
                            "felt252 wraps on overflow silently. "
                            "Use u256 for financial calculations."
                        ),
                        "snippet": match.group()[:80],
                    }
                )

        # Division before multiplication
        div_mul_pattern = r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)"
        for match in re.finditer(div_mul_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Division before multiplication in Cairo",
                    "line": line_num,
                    "details": "Integer division truncates. Reorder to multiply first.",
                    "snippet": match.group()[:80],
                }
            )

        return issues

    def _get_file_extensions(self) -> list[str]:
        """Get file extensions for the current language."""
        extensions = {
            Language.SOLIDITY: [".sol"],
            Language.RUST: [".rs"],
            Language.MOVE: [".move"],
            Language.CAIRO: [".cairo"],
        }
        return extensions.get(self.language, [".sol"])
