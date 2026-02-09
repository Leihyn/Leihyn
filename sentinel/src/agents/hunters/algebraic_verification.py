"""
Algebraic Verification Hunter - Detects mathematical tautologies and logic bugs.

Detects:
- TWAP calculations that reduce to spot price (tautology)
- Validation functions that always return true/false regardless of input
- Price derivation formulas that cancel out
- Invariant checks that are algebraically vacuous
- Division-then-multiplication precision loss that negates checks

This hunter catches bugs that pattern-based hunters miss. It feeds mathematical
operations to the LLM and asks for algebraic simplification. If a "check" simplifies
to a constant (true, false, 0, input), the check is broken.

Supports: Solidity, Rust/Solana, Move, Cairo
"""

import re
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are a mathematician and formal verification expert specializing in smart contract
security. Your unique skill is algebraic simplification of on-chain computations.

Most security auditors look for patterns (amountOutMin=0, reentrancy, access control).
You look at the MATH. You simplify expressions, cancel terms, and prove whether a
computation actually does what the developer intended.

## What You're Looking For

### 1. Tautological Checks
A "check" that always passes because the math cancels out:

```solidity
// Developer THINKS this is TWAP vs spot comparison:
uint256 cumulative = cumulativeLast + (spotPrice * elapsed);
uint256 twap = (cumulative - cumulativeLast) / elapsed;
uint256 deviation = abs(spotPrice - twap);
require(deviation <= maxSlippage);  // ALWAYS PASSES: twap == spotPrice

// Algebraically: twap = (cumulativeLast + spotPrice*elapsed - cumulativeLast) / elapsed
//                     = spotPrice*elapsed / elapsed
//                     = spotPrice
// Therefore deviation = |spotPrice - spotPrice| = 0
```

### 2. Identity Functions Disguised as Validation
Functions that return their input (or a constant) regardless of state:

```solidity
function validatePrice(uint256 slippage) returns (bool) {
    uint256 price = getPrice();
    uint256 avg = computeAverage();  // But avg always equals price!
    return abs(price - avg) <= slippage;  // Always true when avg == price
}
```

### 3. Precision Loss That Negates Checks
Division-then-multiplication that truncates the meaningful part:

```solidity
// Intended: check if value changed by more than 1%
uint256 change = (newValue - oldValue) * 100 / oldValue;
require(change <= 1);
// Problem: if oldValue > 100 * (newValue - oldValue), change truncates to 0
// The check passes even for significant changes
```

### 4. Self-Referential Computations
Functions that compare a value against itself through an indirect path:

```solidity
uint256 expected = oracle.getPrice() * amount / 1e18;
uint256 actual = pool.getAmountOut(amount);  // Uses same price source
require(actual >= expected * 99 / 100);  // Comparing oracle to itself
```

## Analysis Method

For each candidate function:
1. Extract the mathematical operations
2. Substitute and simplify algebraically
3. Determine if the result is a tautology, identity, or constant
4. If so, explain what the developer intended vs what actually happens
5. Assess the security impact (what defense layer is negated)

## Severity Rating

- CRITICAL: A security check (price validation, slippage check) is algebraically vacuous
- HIGH: A calculation used for access control or fund distribution simplifies incorrectly
- MEDIUM: A non-critical invariant or sanity check is a tautology
- LOW: Precision loss that could affect rounding but not security"""


class AlgebraicVerificationHunter(AnalysisAgent):
    """
    Hunts for mathematical tautologies, identity functions, and algebraic bugs
    that negate security checks.
    """

    role = "hunter"
    name = "algebraic_verification_hunter"
    description = "Specialized agent for finding algebraic tautologies and math logic bugs"

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
                description="Find functions that perform mathematical computations, price calculations, TWAP, averages, or validation checks",
                input_schema={"type": "object", "properties": {}},
                handler=self._find_math_functions,
            ),
            Tool(
                name="simplify_and_verify",
                description="Extract and simplify the algebraic operations in a specific function to check for tautologies",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file containing the function",
                        },
                        "function_name": {
                            "type": "string",
                            "description": "Name of the function to analyze",
                        },
                    },
                    "required": ["file_path", "function_name"],
                },
                handler=self._simplify_and_verify,
            ),
            Tool(
                name="report_finding",
                description="Report an algebraic/mathematical vulnerability",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "contract": {"type": "string"},
                        "function": {"type": "string"},
                        "description": {"type": "string"},
                        "algebraic_proof": {
                            "type": "string",
                            "description": "Step-by-step algebraic simplification proving the bug",
                        },
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                    },
                    "required": ["title", "severity", "contract", "description", "algebraic_proof"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run algebraic verification analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        contracts_info = self._format_contracts_info()

        initial_prompt = f"""Analyze this {self.language.value} codebase for algebraic and mathematical logic bugs.

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture
{self._format_architecture()}

Your analysis should:
1. Use find_math_functions to identify all functions that perform price calculations,
   TWAP computations, validation checks, or mathematical derivations
2. For each candidate, use simplify_and_verify to extract the math and check for tautologies
3. Read specific files for deeper manual analysis when needed
4. Report all findings with report_finding, including the algebraic_proof

Focus on:
- Price oracle calculations (TWAP, VWAP, moving averages) - do they actually compute
  an average, or do terms cancel out?
- Validation functions (validatePrice, checkSlippage, verifyInvariant) - can they
  ever return false, or is the math structured so they always pass?
- Interest rate computations - do they correctly accumulate, or does precision loss
  make them ineffective?
- Comparison checks where both sides derive from the same source through different paths
- Any function where the output provably equals the input regardless of state
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(f"  Algebraic Verification Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _format_contracts_info(self) -> str:
        """Format contract info for prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:15]:
            lines.append(f"- {contract.name}")
            if hasattr(contract, "functions"):
                for func in getattr(contract, "functions", [])[:5]:
                    if hasattr(func, "name"):
                        lines.append(f"  - {func.name}()")
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture info."""
        if not self.state.architecture:
            return "No architecture analysis."

        notes = []
        if self.state.architecture.is_defi:
            notes.append("- DeFi protocol detected")
        if self.state.architecture.external_protocols:
            notes.append(
                f"- External protocols: {', '.join(self.state.architecture.external_protocols)}"
            )
        return "\n".join(notes) if notes else "Standard architecture"

    # Tool handlers

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
        """Find functions with mathematical computations that might be tautological."""
        patterns = self._get_math_patterns()
        results = []
        extensions = self._get_file_extensions()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    rel_path = str(file_path.relative_to(self.state.target_path))

                    for pattern_name, pattern in patterns.items():
                        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                        for match in matches[:5]:
                            line_num = content[: match.start()].count("\n") + 1
                            # Get surrounding context (function body)
                            context_start = max(0, match.start() - 50)
                            context_end = min(len(content), match.end() + 200)
                            context = content[context_start:context_end].strip()

                            results.append({
                                "file": rel_path,
                                "line": line_num,
                                "type": pattern_name,
                                "match": context[:200],
                            })
                except Exception:
                    continue

        if not results:
            return "No mathematical computation functions found."

        output = "Mathematical Computation Functions Found:\n\n"
        for r in results[:30]:
            output += f"[{r['type']}] {r['file']}:{r['line']}\n  {r['match']}\n\n"

        return output

    async def _simplify_and_verify(self, file_path: str, function_name: str) -> str:
        """Extract a function's math and prepare it for algebraic analysis."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        # Find the function in the file
        func_body = self._extract_function(content, function_name)
        if not func_body:
            return f"Function '{function_name}' not found in {file_path}"

        # Extract mathematical operations
        math_ops = self._extract_math_operations(func_body)

        output = f"Function: {function_name}\n"
        output += f"File: {file_path}\n\n"
        output += f"Function Body:\n```\n{func_body}\n```\n\n"
        output += f"Mathematical Operations Extracted:\n"
        for i, op in enumerate(math_ops, 1):
            output += f"  {i}. {op}\n"

        output += "\nNow simplify these operations algebraically. Check if:\n"
        output += "- Any comparison always evaluates to the same result (tautology)\n"
        output += "- Any computed value always equals its input (identity)\n"
        output += "- Any terms cancel out making a check vacuous\n"
        output += "- Any precision loss makes a threshold check ineffective\n"

        return output

    def _extract_function(self, content: str, function_name: str) -> Optional[str]:
        """Extract a function body from source code."""
        if self.language == Language.SOLIDITY:
            pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{'
        elif self.language == Language.RUST:
            pattern = rf'(?:pub\s+)?fn\s+{re.escape(function_name)}\s*[<(]'
        elif self.language == Language.MOVE:
            pattern = rf'(?:public\s+)?(?:entry\s+)?fun\s+{re.escape(function_name)}\s*[<(]'
        elif self.language == Language.CAIRO:
            pattern = rf'fn\s+{re.escape(function_name)}\s*\('
        else:
            pattern = rf'function\s+{re.escape(function_name)}\s*\('

        match = re.search(pattern, content, re.IGNORECASE)
        if not match:
            return None

        # Extract function body by counting braces
        start = match.start()
        brace_count = 0
        in_body = False
        end = start

        for i in range(start, len(content)):
            if content[i] == '{':
                brace_count += 1
                in_body = True
            elif content[i] == '}':
                brace_count -= 1
                if in_body and brace_count == 0:
                    end = i + 1
                    break

        return content[start:end]

    def _extract_math_operations(self, func_body: str) -> list[str]:
        """Extract mathematical operations from a function body."""
        operations = []

        # Variable assignments with arithmetic
        assign_pattern = r'(\w+)\s*=\s*([^;]+[+\-*/][^;]+);'
        for match in re.finditer(assign_pattern, func_body):
            operations.append(f"{match.group(1)} = {match.group(2).strip()}")

        # Return statements with arithmetic
        return_pattern = r'return\s+([^;]+[+\-*/][^;]+);'
        for match in re.finditer(return_pattern, func_body):
            operations.append(f"return {match.group(1).strip()}")

        # Require/assert with comparisons
        require_pattern = r'(?:require|assert)\s*\(([^)]+)\)'
        for match in re.finditer(require_pattern, func_body):
            operations.append(f"check: {match.group(1).strip()}")

        # If conditions with arithmetic comparisons
        if_pattern = r'if\s*\(([^)]*[<>=!]+[^)]*)\)'
        for match in re.finditer(if_pattern, func_body):
            operations.append(f"condition: {match.group(1).strip()}")

        return operations

    def _report_finding(self, params: dict) -> str:
        """Report an algebraic vulnerability."""
        title = params["title"]
        severity = params["severity"]
        contract = params["contract"]
        description = params["description"]
        algebraic_proof = params.get("algebraic_proof", "")
        function = params.get("function", "")
        impact = params.get("impact", "")
        recommendation = params.get("recommendation", "")
        confidence = params.get("confidence", 0.8)

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        # Build description with algebraic proof
        full_description = description
        if algebraic_proof:
            full_description += f"\n\nAlgebraic Proof:\n{algebraic_proof}"

        finding = Finding(
            id=f"ALGEBRAIC-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            vulnerability_type=VulnerabilityType.ORACLE_MANIPULATION,
            description=full_description,
            contract=contract,
            function=function if function else None,
            impact=impact,
            recommendation=recommendation,
            found_by=AgentRole.VULNERABILITY_HUNTER,
            confidence=confidence,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity}] {title}"

    def _get_math_patterns(self) -> dict[str, str]:
        """Get patterns for mathematical computation functions."""
        if self.language == Language.SOLIDITY:
            return {
                "price_calculation": r"function\s+\w*(?:[Pp]rice|[Tt]wap|[Aa]verage|[Oo]racle)\w*\s*\(",
                "validation_check": r"function\s+\w*(?:[Vv]alidate|[Vv]erify|[Cc]heck)\w*\s*\(",
                "cumulative_math": r"cumulative\w*\s*[=+\-]",
                "time_weighted": r"(?:time|elapsed|block\.timestamp)\s*[*/]",
                "deviation_check": r"(?:deviation|derivation|diff|delta)\s*[=<>]",
                "invariant": r"(?:invariant|ratio|balance)\s*[=<>!]+",
                "slippage_calc": r"(?:slippage|minAmount|maxSlippage)\s*[=*/]",
            }
        elif self.language == Language.RUST:
            return {
                "price_calculation": r"(?:pub\s+)?fn\s+\w*(?:price|twap|average|oracle)\w*\s*[<(]",
                "validation_check": r"(?:pub\s+)?fn\s+\w*(?:validate|verify|check)\w*\s*[<(]",
                "math_operation": r"(?:checked_mul|checked_div|checked_add|checked_sub)\s*\(",
            }
        elif self.language == Language.MOVE:
            return {
                "price_calculation": r"(?:public\s+)?fun\s+\w*(?:price|twap|average)\w*\s*[<(]",
                "validation_check": r"(?:public\s+)?fun\s+\w*(?:validate|verify|check)\w*\s*[<(]",
            }
        elif self.language == Language.CAIRO:
            return {
                "price_calculation": r"fn\s+\w*(?:price|twap|average|oracle)\w*\s*\(",
                "validation_check": r"fn\s+\w*(?:validate|verify|check)\w*\s*\(",
            }
        return {}

    def _get_file_extensions(self) -> list[str]:
        """Get file extensions for current language."""
        extensions = {
            Language.SOLIDITY: [".sol"],
            Language.RUST: [".rs"],
            Language.MOVE: [".move"],
            Language.CAIRO: [".cairo"],
        }
        return extensions.get(self.language, [".sol"])
