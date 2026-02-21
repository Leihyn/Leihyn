"""
Parameter Validation Hunter Agent - Inconsistent bounds checking detection.

Detects:
- Inconsistent validation between initialize() and setter functions
- Missing bounds checks on critical parameters
- Parameters that can be set to dangerous values (0, type(uint256).max)
- Setter functions without the same validation as constructors/initializers
- State variables writable from multiple paths with different constraints

Real-world example (Olas tokenomics):
    initialize() checks `if (maxSlippage > MAX_BPS) revert Overflow(maxSlippage, MAX_BPS);`
    changeMaxSlippage() has NO such check -- allowing values > 10_000 BPS.

Supports: Solidity (primary), Rust/Solana, Move, Cairo
"""

import re
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite smart contract security researcher specializing in parameter
validation inconsistencies between initialize()/constructor and their setter functions.

Your mental model: every state variable written in initialize() AND also by a setter
(set*, change*, update*) is a suspect. Validation constraints in one write path MUST
be present in ALL write paths.
Consult the vulnerability cheatsheet below for known patterns, and use the
`get_vulnerability_reference` tool with category="parameter_validation" for detailed
detection heuristics, high-signal parameter types, and false-positive conditions.

## Analysis Approach
1. Use find_setter_functions to enumerate all setters, initializers, and constructors
2. Use extract_validation_checks to see constraints per function
3. Use compare_validation_consistency to automatically flag mismatches
4. Read source to confirm flagged issues
5. Focus on: fee rates, slippage limits, addresses, multipliers, timelock durations

## Reporting
- Identify the specific missing check and which function lacks it
- Rate: CRITICAL (fund loss), HIGH (protocol malfunction), MEDIUM (privileged + limited), LOW (minor)
- Only report findings you are confident about. Avoid false positives."""


class ParameterValidationHunter(AnalysisAgent):
    """
    Hunts for inconsistent parameter validation between initialize/constructor
    and setter functions.

    The core insight: if initialize() validates a parameter, every subsequent
    setter for that same state variable must enforce identical (or stricter)
    constraints. When they don't, it's a bug.
    """

    role = "hunter"
    name = "parameter_validation_hunter"
    description = "Specialized agent for finding inconsistent parameter validation"

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
                        "path": {
                            "type": "string",
                            "description": "File path to read",
                        }
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="find_setter_functions",
                description=(
                    "Find all setter/change/update functions and initializers across "
                    "the codebase. Returns file path, line number, function name, and "
                    "what state variables each function writes to."
                ),
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=self._find_setter_functions,
            ),
            Tool(
                name="extract_validation_checks",
                description=(
                    "Given a file path, extract all require/if-revert/assert "
                    "validation constraints organized by function. Returns a "
                    "structured view like:\n"
                    "  initialize(): maxSlippage > MAX_BPS -> revert, "
                    "maxSlippage != 0 -> revert\n"
                    "  changeMaxSlippage(): (no checks)"
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        }
                    },
                    "required": ["file_path"],
                },
                handler=self._extract_validation_checks,
            ),
            Tool(
                name="compare_validation_consistency",
                description=(
                    "Given a file path, compare validation constraints across all "
                    "functions that write to the same state variable. Flags when:\n"
                    "- initialize() has bounds checks but setter doesn't\n"
                    "- Constructor validates but update function doesn't\n"
                    "- Different setters for same variable have different constraints\n"
                    "- A parameter can be set to 0 via setter but not via initialize"
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        }
                    },
                    "required": ["file_path"],
                },
                handler=self._compare_validation_consistency,
            ),
            Tool(
                name="report_finding",
                description="Report a parameter validation vulnerability",
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
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "missing_check": {
                            "type": "string",
                            "description": (
                                "The specific validation that is missing, "
                                "e.g. 'maxSlippage > MAX_BPS'"
                            ),
                        },
                        "vuln_category": {
                            "type": "string",
                            "enum": ["missing_bounds", "access_control", "business_logic"],
                            "description": "Sub-category of the vulnerability",
                        },
                    },
                    "required": ["title", "severity", "description", "location"],
                },
                handler=self._report_finding,
            ),
        ]

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> list[Finding]:
        """Run parameter validation consistency analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        # Build context
        contracts_info = self._format_contracts_info()

        initial_prompt = f"""Analyze this {self.language.value} codebase for inconsistent parameter validation.

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture
{self._format_architecture()}

## Instructions

Your job is to find state variables that are written by BOTH an initializer/constructor
AND a dedicated setter function, then verify that the validation constraints are
consistent across all write paths.

Follow this procedure:
1. Use `find_setter_functions` to enumerate all setters, initializers, and constructors.
2. For each file that contains setters, use `extract_validation_checks` to see the
   constraints per function.
3. Use `compare_validation_consistency` to automatically flag mismatches.
4. Read the source with `read_file` for any flagged files to confirm the issue.
5. Report confirmed findings with `report_finding`.

Pay special attention to:
- Parameters used in arithmetic (fees, slippage, rates, multipliers)
- Address parameters that should never be zero
- Array length / count parameters that could cause DoS
- Threshold values used in comparisons

This is a HIGH-SIGNAL hunt. The pattern of "initialize validates, setter doesn't"
is responsible for real production exploits (Olas tokenomics, Compound parameter
misconfiguration, etc.). Be thorough.
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(
                f"  Parameter Validation Hunter completed: "
                f"{len(self.findings)} findings"
            )

        return self.findings

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            return file_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

    async def _find_setter_functions(self) -> str:
        """
        Find all setter/change/update functions and initializers across the
        codebase. Scans .sol files for function signatures that match common
        setter naming conventions and identifies which state variables they
        write to.
        """
        results = []
        extensions = self._get_file_extensions()

        # Patterns that identify setter-like functions
        patterns = [
            (r"function\s+(set\w+)\s*\(", "setter"),
            (r"function\s+(change\w+)\s*\(", "setter"),
            (r"function\s+(update\w+)\s*\(", "setter"),
            (r"function\s+(initialize)\s*\(", "initializer"),
            (r"constructor\s*\(", "constructor"),
        ]

        # State-write pattern: identifies `variableName = value` or
        # `variableName[key] = value` inside function bodies
        state_write_pattern = re.compile(
            r"(\w+)\s*(?:\[[^\]]*\])?\s*=\s*[^=]", re.MULTILINE
        )

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    rel_path = str(
                        file_path.relative_to(self.state.target_path)
                    )

                    for pattern, func_type in patterns:
                        for match in re.finditer(pattern, content):
                            func_name = (
                                match.group(1)
                                if match.lastindex and match.lastindex >= 1
                                else "constructor"
                            )
                            line_num = (
                                content[: match.start()].count("\n") + 1
                            )

                            # Extract function body to find state writes
                            brace_start = content.find("{", match.start())
                            if brace_start == -1:
                                continue
                            brace_end = self._find_matching_brace(
                                content, brace_start
                            )
                            if brace_end == -1:
                                continue
                            func_body = content[brace_start:brace_end]

                            # Find state writes inside the function body
                            writes = set()
                            for write_match in state_write_pattern.finditer(
                                func_body
                            ):
                                var_name = write_match.group(1).strip()
                                # Filter out local variable declarations
                                # and common non-state identifiers
                                if var_name in (
                                    "bool",
                                    "uint256",
                                    "uint128",
                                    "uint64",
                                    "uint32",
                                    "uint8",
                                    "int256",
                                    "address",
                                    "bytes32",
                                    "string",
                                    "memory",
                                    "storage",
                                    "calldata",
                                    "returns",
                                    "return",
                                    "if",
                                    "for",
                                    "while",
                                ):
                                    continue
                                writes.add(var_name)

                            writes_str = (
                                ", ".join(sorted(writes))
                                if writes
                                else "(could not determine)"
                            )

                            results.append(
                                {
                                    "file": rel_path,
                                    "line": line_num,
                                    "function": func_name,
                                    "type": func_type,
                                    "writes_to": writes_str,
                                }
                            )
                except Exception:
                    continue

        if not results:
            return "No setter functions or initializers found in the codebase."

        output = "Setter Functions and Initializers Found:\n\n"
        for r in results[:50]:
            output += (
                f"[{r['type']}] {r['file']}:{r['line']}  "
                f"{r['function']}()\n"
                f"  Writes to: {r['writes_to']}\n\n"
            )

        return output

    async def _extract_validation_checks(self, file_path: str) -> str:
        """
        Extract all require/if-revert/assert validation constraints from every
        setter and initializer function in the given file.

        Returns a structured view mapping function names to their parameter
        constraints.
        """
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

        # Patterns to locate setter-like functions
        func_patterns = [
            r"function\s+(set\w+)\s*\([^)]*\)",
            r"function\s+(change\w+)\s*\([^)]*\)",
            r"function\s+(update\w+)\s*\([^)]*\)",
            r"function\s+(initialize)\s*\([^)]*\)",
            r"(constructor)\s*\([^)]*\)",
        ]

        # Patterns that represent validation checks
        require_pattern = re.compile(
            r"require\s*\(([^;]+?)\)", re.DOTALL
        )
        revert_pattern = re.compile(
            r"if\s*\(([^)]+)\)\s*(?:revert\s+\w+|{\s*revert)", re.DOTALL
        )
        assert_pattern = re.compile(
            r"assert\s*\(([^;]+?)\)", re.DOTALL
        )

        results = {}

        for func_pat in func_patterns:
            for match in re.finditer(func_pat, content):
                func_name = match.group(1)
                # Find function body
                brace_start = content.find("{", match.start())
                if brace_start == -1:
                    continue
                brace_end = self._find_matching_brace(
                    content, brace_start
                )
                if brace_end == -1:
                    continue
                func_body = content[brace_start:brace_end]

                checks = []

                # Extract require() conditions
                for req_match in require_pattern.finditer(func_body):
                    condition = req_match.group(1).strip()
                    # Clean up multi-line conditions
                    condition = " ".join(condition.split())
                    # Truncate overly long conditions
                    if len(condition) > 200:
                        condition = condition[:200] + "..."
                    checks.append(f"require({condition})")

                # Extract if-revert conditions
                for rev_match in revert_pattern.finditer(func_body):
                    condition = rev_match.group(1).strip()
                    condition = " ".join(condition.split())
                    if len(condition) > 200:
                        condition = condition[:200] + "..."
                    checks.append(f"if ({condition}) revert")

                # Extract assert() conditions
                for assert_match in assert_pattern.finditer(func_body):
                    condition = assert_match.group(1).strip()
                    condition = " ".join(condition.split())
                    if len(condition) > 200:
                        condition = condition[:200] + "..."
                    checks.append(f"assert({condition})")

                results[func_name] = checks

        if not results:
            return (
                f"No setter/initializer functions found in {file_path}."
            )

        output = f"Validation Checks in {file_path}:\n\n"
        for func_name, checks in results.items():
            output += f"  {func_name}():\n"
            if checks:
                for check in checks:
                    output += f"    - {check}\n"
            else:
                output += "    (no validation checks)\n"
            output += "\n"

        return output

    async def _compare_validation_consistency(self, file_path: str) -> str:
        """
        Compare validation constraints across all functions that write to
        the same state variable. Identifies mismatches where one writer
        validates but another does not.
        """
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

        # Step 1: Find all setter/initializer functions and their bodies
        func_patterns = [
            r"function\s+(set\w+)\s*\([^)]*\)",
            r"function\s+(change\w+)\s*\([^)]*\)",
            r"function\s+(update\w+)\s*\([^)]*\)",
            r"function\s+(initialize)\s*\([^)]*\)",
            r"(constructor)\s*\([^)]*\)",
        ]

        state_write_pattern = re.compile(
            r"(\w+)\s*(?:\[[^\]]*\])?\s*=\s*[^=]", re.MULTILINE
        )
        require_pattern = re.compile(
            r"require\s*\(([^;]+?)\)", re.DOTALL
        )
        revert_pattern = re.compile(
            r"if\s*\(([^)]+)\)\s*(?:revert\s+\w+|{\s*revert)", re.DOTALL
        )
        assert_pattern = re.compile(
            r"assert\s*\(([^;]+?)\)", re.DOTALL
        )

        # Common Solidity type keywords to ignore as variable names
        ignore_vars = {
            "bool", "uint256", "uint128", "uint64", "uint32", "uint8",
            "int256", "address", "bytes32", "string", "memory", "storage",
            "calldata", "returns", "return", "if", "for", "while",
        }

        # Map: state_var -> {func_name: [checks_mentioning_var]}
        var_writers: dict[str, dict[str, list[str]]] = {}

        for func_pat in func_patterns:
            for match in re.finditer(func_pat, content):
                func_name = match.group(1)
                brace_start = content.find("{", match.start())
                if brace_start == -1:
                    continue
                brace_end = self._find_matching_brace(
                    content, brace_start
                )
                if brace_end == -1:
                    continue
                func_body = content[brace_start:brace_end]

                # Find which state vars this function writes to
                written_vars = set()
                for write_match in state_write_pattern.finditer(func_body):
                    var_name = write_match.group(1).strip()
                    if var_name in ignore_vars:
                        continue
                    written_vars.add(var_name)

                # Extract all checks in this function
                all_checks = []
                for req in require_pattern.finditer(func_body):
                    all_checks.append(
                        " ".join(req.group(1).strip().split())
                    )
                for rev in revert_pattern.finditer(func_body):
                    all_checks.append(
                        " ".join(rev.group(1).strip().split())
                    )
                for ast in assert_pattern.finditer(func_body):
                    all_checks.append(
                        " ".join(ast.group(1).strip().split())
                    )

                # For each written var, record which checks mention it
                for var in written_vars:
                    if var not in var_writers:
                        var_writers[var] = {}
                    related_checks = [
                        c for c in all_checks if var in c
                    ]
                    var_writers[var][func_name] = related_checks

        # Step 2: Compare and flag inconsistencies
        inconsistencies = []

        for var, writers in var_writers.items():
            # Only interesting if written by 2+ functions
            if len(writers) < 2:
                continue

            # Separate initializers/constructors from setters
            init_funcs = {
                f: checks
                for f, checks in writers.items()
                if f in ("initialize", "constructor")
            }
            setter_funcs = {
                f: checks
                for f, checks in writers.items()
                if f not in ("initialize", "constructor")
            }

            if not init_funcs or not setter_funcs:
                # Still compare setter-to-setter if no initializer
                if len(setter_funcs) >= 2:
                    # Find the setter with the most checks
                    max_checks_func = max(
                        setter_funcs, key=lambda f: len(setter_funcs[f])
                    )
                    max_checks = setter_funcs[max_checks_func]

                    for func, checks in setter_funcs.items():
                        if func == max_checks_func:
                            continue
                        if len(max_checks) > len(checks):
                            inconsistencies.append(
                                {
                                    "variable": var,
                                    "stricter_func": max_checks_func,
                                    "stricter_checks": max_checks,
                                    "weaker_func": func,
                                    "weaker_checks": checks,
                                    "type": "setter_vs_setter",
                                }
                            )
                continue

            # Compare each initializer against each setter
            for init_name, init_checks in init_funcs.items():
                if not init_checks:
                    continue  # Initializer has no checks -- nothing to compare

                for setter_name, setter_checks in setter_funcs.items():
                    # Find checks present in init but missing in setter
                    missing = []
                    for init_check in init_checks:
                        # Fuzzy match: check if any setter check covers
                        # the same constraint
                        found_match = False
                        for setter_check in setter_checks:
                            if self._checks_are_similar(
                                init_check, setter_check, var
                            ):
                                found_match = True
                                break
                        if not found_match:
                            missing.append(init_check)

                    if missing:
                        inconsistencies.append(
                            {
                                "variable": var,
                                "stricter_func": init_name,
                                "stricter_checks": init_checks,
                                "weaker_func": setter_name,
                                "weaker_checks": setter_checks,
                                "missing_checks": missing,
                                "type": "initializer_vs_setter",
                            }
                        )

        if not inconsistencies:
            return (
                f"No validation inconsistencies detected in {file_path}.\n"
                "All setters have consistent checks with their "
                "initializers/constructors."
            )

        output = f"VALIDATION INCONSISTENCIES in {file_path}:\n\n"
        for i, issue in enumerate(inconsistencies, 1):
            output += f"--- Inconsistency #{i} ---\n"
            output += f"State variable: {issue['variable']}\n"
            output += f"Type: {issue['type']}\n"
            output += (
                f"Stricter function: {issue['stricter_func']}() "
                f"with checks:\n"
            )
            for c in issue["stricter_checks"]:
                output += f"  - {c}\n"
            output += (
                f"Weaker function: {issue['weaker_func']}() "
                f"with checks:\n"
            )
            if issue["weaker_checks"]:
                for c in issue["weaker_checks"]:
                    output += f"  - {c}\n"
            else:
                output += "  (NO checks on this variable)\n"

            if "missing_checks" in issue:
                output += "MISSING in weaker function:\n"
                for c in issue["missing_checks"]:
                    output += f"  >> {c}\n"
            output += "\n"

        return output

    def _report_finding(self, params: dict) -> str:
        """Report a parameter validation finding."""
        title = params["title"]
        severity = params["severity"]
        description = params["description"]
        location = params["location"]
        impact = params.get("impact", "")
        recommendation = params.get("recommendation", "")
        missing_check = params.get("missing_check", "")
        vuln_category = params.get("vuln_category", "missing_bounds")

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        # Determine vulnerability type based on sub-category
        if vuln_category == "access_control":
            vuln_type = VulnerabilityType.ACCESS_CONTROL
        else:
            # missing_bounds, business_logic, and default
            vuln_type = VulnerabilityType.BUSINESS_LOGIC

        full_description = description
        if missing_check:
            full_description += (
                f"\n\n**Missing Check:** `{missing_check}`"
            )

        finding = Finding(
            id=f"PARAM-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            vulnerability_type=vuln_type,
            description=full_description,
            contract=location,
            impact=impact,
            recommendation=recommendation,
            confidence=0.85,
            found_by=AgentRole.VULNERABILITY_HUNTER,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity}] {title}"

    # ------------------------------------------------------------------
    # Helper / utility methods
    # ------------------------------------------------------------------

    def _checks_are_similar(
        self, check_a: str, check_b: str, var_name: str
    ) -> bool:
        """
        Determine if two validation check strings express the same
        constraint on the given variable.

        Uses a simplified comparison: strips whitespace, normalises
        comparison operators, and checks for substring containment.
        Not perfect, but good enough for flagging suspects.
        """
        # Normalise whitespace
        a = " ".join(check_a.split()).lower()
        b = " ".join(check_b.split()).lower()

        # Direct substring match (most common case)
        if a in b or b in a:
            return True

        # Check if both reference the same constant/boundary
        # e.g. "maxslippage > max_bps" vs "newslippage > max_bps"
        var_lower = var_name.lower()

        # Extract comparison targets (constants/upper-bounds)
        const_pattern = re.compile(
            r"(?:>|<|>=|<=|==|!=)\s*(\w+)"
        )
        a_constants = set(const_pattern.findall(a))
        b_constants = set(const_pattern.findall(b))

        # If both compare against the same constant and both mention the
        # variable (or its parameter alias), consider them similar
        shared_constants = a_constants & b_constants
        if shared_constants and (var_lower in a or var_lower in b):
            return True

        return False

    def _find_matching_brace(self, content: str, start: int) -> int:
        """Find the matching closing brace for an opening brace."""
        if start < 0 or start >= len(content) or content[start] != "{":
            return -1

        count = 1
        i = start + 1
        while i < len(content) and count > 0:
            if content[i] == "{":
                count += 1
            elif content[i] == "}":
                count -= 1
            i += 1

        return i if count == 0 else -1

    def _format_contracts_info(self) -> str:
        """Format contract information for the prompt."""
        if not self.state.contracts:
            return (
                "No contracts analyzed yet. "
                "Use find_setter_functions first."
            )

        lines = []
        for contract in self.state.contracts[:10]:
            lines.append(f"- {contract.name} ({contract.path})")
            if contract.functions:
                for func in contract.functions[:5]:
                    lines.append(f"  - {func}")
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture notes."""
        if not self.state.architecture:
            return "No architecture analysis available."

        notes = []
        if self.state.architecture.is_upgradeable:
            notes.append("- Upgradeable proxy pattern detected")
        if self.state.architecture.uses_access_control:
            notes.append("- Access control system present")
        if self.state.architecture.notes:
            notes.extend(
                [f"- {note}" for note in self.state.architecture.notes[:5]]
            )

        return "\n".join(notes) if notes else "No specific notes."

    def _get_file_extensions(self) -> list[str]:
        """Get file extensions for current language."""
        extensions = {
            Language.SOLIDITY: [".sol"],
            Language.RUST: [".rs"],
            Language.MOVE: [".move"],
            Language.CAIRO: [".cairo"],
        }
        return extensions.get(self.language, [".sol"])
