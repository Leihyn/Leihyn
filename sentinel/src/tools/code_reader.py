"""
Code reading and Solidity parsing tools.
"""

import re
from pathlib import Path
from typing import Optional

from ..core.types import ContractInfo, FunctionInfo, StateVariable, ExternalCall


def read_solidity_file(path: Path) -> str:
    """Read a Solidity file and return its contents."""
    return path.read_text(encoding="utf-8")


_SKIP_DIR_NAMES = {
    "out",            # Foundry build artifacts (Name.sol/ is a DIR, not a file)
    "cache",          # Foundry cache + Hardhat cache
    "artifacts",      # Hardhat build artifacts
    "node_modules",   # JS deps
    "lib",            # Foundry installed deps
    "x-ray",          # x-ray skill output
    ".git",
    ".forge-snapshots",
    "broadcast",      # Foundry deployment logs
    "coverage",       # coverage reports
    "deployments",    # hardhat-deploy artifacts
    "mocks",          # test mocks (not in audit scope)
    "test",           # test files
    "tests",          # test files (alt naming)
    "others",         # vendored multicall/create3 etc
}


def find_solidity_files(directory: Path, recursive: bool = True) -> list[Path]:
    """Find all Solidity files in a directory.

    Excludes build artifacts, dependency dirs, and skill outputs. Also
    filters out paths matched by the glob that are directories rather
    than files (Foundry's `out/Name.sol/` layout would otherwise be
    treated as parseable .sol entries).
    """
    pattern = "**/*.sol" if recursive else "*.sol"
    results = []
    for p in directory.glob(pattern):
        if not p.is_file():
            continue
        # Drop anything inside a skipped directory (any depth).
        try:
            rel_parts = set(p.relative_to(directory).parts)
        except ValueError:
            rel_parts = set(p.parts)
        if rel_parts & _SKIP_DIR_NAMES:
            continue
        results.append(p)
    return results


def extract_contract_info(source: str, file_path: Path) -> list[ContractInfo]:
    """
    Extract contract information from Solidity source code.

    Uses regex-based parsing (faster than full AST for initial analysis).
    """
    contracts = []

    # Find all contract/interface/library definitions
    contract_pattern = r"(contract|interface|library|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{"
    matches = list(re.finditer(contract_pattern, source))

    for i, match in enumerate(matches):
        contract_type = match.group(1)
        contract_name = match.group(2)
        inheritance = match.group(3)

        # Find contract body (rough - between this { and matching })
        start = match.end()
        end = find_matching_brace(source, match.end() - 1)

        if end == -1:
            continue

        body = source[start:end]

        contract = ContractInfo(
            name=contract_name,
            path=file_path,
            source=source[match.start():end + 1],
        )

        # Parse inheritance
        if inheritance:
            contract.inheritance = [i.strip() for i in inheritance.split(",")]

        # Extract functions
        contract.functions = extract_functions(body)

        # Extract state variables
        contract.state_variables = extract_state_variables(body)

        # Extract modifiers
        contract.modifiers = extract_modifiers(body)

        # Extract imports from full source
        contract.imports = extract_imports(source)

        # Detect patterns
        contract.is_upgradeable = any(
            kw in source for kw in ["Upgradeable", "UUPSUpgradeable", "TransparentUpgradeableProxy"]
        )
        contract.is_proxy = "delegatecall" in body.lower() or "Proxy" in contract_name
        contract.uses_delegatecall = "delegatecall" in body
        contract.has_external_calls = bool(re.search(r"\.\w+\s*\(", body))

        contracts.append(contract)

    return contracts


def find_matching_brace(source: str, start: int) -> int:
    """Find the index of the closing brace matching the one at start."""
    if source[start] != "{":
        return -1

    depth = 1
    i = start + 1

    while i < len(source) and depth > 0:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1

    return i - 1 if depth == 0 else -1


def extract_functions(body: str) -> list[FunctionInfo]:
    """Extract function information from contract body."""
    functions = []

    # Function pattern. Anchored quantifiers are bounded to prevent catastrophic
    # backtracking on large files (TradePairs.sol 1500+ lines) where a long
    # modifier sequence used to hang re.finditer indefinitely. Modifier list is
    # captured greedily but with a 256-char ceiling.
    func_pattern = r"""
        function\s+(\w+)\s*\(([^)]*)\)\s*
        ((?:public|external|internal|private)\s+)?
        ((?:view|pure|payable)\s+)?
        ([^{;()]{0,256})  # modifiers (no braces/semis/parens; bounded)
        (?:returns\s*\(([^)]*)\))?\s*
        (\{|;)
    """

    for match in re.finditer(func_pattern, body, re.VERBOSE):
        name = match.group(1)
        params_str = match.group(2)
        visibility = (match.group(3) or "internal").strip()
        mutability = (match.group(4) or "nonpayable").strip()
        modifiers_str = match.group(5) or ""
        returns_str = match.group(6) or ""

        # Parse parameters
        params = []
        if params_str.strip():
            for param in params_str.split(","):
                param = param.strip()
                if param:
                    parts = param.split()
                    if len(parts) >= 2:
                        params.append({"type": parts[0], "name": parts[-1]})
                    elif len(parts) == 1:
                        params.append({"type": parts[0], "name": ""})

        # Parse returns
        returns = []
        if returns_str.strip():
            for ret in returns_str.split(","):
                ret = ret.strip()
                if ret:
                    parts = ret.split()
                    if parts:
                        returns.append({"type": parts[0], "name": parts[-1] if len(parts) > 1 else ""})

        # Parse modifiers
        modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]

        # Find function body for deeper analysis
        func_body = ""
        line_start = body.count("\n", 0, match.start()) + 1
        line_end = line_start
        if match.group(7) == "{":
            func_start = match.end() - 1
            func_end = find_matching_brace(body, func_start)
            if func_end > func_start:
                func_body = body[func_start:func_end + 1]
                line_end = body.count("\n", 0, func_end + 1) + 1
                external_calls = extract_external_calls(func_body, name)
            else:
                external_calls = []
        else:
            external_calls = []

        # NatSpec extraction: capture comment lines immediately preceding the
        # function signature. Walk back from match.start() over `///` and
        # `/** ... */` blocks. Stop on the first non-comment line.
        doc = _extract_natspec_above(body, match.start())

        functions.append(
            FunctionInfo(
                name=name,
                visibility=visibility,
                mutability=mutability,
                parameters=params,
                returns=returns,
                modifiers=modifiers,
                external_calls=external_calls,
                source_lines=(line_start, line_end),
                line_start=line_start,
                line_end=line_end,
                body=func_body,
                documentation=doc,
            )
        )

    return functions


def _extract_natspec_above(body: str, match_start: int) -> str:
    """Return the NatSpec block (`///` or `/** */`) immediately preceding `match_start`.

    Empty string if there is none. Used to feed the spec_skeptic thinker.
    """
    if match_start <= 0:
        return ""
    # Walk backwards over whitespace lines
    i = match_start
    # skip whitespace before the function
    while i > 0 and body[i - 1] in " \t":
        i -= 1
    if i == 0 or body[i - 1] != "\n":
        # function may start mid-line (rare); look for the line start
        line_start = body.rfind("\n", 0, match_start) + 1
    else:
        line_start = i
    # Now read lines upward until we leave the comment block
    pos = line_start
    lines: list[str] = []
    while pos > 0:
        prev_nl = body.rfind("\n", 0, pos - 1)
        line = body[prev_nl + 1: pos - 1]
        stripped = line.strip()
        if not stripped:
            # blank line inside doc continues; outside breaks
            if lines:
                pos = prev_nl + 1
                continue
            break
        if stripped.startswith("///") or stripped.startswith("*") or stripped.startswith("/**") or stripped.startswith("//"):
            lines.append(stripped)
            pos = prev_nl + 1
            continue
        if stripped.endswith("*/"):
            lines.append(stripped)
            pos = prev_nl + 1
            continue
        break
    if not lines:
        return ""
    return "\n".join(reversed(lines))


def extract_state_variables(body: str) -> list[StateVariable]:
    """Extract state variable information from contract body.

    Strips function/modifier/constructor bodies before scanning so local
    variable declarations like `uint256 expiry = ...;` inside functions are
    not misclassified as state variables. Without this strip, local-name
    pollution downstream (trust_mapper, invariant_inferrer) emits false
    hypotheses on stack temporaries. Verified against
    contracts/src/multiproof/tee/NitroEnclaveVerifier.sol on 2026-05-04.
    """
    stripped = _strip_function_bodies(body)

    # Type slot supports nested mapping declarations like
    # `mapping(K1 => mapping(K2 => V))` up to two nesting levels (covers the
    # bulk of Solidity-in-the-wild without needing a real parser).
    var_pattern = r"""
        ^\s*
        (
            mapping\s*\(
                (?:[^()]|\([^()]*\))*               # one level of nested parens
            \)
          | [\w\[\]]+                                # plain type
        )\s+
        (public|private|internal)?\s*                # visibility
        (constant|immutable|transient)?\s*           # modifiers
        (\w+)\s*                                     # name
        (?:=|;)                                      # assignment or end
    """

    seen: set[str] = set()
    variables: list[StateVariable] = []
    for match in re.finditer(var_pattern, stripped, re.VERBOSE | re.MULTILINE):
        var_type = match.group(1).strip()
        visibility = match.group(2) or "internal"
        modifier = match.group(3)
        name = match.group(4)

        # Skip pseudo-keywords picked up by the type slot.
        if var_type in ("function", "modifier", "constructor", "event", "error", "struct", "enum"):
            continue
        if name in seen:
            continue
        seen.add(name)

        variables.append(
            StateVariable(
                name=name,
                var_type=var_type,
                visibility=visibility,
                is_constant=modifier == "constant",
                is_immutable=modifier == "immutable",
            )
        )

    return variables


def _strip_function_bodies(contract_body: str) -> str:
    """Replace each `function/modifier/constructor ... { ... }` block with
    a same-length whitespace blob so line numbers are preserved but
    local declarations no longer match the state-var regex.
    """
    out_chars = list(contract_body)
    pos = 0
    pat = re.compile(r"\b(function|modifier|constructor)\b")
    while True:
        m = pat.search(contract_body, pos)
        if not m:
            break
        # Find the opening brace after this declaration's signature.
        brace = contract_body.find("{", m.end())
        if brace == -1:
            break
        end = find_matching_brace(contract_body, brace)
        if end == -1 or end <= brace:
            pos = brace + 1
            continue
        # Wipe the body (keep newlines so line counting survives).
        for i in range(brace, end + 1):
            out_chars[i] = "\n" if contract_body[i] == "\n" else " "
        pos = end + 1
    return "".join(out_chars)


def extract_modifiers(body: str) -> list[str]:
    """Extract modifier names from contract body."""
    modifiers = []
    modifier_pattern = r"modifier\s+(\w+)"

    for match in re.finditer(modifier_pattern, body):
        modifiers.append(match.group(1))

    return modifiers


def extract_imports(source: str) -> list[str]:
    """Extract import statements from source."""
    imports = []
    import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']'

    for match in re.finditer(import_pattern, source):
        imports.append(match.group(1))

    return imports


def extract_external_calls(func_body: str, func_name: str) -> list[ExternalCall]:
    """Extract external calls from a function body."""
    calls = []

    # Pattern for external calls: address.function() or contract.function()
    call_pattern = r"(\w+)\.(\w+)\s*(?:\{[^}]*\})?\s*\("

    for match in re.finditer(call_pattern, func_body):
        target = match.group(1)
        function = match.group(2)

        # Skip common internal patterns
        if target in ["abi", "keccak256", "type", "bytes", "string"]:
            continue

        # Check if value is being sent
        value_sent = bool(re.search(rf"{re.escape(target)}\.{re.escape(function)}\s*\{{.*value", func_body))

        calls.append(
            ExternalCall(
                target=target,
                function=function,
                value_sent=value_sent,
                in_function=func_name,
            )
        )

    # Look for low-level calls
    low_level_pattern = r"(\w+)\.(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\("

    for match in re.finditer(low_level_pattern, func_body):
        target = match.group(1)
        call_type = match.group(2)
        value_sent = "value" in func_body[match.start():match.end() + 50]

        calls.append(
            ExternalCall(
                target=target,
                function=call_type,
                value_sent=value_sent,
                in_function=func_name,
            )
        )

    return calls


def get_function_source(contract: ContractInfo, function_name: str) -> Optional[str]:
    """Extract the source code of a specific function."""
    pattern = rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{"

    match = re.search(pattern, contract.source)
    if not match:
        return None

    start = match.end() - 1
    end = find_matching_brace(contract.source, start)

    if end == -1:
        return None

    return contract.source[match.start():end + 1]


def get_call_graph(contracts: list[ContractInfo]) -> dict[str, list[str]]:
    """
    Build a call graph showing which functions call which.

    Returns dict mapping "Contract.function" to list of called functions.
    """
    graph = {}

    for contract in contracts:
        for func in contract.functions:
            key = f"{contract.name}.{func.name}"
            calls = []

            for ext_call in func.external_calls:
                calls.append(f"{ext_call.target}.{ext_call.function}")

            # Also look for internal calls
            func_source = get_function_source(contract, func.name)
            if func_source:
                for other_func in contract.functions:
                    if other_func.name != func.name:
                        if re.search(rf"\b{re.escape(other_func.name)}\s*\(", func_source):
                            calls.append(f"{contract.name}.{other_func.name}")

            graph[key] = calls

    return graph


def summarize_contract(contract: ContractInfo) -> str:
    """Generate a text summary of a contract."""
    lines = [
        f"# Contract: {contract.name}",
        f"Path: {contract.path}",
        "",
    ]

    if contract.inheritance:
        lines.append(f"Inherits: {', '.join(contract.inheritance)}")

    if contract.is_upgradeable:
        lines.append("Pattern: Upgradeable")
    if contract.is_proxy:
        lines.append("Pattern: Proxy")

    lines.append("")
    lines.append("## State Variables")
    for var in contract.state_variables:
        mod = ""
        if var.is_constant:
            mod = " (constant)"
        elif var.is_immutable:
            mod = " (immutable)"
        lines.append(f"  - {var.name}: {var.var_type}{mod}")

    lines.append("")
    lines.append("## Functions")
    for func in contract.functions:
        mods = f" [{', '.join(func.modifiers)}]" if func.modifiers else ""
        lines.append(f"  - {func.visibility} {func.name}({len(func.parameters)} params){mods}")

        if func.external_calls:
            for call in func.external_calls:
                value = " (sends value)" if call.value_sent else ""
                lines.append(f"      -> calls {call.target}.{call.function}{value}")

    return "\n".join(lines)
