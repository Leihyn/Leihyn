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


def find_solidity_files(directory: Path, recursive: bool = True) -> list[Path]:
    """Find all Solidity files in a directory."""
    pattern = "**/*.sol" if recursive else "*.sol"
    return list(directory.glob(pattern))


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

    # Function pattern
    func_pattern = r"""
        function\s+(\w+)\s*\(([^)]*)\)\s*
        ((?:public|external|internal|private)\s*)?
        ((?:view|pure|payable)\s*)?
        ((?:\w+\s*)*)?  # modifiers
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
        if match.group(7) == "{":
            func_start = match.end() - 1
            func_end = find_matching_brace(body, func_start)
            if func_end > func_start:
                func_body = body[func_start:func_end + 1]
                external_calls = extract_external_calls(func_body, name)
            else:
                external_calls = []
        else:
            external_calls = []

        functions.append(
            FunctionInfo(
                name=name,
                visibility=visibility,
                mutability=mutability,
                parameters=params,
                returns=returns,
                modifiers=modifiers,
                external_calls=external_calls,
            )
        )

    return functions


def extract_state_variables(body: str) -> list[StateVariable]:
    """Extract state variable information from contract body."""
    variables = []

    # State variable pattern (simplified)
    var_pattern = r"""
        ^\s*
        (mapping\s*\([^)]+\)|[\w\[\]]+)\s+  # type
        (public|private|internal)?\s*        # visibility
        (constant|immutable)?\s*             # modifiers
        (\w+)\s*                             # name
        (?:=|;)                              # assignment or end
    """

    for match in re.finditer(var_pattern, body, re.VERBOSE | re.MULTILINE):
        var_type = match.group(1).strip()
        visibility = match.group(2) or "internal"
        modifier = match.group(3)
        name = match.group(4)

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
