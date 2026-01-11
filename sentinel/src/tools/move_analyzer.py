"""
Move language analysis tools for Aptos and Sui.

Move is a resource-oriented language with built-in safety features,
but still has unique vulnerability patterns.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.languages import Language, LanguageAnalyzer, LanguageParser


@dataclass
class MoveFunctionInfo:
    """Information about a Move function."""
    name: str
    visibility: str  # public, public(friend), entry, private
    is_entry: bool
    parameters: list[dict]
    return_type: Optional[str]
    acquires: list[str]  # Resources acquired
    type_parameters: list[str]


@dataclass
class MoveStructInfo:
    """Information about a Move struct/resource."""
    name: str
    abilities: list[str]  # copy, drop, store, key
    fields: list[dict]
    is_resource: bool  # Has 'key' ability


@dataclass
class MoveModuleInfo:
    """Information about a Move module."""
    name: str
    address: str
    functions: list[MoveFunctionInfo]
    structs: list[MoveStructInfo]
    uses: list[str]
    friends: list[str]


class MoveParser(LanguageParser):
    """Parser for Move smart contracts."""

    @property
    def language(self) -> Language:
        return Language.MOVE

    def parse_file(self, path: Path) -> dict:
        """Parse a Move file."""
        source = path.read_text()

        return {
            "path": str(path),
            "modules": self.extract_modules(source),
            "functions": self.extract_functions(source),
            "structs": self.extract_structs(source),
            "state": self.extract_state(source),
            "external_calls": self.find_external_calls(source),
            "is_aptos": self._is_aptos(source),
            "is_sui": self._is_sui(source),
        }

    def extract_modules(self, source: str) -> list[dict]:
        """Extract module definitions."""
        modules = []

        module_pattern = r"module\s+(?:(\w+)::)?(\w+)\s*\{"

        for match in re.finditer(module_pattern, source):
            modules.append({
                "address": match.group(1) or "_",
                "name": match.group(2),
            })

        return modules

    def extract_functions(self, source: str) -> list[dict]:
        """Extract function information from Move source."""
        functions = []

        # Move function pattern
        func_pattern = r"""
            (?P<vis>public\s*(?:\(friend\))?\s*|entry\s+)?  # Visibility
            fun\s+(?P<name>\w+)                              # Function name
            (?:<(?P<type_params>[^>]+)>)?                    # Type parameters
            \s*\((?P<params>[^)]*)\)                         # Parameters
            (?:\s*:\s*(?P<ret>[^{]+))?                       # Return type
            (?:\s+acquires\s+(?P<acquires>[^{]+))?           # Acquires clause
        """

        for match in re.finditer(func_pattern, source, re.VERBOSE):
            vis = (match.group("vis") or "private").strip()
            is_entry = "entry" in vis

            acquires = []
            if match.group("acquires"):
                acquires = [a.strip() for a in match.group("acquires").split(",")]

            type_params = []
            if match.group("type_params"):
                type_params = [t.strip() for t in match.group("type_params").split(",")]

            functions.append({
                "name": match.group("name"),
                "visibility": vis,
                "is_entry": is_entry,
                "parameters": self._parse_params(match.group("params")),
                "return_type": (match.group("ret") or "").strip(),
                "acquires": acquires,
                "type_parameters": type_params,
            })

        return functions

    def extract_structs(self, source: str) -> list[dict]:
        """Extract struct/resource definitions."""
        structs = []

        # Struct pattern with abilities
        struct_pattern = r"""
            struct\s+(?P<name>\w+)
            (?:<[^>]+>)?                           # Type parameters
            \s+has\s+(?P<abilities>[^{]+)          # Abilities
            \s*\{(?P<body>[^}]*)\}
        """

        for match in re.finditer(struct_pattern, source, re.VERBOSE | re.DOTALL):
            abilities = [a.strip() for a in match.group("abilities").split(",")]

            structs.append({
                "name": match.group("name"),
                "abilities": abilities,
                "fields": self._parse_struct_fields(match.group("body")),
                "is_resource": "key" in abilities,
            })

        # Also match structs without explicit abilities (Sui style)
        simple_struct_pattern = r"struct\s+(\w+)(?:<[^>]+>)?\s*\{([^}]*)\}"

        for match in re.finditer(simple_struct_pattern, source, re.DOTALL):
            name = match.group(1)
            # Skip if already found with abilities
            if not any(s["name"] == name for s in structs):
                structs.append({
                    "name": name,
                    "abilities": [],
                    "fields": self._parse_struct_fields(match.group(2)),
                    "is_resource": False,
                })

        return structs

    def extract_state(self, source: str) -> list[dict]:
        """Extract resource/state definitions."""
        # In Move, resources are structs with 'key' ability
        structs = self.extract_structs(source)
        return [s for s in structs if s.get("is_resource")]

    def find_external_calls(self, source: str) -> list[dict]:
        """Find cross-module calls."""
        calls = []

        # Module::function calls
        call_pattern = r"(\w+)::(\w+)(?:<[^>]*>)?\s*\("

        for match in re.finditer(call_pattern, source):
            module = match.group(1)
            func = match.group(2)

            # Skip common standard library modules
            if module not in ["vector", "option", "string", "error", "signer"]:
                calls.append({
                    "module": module,
                    "function": func,
                    "type": "cross_module_call",
                })

        return calls

    def _is_aptos(self, source: str) -> bool:
        """Check if this is an Aptos Move file."""
        aptos_markers = [
            "aptos_framework",
            "aptos_std",
            "aptos_token",
            "0x1::coin",
            "0x1::account",
        ]
        return any(marker in source for marker in aptos_markers)

    def _is_sui(self, source: str) -> bool:
        """Check if this is a Sui Move file."""
        sui_markers = [
            "sui::object",
            "sui::transfer",
            "sui::tx_context",
            "TxContext",
            "UID",
        ]
        return any(marker in source for marker in sui_markers)

    def _parse_params(self, params_str: str) -> list[dict]:
        """Parse function parameters."""
        if not params_str.strip():
            return []

        params = []
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue

            parts = param.split(":")
            if len(parts) == 2:
                params.append({
                    "name": parts[0].strip(),
                    "type": parts[1].strip(),
                })

        return params

    def _parse_struct_fields(self, body: str) -> list[dict]:
        """Parse struct fields."""
        fields = []

        field_pattern = r"(\w+)\s*:\s*([^,\n}]+)"

        for match in re.finditer(field_pattern, body):
            fields.append({
                "name": match.group(1),
                "type": match.group(2).strip().rstrip(","),
            })

        return fields


class MoveProverAnalyzer(LanguageAnalyzer):
    """Move Prover for formal verification."""

    @property
    def language(self) -> Language:
        return Language.MOVE

    @property
    def name(self) -> str:
        return "move-prover"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["aptos", "move", "prove", "--help"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run(self, project_path: Path) -> list[dict]:
        """Run Move Prover."""
        if not self.is_available():
            return [{"error": "Move Prover not available. Install Aptos CLI."}]

        try:
            result = subprocess.run(
                ["aptos", "move", "prove"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Parse prover output
            findings = []

            if "error" in result.stderr.lower():
                # Extract error messages
                error_pattern = r"error\[([^\]]+)\]:\s*(.+)"
                for match in re.finditer(error_pattern, result.stderr, re.MULTILINE):
                    findings.append({
                        "severity": "HIGH",
                        "code": match.group(1),
                        "message": match.group(2).strip(),
                    })

            return findings

        except subprocess.TimeoutExpired:
            return [{"error": "Move Prover timed out"}]
        except Exception as e:
            return [{"error": str(e)}]


# Move-specific vulnerability patterns
MOVE_VULNERABILITY_PATTERNS = {
    "resource_leak": {
        "severity": "Critical",
        "patterns": [
            r"move_to\s*\(",  # Check resource is properly stored
            r"move_from\s*\(",  # Check resource is properly consumed
        ],
        "description": "Resource may be leaked or improperly handled",
    },
    "capability_leak": {
        "severity": "Critical",
        "patterns": [
            r"public.*fun.*\(&.*Capability",
            r"public.*fun.*returns.*Capability",
        ],
        "description": "Capability may be exposed to unauthorized callers",
    },
    "signer_check": {
        "severity": "High",
        "patterns": [
            r"public\s+entry\s+fun\s+\w+\s*\([^)]*\)",  # Entry without signer
        ],
        "description": "Entry function may be missing signer validation",
    },
    "flash_loan_vulnerability": {
        "severity": "High",
        "patterns": [
            r"borrow_global_mut.*\n.*[^}]*\n.*borrow_global",
        ],
        "description": "Potential flash loan vulnerability - state read after mutable borrow",
    },
    "access_control": {
        "severity": "High",
        "patterns": [
            r"public\s+fun.*move_to",
            r"public\s+fun.*move_from",
        ],
        "description": "Public function modifies global state - verify access control",
    },
    "object_safety_sui": {
        "severity": "High",
        "patterns": [
            r"transfer::share_object",
            r"transfer::freeze_object",
        ],
        "description": "Object ownership transfer - verify access patterns",
    },
    "reentrancy_via_callback": {
        "severity": "Medium",
        "patterns": [
            r"public.*fun.*\n.*[^}]*call.*\n.*borrow_global",
        ],
        "description": "Potential reentrancy via external module callback",
    },
}


# Sui-specific patterns
SUI_VULNERABILITY_PATTERNS = {
    "shared_object_mutation": {
        "severity": "High",
        "patterns": [
            r"&mut.*SharedObject",
            r"borrow_mut.*shared",
        ],
        "description": "Shared object mutation - verify concurrent access safety",
    },
    "object_wrapping": {
        "severity": "Medium",
        "patterns": [
            r"wrap\s*\(",
            r"unwrap\s*\(",
        ],
        "description": "Object wrapping/unwrapping - verify ownership transfer",
    },
    "dynamic_field_access": {
        "severity": "Medium",
        "patterns": [
            r"dynamic_field::add",
            r"dynamic_field::remove",
            r"dynamic_object_field",
        ],
        "description": "Dynamic field access - verify field existence checks",
    },
}


def analyze_move_patterns(source: str, is_sui: bool = False) -> list[dict]:
    """
    Analyze Move-specific vulnerability patterns.
    """
    findings = []

    patterns = MOVE_VULNERABILITY_PATTERNS.copy()
    if is_sui:
        patterns.update(SUI_VULNERABILITY_PATTERNS)

    for vuln_name, vuln_info in patterns.items():
        for pattern in vuln_info["patterns"]:
            matches = list(re.finditer(pattern, source, re.MULTILINE))
            if matches:
                findings.append({
                    "vulnerability": vuln_name,
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "matches": len(matches),
                })

    return findings
