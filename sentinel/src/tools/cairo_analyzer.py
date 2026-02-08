"""
Cairo language analysis tools for StarkNet.

Cairo is StarkNet's native language with unique characteristics:
- Felt (field element) arithmetic
- Storage proofs
- L1-L2 messaging
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.languages import Language, LanguageAnalyzer, LanguageParser


@dataclass
class CairoFunctionInfo:
    """Information about a Cairo function."""
    name: str
    visibility: str  # external, view, internal
    decorators: list[str]  # @external, @view, @l1_handler, etc.
    parameters: list[dict]
    return_type: Optional[str]
    is_external: bool
    is_view: bool
    is_l1_handler: bool


@dataclass
class CairoStorageInfo:
    """Information about Cairo storage."""
    name: str
    storage_type: str
    is_mapping: bool = False


class CairoParser(LanguageParser):
    """Parser for Cairo smart contracts (Cairo 1.0+)."""

    @property
    def language(self) -> Language:
        return Language.CAIRO

    def parse_file(self, path: Path) -> dict:
        """Parse a Cairo file."""
        source = path.read_text()

        # Detect Cairo version
        is_cairo_1 = self._is_cairo_1(source)

        return {
            "path": str(path),
            "cairo_version": "1.0+" if is_cairo_1 else "0.x",
            "contracts": self.extract_contracts(source),
            "functions": self.extract_functions(source),
            "storage": self.extract_state(source),
            "events": self.extract_events(source),
            "external_calls": self.find_external_calls(source),
        }

    def extract_contracts(self, source: str) -> list[dict]:
        """Extract contract/module definitions."""
        contracts = []

        # Cairo 1.0 module pattern
        module_pattern = r"#\[starknet::contract\]\s*mod\s+(\w+)"

        for match in re.finditer(module_pattern, source):
            contracts.append({
                "name": match.group(1),
                "type": "starknet_contract",
            })

        # Cairo 0.x %contract pattern (legacy)
        legacy_pattern = r"%contract\s+(\w+)"
        for match in re.finditer(legacy_pattern, source):
            contracts.append({
                "name": match.group(1),
                "type": "legacy_contract",
            })

        return contracts

    def extract_functions(self, source: str) -> list[dict]:
        """Extract function information from Cairo source."""
        functions = []

        # Cairo 1.0 function pattern
        func_pattern = r"""
            (?P<decorators>(?:#\[[^\]]+\]\s*)*)  # Decorators
            fn\s+(?P<name>\w+)                   # Function name
            \s*\((?P<params>[^)]*)\)             # Parameters
            (?:\s*->\s*(?P<ret>[^{]+))?          # Return type
        """

        for match in re.finditer(func_pattern, source, re.VERBOSE):
            decorators_str = match.group("decorators") or ""
            decorators = re.findall(r"#\[(\w+)[^\]]*\]", decorators_str)

            is_external = "external" in decorators or "abi" in decorators_str
            is_view = "view" in decorators
            is_l1_handler = "l1_handler" in decorators

            functions.append({
                "name": match.group("name"),
                "decorators": decorators,
                "parameters": self._parse_params(match.group("params")),
                "return_type": (match.group("ret") or "").strip(),
                "is_external": is_external,
                "is_view": is_view,
                "is_l1_handler": is_l1_handler,
                "visibility": "external" if is_external else ("view" if is_view else "internal"),
            })

        return functions

    def extract_state(self, source: str) -> list[dict]:
        """Extract storage variables."""
        storage = []

        # Cairo 1.0 #[storage] block
        storage_block_pattern = r"#\[storage\]\s*struct\s+Storage\s*\{([^}]+)\}"

        match = re.search(storage_block_pattern, source, re.DOTALL)
        if match:
            storage_body = match.group(1)

            # Parse individual storage vars
            var_pattern = r"(\w+)\s*:\s*([^,\n}]+)"
            for var_match in re.finditer(var_pattern, storage_body):
                name = var_match.group(1)
                var_type = var_match.group(2).strip()

                is_mapping = "LegacyMap" in var_type or "Map" in var_type

                storage.append({
                    "name": name,
                    "type": var_type,
                    "is_mapping": is_mapping,
                })

        # Cairo 0.x @storage_var (legacy)
        legacy_pattern = r"@storage_var\s*func\s+(\w+)"
        for match in re.finditer(legacy_pattern, source):
            storage.append({
                "name": match.group(1),
                "type": "storage_var",
                "is_mapping": True,  # Legacy storage vars are typically mappings
            })

        return storage

    def extract_events(self, source: str) -> list[str]:
        """Extract event definitions."""
        events = []

        # Cairo 1.0 #[event] enum
        event_pattern = r"#\[event\]\s*#\[derive\([^\)]+\)\]\s*enum\s+(\w+)"
        for match in re.finditer(event_pattern, source):
            events.append(match.group(1))

        # Individual event variants
        variant_pattern = r"#\[derive\(Drop,\s*starknet::Event\)\]\s*struct\s+(\w+)"
        for match in re.finditer(variant_pattern, source):
            events.append(match.group(1))

        return events

    def find_external_calls(self, source: str) -> list[dict]:
        """Find external contract calls."""
        calls = []

        # Cairo 1.0 dispatcher pattern
        dispatcher_pattern = r"(\w+)Dispatcher\s*\{\s*contract_address[^}]*\}\.(\w+)\s*\("

        for match in re.finditer(dispatcher_pattern, source):
            calls.append({
                "contract": match.group(1),
                "function": match.group(2),
                "type": "dispatcher_call",
            })

        # L1 handler calls
        l1_pattern = r"send_message_to_l1\s*\("
        if re.search(l1_pattern, source):
            calls.append({
                "type": "l1_message",
                "direction": "outgoing",
            })

        # Library calls
        library_pattern = r"(\w+)LibraryDispatcher"
        for match in re.finditer(library_pattern, source):
            calls.append({
                "library": match.group(1),
                "type": "library_call",
            })

        return calls

    def _is_cairo_1(self, source: str) -> bool:
        """Detect if this is Cairo 1.0+ syntax."""
        cairo_1_markers = [
            "#[starknet::contract]",
            "#[starknet::interface]",
            "use starknet::",
            "#[storage]",
            "#[external",
            "fn ",  # Cairo 1.0 uses fn instead of func
        ]
        return any(marker in source for marker in cairo_1_markers)

    def _parse_params(self, params_str: str) -> list[dict]:
        """Parse function parameters."""
        if not params_str.strip():
            return []

        params = []
        # Handle self parameter
        params_str = re.sub(r"ref\s+self:\s*ContractState,?\s*", "", params_str)
        params_str = re.sub(r"self:\s*@ContractState,?\s*", "", params_str)

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


class AmarnaAnalyzer(LanguageAnalyzer):
    """Amarna static analyzer for Cairo (StarkWare's official tool)."""

    @property
    def language(self) -> Language:
        return Language.CAIRO

    @property
    def name(self) -> str:
        return "amarna"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["amarna", "--help"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run(self, project_path: Path) -> list[dict]:
        """Run Amarna analysis."""
        if not self.is_available():
            return [{"error": "Amarna not installed. Install with: pip install amarna"}]

        try:
            # Find Cairo files
            cairo_files = list(project_path.rglob("*.cairo"))

            if not cairo_files:
                return [{"error": "No Cairo files found"}]

            all_findings = []

            for cairo_file in cairo_files:
                result = subprocess.run(
                    ["amarna", str(cairo_file), "-o", "-"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                # Parse SARIF output
                findings = self._parse_sarif(result.stdout, str(cairo_file))
                all_findings.extend(findings)

            return all_findings

        except subprocess.TimeoutExpired:
            return [{"error": "Amarna timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def _parse_sarif(self, output: str, file_path: str) -> list[dict]:
        """Parse SARIF format output from Amarna."""
        import json

        findings = []

        try:
            sarif = json.loads(output)
            runs = sarif.get("runs", [])

            for run in runs:
                results = run.get("results", [])
                for result in results:
                    rule_id = result.get("ruleId", "unknown")
                    message = result.get("message", {}).get("text", "")
                    level = result.get("level", "warning")

                    # Map level to severity
                    severity_map = {
                        "error": "HIGH",
                        "warning": "MEDIUM",
                        "note": "LOW",
                    }

                    findings.append({
                        "rule": rule_id,
                        "severity": severity_map.get(level, "MEDIUM"),
                        "message": message,
                        "file": file_path,
                    })

        except json.JSONDecodeError:
            # Fall back to text parsing
            lines = output.strip().split("\n")
            for line in lines:
                if ":" in line:
                    findings.append({
                        "message": line,
                        "severity": "MEDIUM",
                    })

        return findings


class CaracalAnalyzer(LanguageAnalyzer):
    """Caracal static analyzer for Cairo/StarkNet."""

    @property
    def language(self) -> Language:
        return Language.CAIRO

    @property
    def name(self) -> str:
        return "caracal"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["caracal", "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run(self, project_path: Path) -> list[dict]:
        """Run Caracal analysis."""
        if not self.is_available():
            return [{"error": "Caracal not installed. See: https://github.com/crytic/caracal"}]

        try:
            result = subprocess.run(
                ["caracal", "detect", "--json", str(project_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            import json
            try:
                findings = json.loads(result.stdout)
                return findings
            except json.JSONDecodeError:
                return [{"output": result.stdout}]

        except subprocess.TimeoutExpired:
            return [{"error": "Caracal timed out"}]
        except Exception as e:
            return [{"error": str(e)}]


# Cairo-specific vulnerability patterns
CAIRO_VULNERABILITY_PATTERNS = {
    "felt_overflow": {
        "severity": "Critical",
        "patterns": [
            r"\+\s*(?![^;]*assert|[^;]*check)",  # Addition without check
            r"\*\s*(?![^;]*assert|[^;]*check)",  # Multiplication without check
        ],
        "description": "Felt arithmetic may overflow without proper checks",
    },
    "unprotected_initializer": {
        "severity": "Critical",
        "patterns": [
            r"fn\s+initializer?\s*\([^)]*\)",
            r"fn\s+constructor\s*\([^)]*\)(?![^{]*assert)",
        ],
        "description": "Initializer may be callable multiple times",
    },
    "storage_collision": {
        "severity": "High",
        "patterns": [
            r"storage_write\s*\(",
            r"storage_read\s*\(",
        ],
        "description": "Direct storage access may cause collision with storage vars",
    },
    "l1_l2_messaging": {
        "severity": "High",
        "patterns": [
            r"#\[l1_handler\]",
            r"send_message_to_l1",
        ],
        "description": "L1-L2 messaging - verify message handling and replay protection",
    },
    "missing_zero_check": {
        "severity": "Medium",
        "patterns": [
            r"contract_address\s*:\s*\w+(?![^;]*assert.*!= 0)",
        ],
        "description": "Contract address parameter may be zero",
    },
    "unchecked_return": {
        "severity": "Medium",
        "patterns": [
            r"Dispatcher.*\.\w+\s*\([^)]*\)\s*;",  # Dispatcher call without using return
        ],
        "description": "Return value from external call not checked",
    },
    "reentrancy_cairo": {
        "severity": "High",
        "patterns": [
            r"Dispatcher.*\.\w+\s*\([^)]*\)[^;]*\n[^}]*storage",
        ],
        "description": "External call before storage update - potential reentrancy",
    },
    "access_control": {
        "severity": "High",
        "patterns": [
            r"#\[external[^\]]*\]\s*fn[^{]*\{(?![^}]*assert.*caller|[^}]*get_caller)",
        ],
        "description": "External function may be missing access control",
    },
}


def analyze_cairo_patterns(source: str) -> list[dict]:
    """
    Analyze Cairo-specific vulnerability patterns.
    """
    findings = []

    for vuln_name, vuln_info in CAIRO_VULNERABILITY_PATTERNS.items():
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


# StarkNet-specific concerns
STARKNET_SECURITY_CHECKS = [
    {
        "name": "Proxy Pattern",
        "check": lambda s: "#[starknet::contract]" in s and "upgrade" in s.lower(),
        "concern": "Contract appears upgradeable - verify upgrade access control",
    },
    {
        "name": "L1 Handler",
        "check": lambda s: "#[l1_handler]" in s,
        "concern": "L1 handler found - verify message authentication and replay protection",
    },
    {
        "name": "Multi-call",
        "check": lambda s: "multicall" in s.lower() or "batch" in s.lower(),
        "concern": "Multicall pattern - verify atomicity and reentrancy protection",
    },
    {
        "name": "Account Abstraction",
        "check": lambda s: "__validate__" in s or "is_valid_signature" in s,
        "concern": "Account contract - verify signature validation and execution flow",
    },
]
