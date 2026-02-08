"""
Rust/Solana/Anchor analysis tools.

Supports:
- Solana programs (native and Anchor)
- CosmWasm contracts
- NEAR contracts
"""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.languages import Language, LanguageAnalyzer, LanguageParser


@dataclass
class RustFunctionInfo:
    """Information about a Rust function."""
    name: str
    visibility: str  # pub, pub(crate), private
    is_async: bool
    parameters: list[dict]
    return_type: Optional[str]
    attributes: list[str]  # #[instruction], #[account], etc.
    source_lines: tuple[int, int]

    # Solana-specific
    is_instruction: bool = False
    accounts_required: list[str] = None


@dataclass
class AnchorAccountInfo:
    """Information about an Anchor account struct."""
    name: str
    fields: list[dict]
    constraints: list[str]  # #[account(mut)], etc.
    is_signer: bool = False
    is_mutable: bool = False


@dataclass
class SoteriaResult:
    """Result from Soteria static analyzer."""
    severity: str
    vulnerability: str
    description: str
    file: str
    line: int
    code_snippet: Optional[str] = None


class RustParser(LanguageParser):
    """Parser for Rust smart contracts."""

    @property
    def language(self) -> Language:
        return Language.RUST

    def parse_file(self, path: Path) -> dict:
        """Parse a Rust file."""
        source = path.read_text()

        return {
            "path": str(path),
            "functions": self.extract_functions(source),
            "structs": self.extract_structs(source),
            "state": self.extract_state(source),
            "imports": self.extract_imports(source),
            "external_calls": self.find_external_calls(source),
            "is_anchor": self._is_anchor_program(source),
        }

    def extract_functions(self, source: str) -> list[dict]:
        """Extract function information from Rust source."""
        functions = []

        # Pattern for Rust functions
        # Handles pub, pub(crate), async, attributes
        func_pattern = r"""
            (?P<attrs>(?:\#\[[^\]]+\]\s*)*)  # Attributes
            (?P<vis>pub(?:\([^)]+\))?\s+)?   # Visibility
            (?P<async>async\s+)?             # Async
            fn\s+(?P<name>\w+)               # Function name
            (?:<[^>]+>)?                     # Generics
            \s*\((?P<params>[^)]*)\)         # Parameters
            (?:\s*->\s*(?P<ret>[^{]+))?      # Return type
        """

        for match in re.finditer(func_pattern, source, re.VERBOSE):
            attrs = match.group("attrs") or ""
            attr_list = re.findall(r"#\[([^\]]+)\]", attrs)

            # Check for Anchor instruction
            is_instruction = any("instruction" in a or "Instruction" in a for a in attr_list)

            functions.append({
                "name": match.group("name"),
                "visibility": (match.group("vis") or "private").strip(),
                "is_async": bool(match.group("async")),
                "parameters": self._parse_params(match.group("params")),
                "return_type": (match.group("ret") or "").strip(),
                "attributes": attr_list,
                "is_instruction": is_instruction,
            })

        return functions

    def extract_structs(self, source: str) -> list[dict]:
        """Extract struct definitions, especially Anchor accounts."""
        structs = []

        # Pattern for structs with attributes
        struct_pattern = r"""
            (?P<attrs>(?:\#\[[^\]]+\]\s*)*)
            (?:pub\s+)?struct\s+(?P<name>\w+)
            (?:<[^>]+>)?
            \s*\{(?P<body>[^}]+)\}
        """

        for match in re.finditer(struct_pattern, source, re.VERBOSE | re.DOTALL):
            attrs = match.group("attrs") or ""
            attr_list = re.findall(r"#\[([^\]]+)\]", attrs)

            # Check for Anchor account types
            is_account = any("account" in a.lower() or "Account" in a for a in attr_list)

            fields = self._parse_struct_fields(match.group("body"))

            structs.append({
                "name": match.group("name"),
                "attributes": attr_list,
                "fields": fields,
                "is_anchor_account": is_account,
            })

        return structs

    def extract_state(self, source: str) -> list[dict]:
        """Extract state/storage definitions."""
        # In Anchor, state is typically in account structs
        # Look for #[account] annotated structs
        state = []

        account_pattern = r"#\[account[^\]]*\]\s*(?:pub\s+)?struct\s+(\w+)"

        for match in re.finditer(account_pattern, source):
            state.append({
                "name": match.group(1),
                "type": "anchor_account",
            })

        return state

    def extract_imports(self, source: str) -> list[str]:
        """Extract use statements."""
        imports = []

        use_pattern = r"use\s+([^;]+);"
        for match in re.finditer(use_pattern, source):
            imports.append(match.group(1).strip())

        return imports

    def find_external_calls(self, source: str) -> list[dict]:
        """Find Cross-Program Invocations (CPIs) and external calls."""
        calls = []

        # Anchor CPI patterns
        cpi_patterns = [
            r"CpiContext::new\s*\(",
            r"invoke\s*\(",
            r"invoke_signed\s*\(",
            r"::cpi::\w+\s*\(",
            r"token::\w+\s*\(",
            r"system_program::\w+\s*\(",
        ]

        for pattern in cpi_patterns:
            for match in re.finditer(pattern, source):
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(source), match.end() + 100)
                context = source[start:end]

                calls.append({
                    "type": "cpi",
                    "pattern": match.group(0),
                    "context": context.strip(),
                })

        return calls

    def _is_anchor_program(self, source: str) -> bool:
        """Check if this is an Anchor program."""
        anchor_markers = [
            "use anchor_lang",
            "#[program]",
            "declare_id!",
            "AnchorSerialize",
        ]
        return any(marker in source for marker in anchor_markers)

    def _parse_params(self, params_str: str) -> list[dict]:
        """Parse function parameters."""
        if not params_str.strip():
            return []

        params = []
        # Simple parsing - doesn't handle all edge cases
        for param in params_str.split(","):
            param = param.strip()
            if not param or param == "self" or param == "&self" or param == "&mut self":
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

        field_pattern = r"(?:#\[([^\]]+)\]\s*)*(?:pub\s+)?(\w+)\s*:\s*([^,\n]+)"

        for match in re.finditer(field_pattern, body):
            attrs = match.group(1) or ""
            fields.append({
                "name": match.group(2),
                "type": match.group(3).strip().rstrip(","),
                "attributes": attrs,
            })

        return fields


class SoteriaAnalyzer(LanguageAnalyzer):
    """Soteria static analyzer for Solana programs."""

    @property
    def language(self) -> Language:
        return Language.RUST

    @property
    def name(self) -> str:
        return "soteria"

    def is_available(self) -> bool:
        """Check if Soteria is installed."""
        try:
            result = subprocess.run(
                ["soteria", "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run(self, project_path: Path) -> list[dict]:
        """Run Soteria analysis."""
        if not self.is_available():
            return [{"error": "Soteria not installed. Install from: https://www.soteria.dev/"}]

        try:
            result = subprocess.run(
                ["soteria", "-analyzeAll", str(project_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse output (Soteria outputs in a specific format)
            findings = self._parse_output(result.stdout)
            return findings

        except subprocess.TimeoutExpired:
            return [{"error": "Soteria timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def _parse_output(self, output: str) -> list[dict]:
        """Parse Soteria output."""
        findings = []

        # Soteria output parsing (format may vary)
        # Looking for patterns like: [VULNERABILITY_TYPE] description at file:line
        vuln_pattern = r"\[(HIGH|MEDIUM|LOW|INFO)\]\s*([^:]+):\s*(.+?)(?:at\s+([^:]+):(\d+))?"

        for match in re.finditer(vuln_pattern, output, re.MULTILINE):
            findings.append({
                "severity": match.group(1),
                "vulnerability": match.group(2).strip(),
                "description": match.group(3).strip(),
                "file": match.group(4) if match.group(4) else "unknown",
                "line": int(match.group(5)) if match.group(5) else 0,
            })

        return findings


class CargoClippyAnalyzer(LanguageAnalyzer):
    """Clippy linter for Rust (catches common issues)."""

    @property
    def language(self) -> Language:
        return Language.RUST

    @property
    def name(self) -> str:
        return "clippy"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["cargo", "clippy", "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def run(self, project_path: Path) -> list[dict]:
        """Run Clippy analysis."""
        try:
            result = subprocess.run(
                [
                    "cargo", "clippy",
                    "--message-format=json",
                    "--",
                    "-D", "warnings",  # Treat warnings as errors
                ],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            findings = []
            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("reason") == "compiler-message":
                        message = msg.get("message", {})
                        if message.get("level") in ["warning", "error"]:
                            findings.append({
                                "severity": "HIGH" if message["level"] == "error" else "MEDIUM",
                                "code": message.get("code", {}).get("code", "unknown"),
                                "message": message.get("message", ""),
                                "spans": message.get("spans", []),
                            })
                except json.JSONDecodeError:
                    continue

            return findings

        except subprocess.TimeoutExpired:
            return [{"error": "Clippy timed out"}]
        except Exception as e:
            return [{"error": str(e)}]


# Solana-specific vulnerability patterns
SOLANA_VULNERABILITY_PATTERNS = {
    "missing_signer_check": {
        "severity": "Critical",
        "patterns": [
            r"AccountInfo.*without.*is_signer",
            r"(?<!if\s+)(?<!require!\s*\().*\.key\s*==",  # Key comparison without signer check
        ],
        "description": "Missing signer verification allows unauthorized account modification",
    },
    "missing_owner_check": {
        "severity": "Critical",
        "patterns": [
            r"AccountInfo.*without.*owner",
            r"\.owner\s*!=\s*program_id",
        ],
        "description": "Missing owner check allows malicious account injection",
    },
    "arithmetic_overflow": {
        "severity": "High",
        "patterns": [
            r"\.checked_add\s*\(",
            r"\.checked_sub\s*\(",
            r"\.checked_mul\s*\(",
            r"\+\s*(?!.*checked)",
            r"-\s*(?!.*checked)",
        ],
        "description": "Arithmetic operations without overflow checks",
    },
    "account_confusion": {
        "severity": "High",
        "patterns": [
            r"#\[account\([^)]*\)\].*\n.*Account<'info",
        ],
        "description": "Potential account type confusion vulnerability",
    },
    "pda_validation": {
        "severity": "High",
        "patterns": [
            r"Pubkey::create_program_address",
            r"Pubkey::find_program_address",
        ],
        "description": "PDA creation - verify bump seed is validated",
    },
    "closing_accounts": {
        "severity": "Medium",
        "patterns": [
            r"close\s*=",
            r"\.close\s*\(",
            r"lamports.*=.*0",
        ],
        "description": "Account closing - verify reinitialization is prevented",
    },
}


def analyze_solana_patterns(source: str) -> list[dict]:
    """
    Analyze Solana-specific vulnerability patterns.
    """
    findings = []

    for vuln_name, vuln_info in SOLANA_VULNERABILITY_PATTERNS.items():
        for pattern in vuln_info["patterns"]:
            matches = list(re.finditer(pattern, source))
            if matches:
                findings.append({
                    "vulnerability": vuln_name,
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "matches": len(matches),
                    "locations": [m.start() for m in matches[:5]],
                })

    return findings
