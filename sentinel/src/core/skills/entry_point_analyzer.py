"""
Entry Point Analyzer - Trail of Bits Skill

Systematically identify all state-changing entry points in smart contracts
to guide security audits. Maps attack surface by access level.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/entry-point-analyzer
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re
import subprocess


class AccessLevel(Enum):
    """Entry point access classification."""
    PUBLIC = "public"  # Unrestricted, anyone can call
    ROLE_RESTRICTED = "role_restricted"  # Limited to specific roles
    ADMIN = "admin"  # Owner/admin only
    GOVERNANCE = "governance"  # Governance/timelock
    GUARDIAN = "guardian"  # Guardian/pauser
    CONTRACT_ONLY = "contract_only"  # Only callable by other contracts
    REVIEW_REQUIRED = "review_required"  # Ambiguous, needs manual review


class ContractLanguage(Enum):
    """Supported smart contract languages."""
    SOLIDITY = "solidity"
    VYPER = "vyper"
    SOLANA_RUST = "solana_rust"
    MOVE_SUI = "move_sui"
    MOVE_APTOS = "move_aptos"
    TON_FUNC = "ton_func"
    TON_TACT = "ton_tact"
    COSMWASM = "cosmwasm"


@dataclass
class EntryPoint:
    """Represents a state-changing entry point."""
    name: str
    file_path: str
    line_number: int
    signature: str
    access_level: AccessLevel
    visibility: str
    modifiers: list[str] = field(default_factory=list)
    restriction_pattern: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "file": f"{self.file_path}:L{self.line_number}",
            "signature": self.signature,
            "access": self.access_level.value,
            "visibility": self.visibility,
            "modifiers": self.modifiers,
            "restriction": self.restriction_pattern,
            "notes": self.notes,
        }


@dataclass
class EntryPointReport:
    """Complete entry point analysis report."""
    project_name: str
    languages: list[ContractLanguage]
    scope: str
    entry_points: list[EntryPoint]
    files_analyzed: list[str]
    slither_used: bool = False

    @property
    def public_count(self) -> int:
        return len([e for e in self.entry_points if e.access_level == AccessLevel.PUBLIC])

    @property
    def role_restricted_count(self) -> int:
        return len([e for e in self.entry_points if e.access_level == AccessLevel.ROLE_RESTRICTED])

    @property
    def admin_count(self) -> int:
        return len([e for e in self.entry_points if e.access_level == AccessLevel.ADMIN])

    @property
    def contract_only_count(self) -> int:
        return len([e for e in self.entry_points if e.access_level == AccessLevel.CONTRACT_ONLY])

    @property
    def review_required_count(self) -> int:
        return len([e for e in self.entry_points if e.access_level == AccessLevel.REVIEW_REQUIRED])

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# Entry Point Analysis: {self.project_name}",
            "",
            f"**Scope**: {self.scope}",
            f"**Languages**: {', '.join(l.value for l in self.languages)}",
            f"**Focus**: State-changing functions only (view/pure excluded)",
            f"**Slither Used**: {'Yes' if self.slither_used else 'No'}",
            "",
            "## Summary",
            "",
            "| Category | Count |",
            "|----------|-------|",
            f"| Public (Unrestricted) | {self.public_count} |",
            f"| Role-Restricted | {self.role_restricted_count} |",
            f"| Admin/Owner | {self.admin_count} |",
            f"| Contract-Only | {self.contract_only_count} |",
            f"| Review Required | {self.review_required_count} |",
            f"| **Total** | **{len(self.entry_points)}** |",
            "",
        ]

        # Group by access level
        for level in AccessLevel:
            level_entries = [e for e in self.entry_points if e.access_level == level]
            if level_entries:
                lines.append(f"## {level.value.replace('_', ' ').title()} Entry Points")
                lines.append("")
                lines.append("| Function | File | Restriction |")
                lines.append("|----------|------|-------------|")
                for ep in level_entries:
                    restriction = ep.restriction_pattern or "-"
                    lines.append(f"| `{ep.signature}` | `{ep.file_path}:L{ep.line_number}` | {restriction} |")
                lines.append("")

        # Files analyzed
        lines.append("## Files Analyzed")
        lines.append("")
        for f in self.files_analyzed:
            count = len([e for e in self.entry_points if e.file_path == f])
            lines.append(f"- `{f}` ({count} state-changing entry points)")

        return "\n".join(lines)


class EntryPointAnalyzer:
    """
    Analyzes smart contract codebases to identify state-changing entry points.

    Excludes view/pure/read-only functions. Focuses on functions that can
    modify state - the primary attack surface for security audits.
    """

    # Role patterns to detect
    ROLE_PATTERNS = {
        "admin": ["onlyOwner", "onlyAdmin", "requireOwner", "require.*owner", "assert_owner"],
        "governance": ["onlyGovernance", "onlyTimelock", "onlyDAO", "requireGovernance"],
        "guardian": ["onlyGuardian", "onlyPauser", "whenNotPaused", "onlyEmergency"],
        "operator": ["onlyOperator", "onlyKeeper", "onlyRelayer", "onlyManager"],
        "minter": ["onlyMinter", "canMint"],
    }

    # Callback patterns (contract-only)
    CALLBACK_PATTERNS = [
        "onERC721Received",
        "onERC1155Received",
        "onERC1155BatchReceived",
        "uniswapV3SwapCallback",
        "uniswapV2Call",
        "pancakeCall",
        "flashLoanCallback",
        "onFlashLoan",
        "receiveFlashLoan",
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.slither_available = self._check_slither()

    def _check_slither(self) -> bool:
        """Check if Slither is available."""
        try:
            result = subprocess.run(["which", "slither"], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False

    def detect_language(self, file_path: Path) -> Optional[ContractLanguage]:
        """Detect contract language from file extension and content."""
        ext = file_path.suffix.lower()

        if ext == ".sol":
            return ContractLanguage.SOLIDITY
        elif ext == ".vy":
            return ContractLanguage.VYPER
        elif ext == ".rs":
            # Check for Solana or CosmWasm
            content = file_path.read_text()
            if "solana_program" in content or "anchor_lang" in content:
                return ContractLanguage.SOLANA_RUST
            elif "cosmwasm_std" in content:
                return ContractLanguage.COSMWASM
        elif ext == ".move":
            # Check for Sui or Aptos
            if (file_path.parent / "Move.toml").exists():
                toml_content = (file_path.parent / "Move.toml").read_text()
                if "edition" in toml_content:
                    return ContractLanguage.MOVE_SUI
                elif "Aptos" in toml_content:
                    return ContractLanguage.MOVE_APTOS
        elif ext in [".fc", ".func"]:
            return ContractLanguage.TON_FUNC
        elif ext == ".tact":
            return ContractLanguage.TON_TACT

        return None

    def analyze(
        self,
        scope: Optional[str] = None,
        use_slither: bool = True,
    ) -> EntryPointReport:
        """
        Analyze codebase for state-changing entry points.

        Args:
            scope: Directory filter (e.g., "src/core/")
            use_slither: Try to use Slither for Solidity (if available)

        Returns:
            EntryPointReport with all identified entry points
        """
        entry_points: list[EntryPoint] = []
        files_analyzed: list[str] = []
        languages_found: set[ContractLanguage] = set()
        slither_used = False

        # Determine search path
        search_path = self.project_path / scope if scope else self.project_path

        # Find all contract files
        contract_files = []
        for pattern in ["**/*.sol", "**/*.vy", "**/*.rs", "**/*.move", "**/*.fc", "**/*.tact"]:
            contract_files.extend(search_path.glob(pattern))

        # Try Slither for Solidity
        sol_files = [f for f in contract_files if f.suffix == ".sol"]
        if sol_files and use_slither and self.slither_available:
            slither_entries = self._run_slither_entry_points()
            if slither_entries:
                entry_points.extend(slither_entries)
                slither_used = True
                languages_found.add(ContractLanguage.SOLIDITY)
                files_analyzed.extend([str(f.relative_to(self.project_path)) for f in sol_files])

        # Manual analysis for non-Solidity or if Slither failed
        for file_path in contract_files:
            if slither_used and file_path.suffix == ".sol":
                continue  # Already analyzed by Slither

            language = self.detect_language(file_path)
            if not language:
                continue

            languages_found.add(language)
            rel_path = str(file_path.relative_to(self.project_path))
            files_analyzed.append(rel_path)

            # Language-specific analysis
            if language == ContractLanguage.SOLIDITY:
                entry_points.extend(self._analyze_solidity(file_path, rel_path))
            elif language == ContractLanguage.VYPER:
                entry_points.extend(self._analyze_vyper(file_path, rel_path))
            elif language == ContractLanguage.SOLANA_RUST:
                entry_points.extend(self._analyze_solana(file_path, rel_path))
            elif language in [ContractLanguage.MOVE_SUI, ContractLanguage.MOVE_APTOS]:
                entry_points.extend(self._analyze_move(file_path, rel_path, language))
            elif language == ContractLanguage.COSMWASM:
                entry_points.extend(self._analyze_cosmwasm(file_path, rel_path))

        return EntryPointReport(
            project_name=self.project_path.name,
            languages=list(languages_found),
            scope=scope or "full codebase",
            entry_points=entry_points,
            files_analyzed=files_analyzed,
            slither_used=slither_used,
        )

    def _run_slither_entry_points(self) -> list[EntryPoint]:
        """Run Slither's entry-points printer."""
        try:
            result = subprocess.run(
                ["slither", str(self.project_path), "--print", "entry-points"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            # Parse Slither output (simplified - actual parsing would be more complex)
            return self._parse_slither_output(result.stdout)
        except Exception:
            return []

    def _parse_slither_output(self, output: str) -> list[EntryPoint]:
        """Parse Slither entry-points output."""
        # Simplified parsing - actual implementation would be more robust
        entry_points = []
        # ... parsing logic ...
        return entry_points

    def _analyze_solidity(self, file_path: Path, rel_path: str) -> list[EntryPoint]:
        """Analyze Solidity file for entry points."""
        content = file_path.read_text()
        entry_points = []

        # Regex for function definitions
        func_pattern = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s+((?:external|public|internal|private)\s*)?'
            r'((?:\s*\w+\s*)*?)(?:returns\s*\([^)]*\))?\s*[{;]',
            re.MULTILINE
        )

        for match in func_pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)
            visibility = match.group(3).strip() if match.group(3) else "public"
            modifiers_str = match.group(4) if match.group(4) else ""

            # Skip view/pure functions
            if "view" in modifiers_str or "pure" in modifiers_str:
                continue

            # Skip internal/private
            if visibility in ["internal", "private"]:
                continue

            line_number = content[:match.start()].count('\n') + 1
            signature = f"{func_name}({params})"

            # Classify access level
            access_level, restriction = self._classify_solidity_access(
                func_name, modifiers_str, content
            )

            entry_points.append(EntryPoint(
                name=func_name,
                file_path=rel_path,
                line_number=line_number,
                signature=signature,
                access_level=access_level,
                visibility=visibility,
                modifiers=[m.strip() for m in modifiers_str.split() if m.strip()],
                restriction_pattern=restriction,
            ))

        return entry_points

    def _classify_solidity_access(
        self,
        func_name: str,
        modifiers: str,
        content: str,
    ) -> tuple[AccessLevel, Optional[str]]:
        """Classify Solidity function access level."""
        modifiers_lower = modifiers.lower()

        # Check for callbacks (contract-only)
        if func_name in self.CALLBACK_PATTERNS:
            return AccessLevel.CONTRACT_ONLY, f"Callback: {func_name}"

        # Check role patterns
        for role, patterns in self.ROLE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, modifiers, re.IGNORECASE):
                    if role == "admin":
                        return AccessLevel.ADMIN, pattern
                    elif role == "governance":
                        return AccessLevel.GOVERNANCE, pattern
                    elif role == "guardian":
                        return AccessLevel.GUARDIAN, pattern
                    else:
                        return AccessLevel.ROLE_RESTRICTED, pattern

        # Check for require(msg.sender == ...) patterns in function body
        # Simplified - would need proper parsing
        if "onlyRole" in modifiers or "hasRole" in modifiers:
            return AccessLevel.ROLE_RESTRICTED, "Role-based access"

        # No restriction found - public
        return AccessLevel.PUBLIC, None

    def _analyze_vyper(self, file_path: Path, rel_path: str) -> list[EntryPoint]:
        """Analyze Vyper file for entry points."""
        content = file_path.read_text()
        entry_points = []

        # Regex for Vyper external functions
        func_pattern = re.compile(
            r'@external\s*\n(?:@\w+\s*\n)*def\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE
        )

        for match in func_pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)

            # Check for @view/@pure decorators
            decorator_section = content[max(0, match.start()-100):match.start()]
            if "@view" in decorator_section or "@pure" in decorator_section:
                continue

            line_number = content[:match.start()].count('\n') + 1
            signature = f"{func_name}({params})"

            entry_points.append(EntryPoint(
                name=func_name,
                file_path=rel_path,
                line_number=line_number,
                signature=signature,
                access_level=AccessLevel.PUBLIC,  # Simplified
                visibility="external",
            ))

        return entry_points

    def _analyze_solana(self, file_path: Path, rel_path: str) -> list[EntryPoint]:
        """Analyze Solana/Anchor program for entry points."""
        content = file_path.read_text()
        entry_points = []

        # Anchor instruction handlers
        anchor_pattern = re.compile(
            r'pub\s+fn\s+(\w+)\s*\(([^)]*)\)\s*->\s*Result',
            re.MULTILINE
        )

        for match in anchor_pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)
            line_number = content[:match.start()].count('\n') + 1

            # Check for signer validation
            access_level = AccessLevel.PUBLIC
            if "#[access_control" in content[max(0, match.start()-200):match.start()]:
                access_level = AccessLevel.ROLE_RESTRICTED

            entry_points.append(EntryPoint(
                name=func_name,
                file_path=rel_path,
                line_number=line_number,
                signature=f"{func_name}({params})",
                access_level=access_level,
                visibility="pub",
            ))

        return entry_points

    def _analyze_move(
        self,
        file_path: Path,
        rel_path: str,
        language: ContractLanguage,
    ) -> list[EntryPoint]:
        """Analyze Move (Sui/Aptos) module for entry points."""
        content = file_path.read_text()
        entry_points = []

        # Entry functions
        entry_pattern = re.compile(
            r'(?:public\s+)?entry\s+fun\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)',
            re.MULTILINE
        )

        for match in entry_pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)
            line_number = content[:match.start()].count('\n') + 1

            entry_points.append(EntryPoint(
                name=func_name,
                file_path=rel_path,
                line_number=line_number,
                signature=f"{func_name}({params})",
                access_level=AccessLevel.PUBLIC,
                visibility="entry",
            ))

        return entry_points

    def _analyze_cosmwasm(self, file_path: Path, rel_path: str) -> list[EntryPoint]:
        """Analyze CosmWasm contract for entry points."""
        content = file_path.read_text()
        entry_points = []

        # Execute message handlers
        execute_pattern = re.compile(
            r'ExecuteMsg::(\w+)\s*\{([^}]*)\}\s*=>',
            re.MULTILINE
        )

        for match in execute_pattern.finditer(content):
            msg_name = match.group(1)
            params = match.group(2)
            line_number = content[:match.start()].count('\n') + 1

            entry_points.append(EntryPoint(
                name=msg_name,
                file_path=rel_path,
                line_number=line_number,
                signature=f"ExecuteMsg::{msg_name}",
                access_level=AccessLevel.PUBLIC,
                visibility="execute",
            ))

        return entry_points


def analyze_entry_points(
    project_path: str,
    scope: Optional[str] = None,
    use_slither: bool = True,
) -> EntryPointReport:
    """
    Analyze a project for state-changing entry points.

    Args:
        project_path: Path to project root
        scope: Optional directory filter
        use_slither: Whether to use Slither for Solidity

    Returns:
        EntryPointReport with all findings
    """
    analyzer = EntryPointAnalyzer(project_path)
    return analyzer.analyze(scope=scope, use_slither=use_slither)
