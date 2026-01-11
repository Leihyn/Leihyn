"""
Multi-language support for Sentinel.

Supported Languages:
- Solidity (Ethereum, EVM chains)
- Rust (Solana/Anchor, CosmWasm, NEAR)
- Move (Aptos, Sui)
- Cairo (StarkNet)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Language(Enum):
    """Supported smart contract languages."""
    SOLIDITY = "solidity"
    RUST = "rust"
    MOVE = "move"
    CAIRO = "cairo"
    UNKNOWN = "unknown"


class Blockchain(Enum):
    """Supported blockchains."""
    # EVM
    ETHEREUM = "ethereum"
    BASE = "base"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"

    # Solana
    SOLANA = "solana"

    # Move chains
    APTOS = "aptos"
    SUI = "sui"

    # StarkNet
    STARKNET = "starknet"

    # Cosmos
    COSMOS = "cosmos"

    # NEAR
    NEAR = "near"

    UNKNOWN = "unknown"


@dataclass
class LanguageConfig:
    """Configuration for a specific language."""
    language: Language
    file_extensions: list[str]
    framework_markers: dict[str, str]  # File/pattern -> framework name
    static_analyzers: list[str]
    test_frameworks: list[str]
    common_vulnerabilities: list[str]


# Language configurations
LANGUAGE_CONFIGS = {
    Language.SOLIDITY: LanguageConfig(
        language=Language.SOLIDITY,
        file_extensions=[".sol"],
        framework_markers={
            "foundry.toml": "foundry",
            "hardhat.config.js": "hardhat",
            "hardhat.config.ts": "hardhat",
            "truffle-config.js": "truffle",
            "brownie-config.yaml": "brownie",
        },
        static_analyzers=["slither", "mythril", "securify", "4naly3er"],
        test_frameworks=["foundry", "hardhat", "brownie"],
        common_vulnerabilities=[
            "reentrancy",
            "access_control",
            "oracle_manipulation",
            "flash_loan",
            "integer_overflow",
            "front_running",
        ],
    ),
    Language.RUST: LanguageConfig(
        language=Language.RUST,
        file_extensions=[".rs"],
        framework_markers={
            "Anchor.toml": "anchor",
            "Cargo.toml": "rust",
            "Xargo.toml": "solana",
        },
        static_analyzers=["clippy", "cargo-audit", "soteria", "cargo-geiger"],
        test_frameworks=["anchor", "cargo-test", "solana-program-test"],
        common_vulnerabilities=[
            "missing_signer_check",
            "account_confusion",
            "pda_validation",
            "arithmetic_overflow",
            "cpi_vulnerability",
            "closing_accounts",
            "type_cosplay",
        ],
    ),
    Language.MOVE: LanguageConfig(
        language=Language.MOVE,
        file_extensions=[".move"],
        framework_markers={
            "Move.toml": "move",
            "Aptos.toml": "aptos",
            "sui.toml": "sui",
        },
        static_analyzers=["move-prover", "move-analyzer"],
        test_frameworks=["move-unit-test", "aptos-cli", "sui-cli"],
        common_vulnerabilities=[
            "resource_safety",
            "capability_leak",
            "module_reentrancy",
            "flash_loan_move",
            "object_safety",
            "access_control",
        ],
    ),
    Language.CAIRO: LanguageConfig(
        language=Language.CAIRO,
        file_extensions=[".cairo"],
        framework_markers={
            "Scarb.toml": "scarb",
            "protostar.toml": "protostar",
            "nile-config.json": "nile",
        },
        static_analyzers=["amarna", "caracal"],
        test_frameworks=["scarb", "protostar", "starknet-py"],
        common_vulnerabilities=[
            "felt_overflow",
            "storage_collision",
            "l1_l2_messaging",
            "access_control",
            "reentrancy",
            "uninitialized_storage",
        ],
    ),
}


def detect_language(project_path: Path) -> tuple[Language, Optional[str]]:
    """
    Detect the primary language and framework of a project.

    Returns:
        Tuple of (Language, framework_name or None)
    """
    if not project_path.exists():
        return Language.UNKNOWN, None

    # Check for framework markers first (more specific)
    for lang, config in LANGUAGE_CONFIGS.items():
        for marker, framework in config.framework_markers.items():
            if (project_path / marker).exists():
                return lang, framework

    # Fall back to file extension detection
    extension_counts = {}

    for config in LANGUAGE_CONFIGS.values():
        for ext in config.file_extensions:
            count = len(list(project_path.rglob(f"*{ext}")))
            if count > 0:
                extension_counts[config.language] = count

    if extension_counts:
        # Return language with most files
        primary = max(extension_counts, key=extension_counts.get)
        return primary, None

    return Language.UNKNOWN, None


def detect_blockchain(project_path: Path, language: Language) -> Blockchain:
    """
    Detect the target blockchain based on project structure.
    """
    if language == Language.SOLIDITY:
        # Could be any EVM chain - default to Ethereum
        # Could analyze imports for chain-specific stuff
        return Blockchain.ETHEREUM

    elif language == Language.RUST:
        # Check for Anchor (Solana)
        if (project_path / "Anchor.toml").exists():
            return Blockchain.SOLANA

        # Check Cargo.toml for CosmWasm
        cargo_toml = project_path / "Cargo.toml"
        if cargo_toml.exists():
            content = cargo_toml.read_text()
            if "cosmwasm" in content.lower():
                return Blockchain.COSMOS
            if "near-sdk" in content.lower():
                return Blockchain.NEAR
            if "solana" in content.lower() or "anchor" in content.lower():
                return Blockchain.SOLANA

    elif language == Language.MOVE:
        # Check for Aptos vs Sui
        if (project_path / "Aptos.toml").exists():
            return Blockchain.APTOS

        move_toml = project_path / "Move.toml"
        if move_toml.exists():
            content = move_toml.read_text()
            if "AptosFramework" in content:
                return Blockchain.APTOS
            if "Sui" in content or "sui" in content:
                return Blockchain.SUI

    elif language == Language.CAIRO:
        return Blockchain.STARKNET

    return Blockchain.UNKNOWN


@dataclass
class ProjectInfo:
    """Information about a detected project."""
    path: Path
    language: Language
    framework: Optional[str]
    blockchain: Blockchain
    config: LanguageConfig

    # Discovered files
    source_files: list[Path] = field(default_factory=list)
    test_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)


def analyze_project(project_path: Path) -> ProjectInfo:
    """
    Analyze a project and return comprehensive information.
    """
    path = Path(project_path)

    # Detect language and framework
    language, framework = detect_language(path)

    if language == Language.UNKNOWN:
        raise ValueError(f"Could not detect language for project: {path}")

    # Get config
    config = LANGUAGE_CONFIGS[language]

    # Detect blockchain
    blockchain = detect_blockchain(path, language)

    # Find source files
    source_files = []
    for ext in config.file_extensions:
        source_files.extend(path.rglob(f"*{ext}"))

    # Filter out test files
    test_patterns = ["test", "tests", "spec", "mock", "fixture"]
    real_source_files = []
    test_files = []

    for f in source_files:
        path_str = str(f).lower()
        if any(p in path_str for p in test_patterns):
            test_files.append(f)
        else:
            real_source_files.append(f)

    # Find config files
    config_files = list(path.glob("*.toml")) + list(path.glob("*.json")) + list(path.glob("*.yaml"))

    return ProjectInfo(
        path=path,
        language=language,
        framework=framework,
        blockchain=blockchain,
        config=config,
        source_files=real_source_files,
        test_files=test_files,
        config_files=config_files,
    )


class LanguageParser(ABC):
    """Abstract base class for language-specific parsers."""

    @property
    @abstractmethod
    def language(self) -> Language:
        """The language this parser handles."""
        pass

    @abstractmethod
    def parse_file(self, path: Path) -> dict:
        """Parse a source file and return structured data."""
        pass

    @abstractmethod
    def extract_functions(self, source: str) -> list[dict]:
        """Extract function information from source code."""
        pass

    @abstractmethod
    def extract_state(self, source: str) -> list[dict]:
        """Extract state/storage variables from source code."""
        pass

    @abstractmethod
    def find_external_calls(self, source: str) -> list[dict]:
        """Find external calls/CPIs/cross-contract calls."""
        pass


class LanguageAnalyzer(ABC):
    """Abstract base class for language-specific static analyzers."""

    @property
    @abstractmethod
    def language(self) -> Language:
        """The language this analyzer handles."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer tool."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the analyzer is installed."""
        pass

    @abstractmethod
    def run(self, project_path: Path) -> list[dict]:
        """Run analysis and return findings."""
        pass
