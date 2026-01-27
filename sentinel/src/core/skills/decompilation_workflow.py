"""
Decompilation Recovery Workflow - Based on SavantChat Methodology

Structured workflow for recovering Solidity source code from unverified
contract bytecode using AI-assisted decompilation.

Methodology:
1. Replay - Fork mainnet, replay attack/interaction TX with Foundry
2. Decompile - Load bytecode into Dedaub/Heimdall/Panoramix
3. Recover - AI agent converts pseudocode to Solidity (simple → complex)
4. Verify - Unit + fuzz tests on both bytecode and recovered code
5. Analyze - Identify vulnerabilities in recovered source

Key insight: "Security through obscurity no longer works. AI decompilation
is fully automated. Attackers can scan unverified contracts at industrial scale."

Source: SavantChat - $3.2M WBTC Hack Analysis (January 2026)
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class RecoveryPhase(Enum):
    REPLAY = "replay"
    DECOMPILE = "decompile"
    RECOVER = "recover"
    VERIFY = "verify"
    ANALYZE = "analyze"


class RecoveryStatus(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class RecoveredFunction:
    """A function recovered from bytecode."""
    selector: str           # 4-byte selector (e.g., "0x67b34120")
    decompiled_name: str    # Name from decompiler
    recovered_name: str     # Human-readable name
    visibility: str         # public, external, internal
    parameters: list[str]
    solidity_code: str = ""
    test_coverage: float = 0.0
    bytecode_equivalent: bool = False

    def to_markdown(self) -> str:
        status = "VERIFIED" if self.bytecode_equivalent else "UNVERIFIED"
        return (
            f"- **{self.recovered_name}** (`{self.selector}`) [{status}]\n"
            f"  - Visibility: {self.visibility}\n"
            f"  - Test coverage: {self.test_coverage:.0f}%\n"
            f"  - Bytecode equivalent: {'Yes' if self.bytecode_equivalent else 'No'}"
        )


@dataclass
class DecompilationReport:
    """Report of decompilation recovery process."""
    target_address: str
    chain: str
    block_number: int
    decompiler: str
    functions: list[RecoveredFunction]
    vulnerabilities: list[dict] = field(default_factory=list)
    phase: RecoveryPhase = RecoveryPhase.REPLAY
    status: RecoveryStatus = RecoveryStatus.NOT_STARTED

    @property
    def recovery_rate(self) -> float:
        if not self.functions:
            return 0.0
        verified = len([f for f in self.functions if f.bytecode_equivalent])
        return (verified / len(self.functions)) * 100

    def to_markdown(self) -> str:
        lines = [
            "# Decompilation Recovery Report",
            "",
            f"**Target**: `{self.target_address}`",
            f"**Chain**: {self.chain}",
            f"**Block**: {self.block_number}",
            f"**Decompiler**: {self.decompiler}",
            f"**Phase**: {self.phase.value}",
            f"**Recovery Rate**: {self.recovery_rate:.0f}%",
            "",
            "## Recovered Functions",
            "",
        ]
        for f in self.functions:
            lines.append(f.to_markdown())
            lines.append("")

        if self.vulnerabilities:
            lines.append("## Vulnerabilities Found")
            lines.append("")
            for v in self.vulnerabilities:
                lines.append(f"### [{v.get('severity', 'Unknown').upper()}] {v.get('title', 'Untitled')}")
                lines.append(f"- **Pattern**: {v.get('pattern', 'N/A')}")
                lines.append(f"- **Location**: {v.get('location', 'N/A')}")
                lines.append(f"- **Description**: {v.get('description', 'N/A')}")
                lines.append("")

        return "\n".join(lines)


# Known decompilation tools and their capabilities
DECOMPILERS = {
    "dedaub": {
        "name": "Dedaub Decompiler",
        "url": "https://app.dedaub.com/",
        "output": "Pseudocode with variable names (vargN, vN)",
        "strengths": "Best readability, handles complex patterns",
        "limitations": "Obfuscated names, sometimes misses struct packing",
    },
    "heimdall": {
        "name": "Heimdall",
        "url": "https://github.com/Jon-Becker/heimdall-rs",
        "output": "Solidity-like pseudocode",
        "strengths": "Open source, Rust-based, fast",
        "limitations": "Less readable than Dedaub for complex contracts",
    },
    "panoramix": {
        "name": "Panoramix",
        "url": "https://github.com/palkeo/panoramix",
        "output": "Python-like pseudocode",
        "strengths": "Good for simple contracts",
        "limitations": "Struggles with complex control flow",
    },
    "ethervm": {
        "name": "EtherVM",
        "url": "https://ethervm.io/decompile",
        "output": "Pseudocode",
        "strengths": "Web-based, quick access",
        "limitations": "Basic decompilation only",
    },
}

# Vulnerability patterns to check in recovered code
RECOVERY_VULN_PATTERNS = {
    "arbitrary_call": {
        "pattern": "address(user_input).call(user_data) without validation",
        "severity": "critical",
        "indicators": [
            "User-controlled address in .call() target",
            "User-controlled calldata",
            "No allowlist validation on target address",
            "Contract holds token approvals",
        ],
    },
    "unprotected_selfdestruct": {
        "pattern": "selfdestruct accessible without proper access control",
        "severity": "critical",
        "indicators": [
            "SELFDESTRUCT opcode reachable",
            "Missing owner/auth check on path to selfdestruct",
        ],
    },
    "delegatecall_to_user_address": {
        "pattern": "delegatecall to user-controlled address",
        "severity": "critical",
        "indicators": [
            "User input flows to delegatecall target",
            "No proxy pattern justifying delegatecall",
        ],
    },
    "unchecked_approval_drain": {
        "pattern": "Contract with approvals can be abused via arbitrary calls",
        "severity": "critical",
        "indicators": [
            "Contract receives token approvals from users",
            "Has functions that make external calls with user params",
            "Missing validation on call target/data",
        ],
    },
}


class DecompilationWorkflow:
    """
    AI-assisted decompilation and recovery workflow.

    Follows SavantChat methodology:
    1. Replay attack on local fork (Foundry)
    2. Decompile bytecode (Dedaub/Heimdall)
    3. Recover Solidity with AI (simple → complex, test each method)
    4. Verify equivalence (same tests pass on bytecode and recovered code)
    5. Analyze recovered source for vulnerabilities

    Recovery Strategy:
    - Start with constructor and simple view functions
    - Progress to complex state-changing functions
    - Each method verified against original bytecode
    - Fuzz tests ensure behavioral equivalence
    """

    def __init__(
        self,
        target_address: str,
        chain: str = "ethereum",
        block_number: int = 0,
        decompiler: str = "dedaub",
    ):
        self.report = DecompilationReport(
            target_address=target_address,
            chain=chain,
            block_number=block_number,
            decompiler=decompiler,
        )

    def generate_replay_commands(self, tx_hash: str = "", rpc_url: str = "$ETH_RPC") -> list[str]:
        """Generate Foundry commands for replaying transactions."""
        commands = [
            f"# Step 1: Fork mainnet at block before incident",
            f"forge test --fork-url {rpc_url} --fork-block-number {self.report.block_number}",
            "",
            f"# Fetch bytecode",
            f"cast code {self.report.target_address} --rpc-url {rpc_url} --block {self.report.block_number}",
            "",
            f"# Get storage layout",
            f"cast storage {self.report.target_address} --rpc-url {rpc_url} --block {self.report.block_number}",
        ]
        if tx_hash:
            commands.extend([
                "",
                f"# Replay specific transaction",
                f"cast run {tx_hash} --rpc-url {rpc_url}",
                "",
                f"# Get transaction trace",
                f"cast run {tx_hash} --rpc-url {rpc_url} --trace",
            ])
        return commands

    def generate_recovery_plan(self) -> list[dict]:
        """Generate ordered recovery plan (simple → complex)."""
        return [
            {"step": 1, "target": "Constructor", "difficulty": "easy",
             "notes": "Extract initialization params, storage layout"},
            {"step": 2, "target": "View functions", "difficulty": "easy",
             "notes": "Pure/view functions, getters, no state changes"},
            {"step": 3, "target": "Internal helpers", "difficulty": "medium",
             "notes": "Math, validation, utility functions"},
            {"step": 4, "target": "State-changing functions", "difficulty": "hard",
             "notes": "Core business logic, requires understanding state layout"},
            {"step": 5, "target": "External integrations", "difficulty": "hard",
             "notes": "Calls to other contracts, DEX interactions"},
            {"step": 6, "target": "Access control", "difficulty": "medium",
             "notes": "Owner/admin patterns, modifiers, role checks"},
        ]

    def add_recovered_function(self, func: RecoveredFunction):
        """Add a recovered function to the report."""
        self.report.functions.append(func)

    def check_vulnerability_patterns(self, recovered_code: str) -> list[dict]:
        """Check recovered code for known vulnerability patterns."""
        findings = []
        import re

        for name, pattern in RECOVERY_VULN_PATTERNS.items():
            # Simple pattern matching on recovered code
            if name == "arbitrary_call":
                if re.search(r"\.call\(", recovered_code) and not re.search(
                    r"(require|assert|allowlist|whitelist|approved)", recovered_code, re.IGNORECASE
                ):
                    findings.append({
                        "title": pattern["pattern"],
                        "severity": pattern["severity"],
                        "pattern": name,
                        "indicators": pattern["indicators"],
                    })

            elif name == "unprotected_selfdestruct":
                if re.search(r"selfdestruct\(", recovered_code, re.IGNORECASE):
                    findings.append({
                        "title": pattern["pattern"],
                        "severity": pattern["severity"],
                        "pattern": name,
                        "indicators": pattern["indicators"],
                    })

            elif name == "delegatecall_to_user_address":
                if re.search(r"delegatecall\(", recovered_code):
                    findings.append({
                        "title": pattern["pattern"],
                        "severity": pattern["severity"],
                        "pattern": name,
                        "indicators": pattern["indicators"],
                    })

        self.report.vulnerabilities.extend(findings)
        return findings

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate decompilation report."""
        report = self.report.to_markdown()
        if output_path:
            Path(output_path).write_text(report)
        return report


def create_decompilation_workflow(
    target_address: str,
    chain: str = "ethereum",
    block_number: int = 0,
    decompiler: str = "dedaub",
) -> DecompilationWorkflow:
    """Create a new decompilation recovery workflow."""
    return DecompilationWorkflow(target_address, chain, block_number, decompiler)
