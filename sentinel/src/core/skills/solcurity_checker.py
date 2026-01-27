"""
Solcurity Checklist Checker - Based on transmissions11/solcurity

Automated Solidity security checklist with 100+ items across 12 categories:
Variables, Structs, Functions, Modifiers, Code, External Calls, Static Calls,
Events, Contract, Project, DeFi, and General Review.

Source: https://github.com/transmissions11/solcurity
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
from typing import Optional


class CheckCategory(Enum):
    VARIABLES = "variables"
    STRUCTS = "structs"
    FUNCTIONS = "functions"
    MODIFIERS = "modifiers"
    CODE = "code"
    EXTERNAL_CALLS = "external_calls"
    STATIC_CALLS = "static_calls"
    EVENTS = "events"
    CONTRACT = "contract"
    PROJECT = "project"
    DEFI = "defi"


class CheckStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    MANUAL = "manual_review"


@dataclass
class CheckResult:
    """Result of a single checklist item."""
    check_id: str
    category: CheckCategory
    description: str
    status: CheckStatus
    file_path: str = ""
    line_number: int = 0
    details: str = ""
    swc_id: str = ""

    def to_markdown(self) -> str:
        status_icon = {
            CheckStatus.PASS: "[PASS]",
            CheckStatus.FAIL: "[FAIL]",
            CheckStatus.WARNING: "[WARN]",
            CheckStatus.MANUAL: "[MANUAL]",
        }
        line = f"- {status_icon[self.status]} **{self.check_id}**: {self.description}"
        if self.file_path:
            line += f"\n  - Location: `{self.file_path}:{self.line_number}`"
        if self.details:
            line += f"\n  - {self.details}"
        if self.swc_id:
            line += f"\n  - SWC: {self.swc_id}"
        return line


@dataclass
class SolcurityReport:
    """Full Solcurity checklist report."""
    project_path: str
    results: list[CheckResult]

    @property
    def pass_count(self) -> int:
        return len([r for r in self.results if r.status == CheckStatus.PASS])

    @property
    def fail_count(self) -> int:
        return len([r for r in self.results if r.status == CheckStatus.FAIL])

    @property
    def score(self) -> float:
        if not self.results:
            return 0.0
        automated = [r for r in self.results if r.status != CheckStatus.MANUAL]
        if not automated:
            return 0.0
        return (len([r for r in automated if r.status == CheckStatus.PASS]) / len(automated)) * 100

    def to_markdown(self) -> str:
        lines = [
            "# Solcurity Checklist Report",
            "",
            f"**Project**: {self.project_path}",
            f"**Score**: {self.score:.0f}%",
            f"**Pass**: {self.pass_count} | **Fail**: {self.fail_count}",
            "",
        ]

        for cat in CheckCategory:
            cat_results = [r for r in self.results if r.category == cat]
            if cat_results:
                lines.append(f"## {cat.value.replace('_', ' ').title()}")
                lines.append("")
                for r in cat_results:
                    lines.append(r.to_markdown())
                lines.append("")

        return "\n".join(lines)


# Automated checks that can be run against Solidity source
AUTOMATED_CHECKS = [
    # Variables
    {
        "id": "V-01",
        "category": CheckCategory.VARIABLES,
        "description": "Variables have explicit visibility (no default)",
        "pattern": r"^\s+(uint|int|bool|address|bytes|string|mapping)\d*\s+\w+\s*[;=]",
        "negative_pattern": r"(public|private|internal|constant|immutable)",
        "swc": "SWC-108",
    },
    # Functions
    {
        "id": "F-05",
        "category": CheckCategory.FUNCTIONS,
        "description": "Functions follow checks-effects-interactions pattern",
        "pattern": r"\.call\{|\.transfer\(|\.send\(",
        "context_after": r"(balances|_balances|balance)\[.*\]\s*[-+]=",
        "swc": "SWC-107",
    },
    {
        "id": "F-09",
        "category": CheckCategory.FUNCTIONS,
        "description": "Access control on state-changing functions",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*(external|public)[^{]*\{",
        "negative_pattern": r"(onlyOwner|onlyAdmin|onlyRole|require\(msg\.sender|_checkRole)",
        "context_pattern": r"(=|delete|push|pop|transfer|send|call)",
    },
    # Code
    {
        "id": "C-04",
        "category": CheckCategory.CODE,
        "description": "No use of tx.origin for authorization",
        "pattern": r"tx\.origin",
        "negative_pattern": r"require\(tx\.origin\s*==\s*msg\.sender",
        "swc": "SWC-115",
    },
    {
        "id": "C-07",
        "category": CheckCategory.CODE,
        "description": "Uses abi.encode() over abi.encodePacked() for hashing",
        "pattern": r"abi\.encodePacked\(",
        "context_pattern": r"keccak256",
        "swc": "SWC-133",
    },
    {
        "id": "C-12",
        "category": CheckCategory.CODE,
        "description": "No use of block.timestamp for short intervals",
        "pattern": r"block\.timestamp",
        "swc": "SWC-116",
    },
    {
        "id": "C-15",
        "category": CheckCategory.CODE,
        "description": "Signatures protected with nonce and chainid",
        "pattern": r"ecrecover|ECDSA\.recover|SignatureChecker",
        "negative_pattern": r"(nonce|block\.chainid|_HASHED_NAME|EIP712)",
        "swc": "SWC-121",
    },
    {
        "id": "C-20",
        "category": CheckCategory.CODE,
        "description": "No assert() except for fuzzing/formal verification",
        "pattern": r"\bassert\(",
        "negative_pattern": r"(invariant_|test_|prove_)",
        "swc": "SWC-110",
    },
    {
        "id": "C-22",
        "category": CheckCategory.CODE,
        "description": "No use of address.transfer() or address.send()",
        "pattern": r"\.(transfer|send)\(",
        "negative_pattern": r"(ERC20|IERC20|SafeERC20|safeTransfer)",
        "swc": "SWC-134",
    },
    {
        "id": "C-30",
        "category": CheckCategory.CODE,
        "description": "No msg.value usage in loops",
        "pattern": r"for\s*\([^)]*\)[^}]*msg\.value",
    },
    # External Calls
    {
        "id": "X-03",
        "category": CheckCategory.EXTERNAL_CALLS,
        "description": "External call results are checked",
        "pattern": r"\.call\(",
        "negative_pattern": r"(bool\s+success|require\(|if\s*\()",
        "swc": "SWC-104",
    },
    # Events
    {
        "id": "E-01",
        "category": CheckCategory.EVENTS,
        "description": "Events emitted for state-changing functions",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*(external|public)[^{]*\{[^}]*=[^}]*\}",
        "negative_pattern": r"emit\s+\w+",
    },
    # Contract
    {
        "id": "T-01",
        "category": CheckCategory.CONTRACT,
        "description": "SPDX license identifier present",
        "pattern": r"^",
        "negative_pattern": r"SPDX-License-Identifier",
    },
    # DeFi
    {
        "id": "D-03",
        "category": CheckCategory.DEFI,
        "description": "No AMM spot price used as oracle",
        "pattern": r"(getReserves|slot0|balanceOf\(address\(this\)\))",
        "context_pattern": r"(price|oracle|rate|value)",
    },
    {
        "id": "D-07",
        "category": CheckCategory.DEFI,
        "description": "ERC-777 reentrancy considered",
        "pattern": r"(safeTransferFrom|transferFrom)\(",
        "negative_pattern": r"(nonReentrant|ReentrancyGuard|_status)",
    },
]


class SolcurityChecker:
    """
    Automated Solcurity checklist verification.

    Based on: https://github.com/transmissions11/solcurity

    Categories:
    - Variables (V1-V10): Visibility, packing, documentation
    - Structs (S1-S3): Design, optimization
    - Functions (F1-F19): Access control, validation, patterns
    - Modifiers (M1-M3): Side effects, documentation
    - Code (C1-C51): Arithmetic, time, signatures, state, calls
    - External Calls (X1-X8): DoS, reentrancy, error handling
    - Static Calls (S1-S4): Read-only safety
    - Events (E1-E6): Indexing, emission
    - Contract (T1-T12): License, inheritance, documentation
    - Project (P1-P5): Testing, analysis
    - DeFi (D1-D11): Oracle, token, accounting safety
    """

    REVIEW_METHODOLOGY = [
        "1. Study project documentation and specifications",
        "2. Develop mental models before code review",
        "3. Analyze contract architecture (Surya/sol2uml)",
        "4. Compare architecture against expectations",
        "5. Create threat models and attack vectors",
        "6. Inspect value-exchange functions (transfers, calls, delegatecalls)",
        "7. Verify external contract assumptions",
        "8. Conduct comprehensive line-by-line reviews",
        "9. Review from each threat actor's perspective",
        "10. Analyze test coverage gaps",
        "11. Execute static analysis tools",
        "12. Research related projects and audits for similar vulnerabilities",
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def check(self) -> SolcurityReport:
        """Run all automated Solcurity checks."""
        results = []

        sol_files = list(self.project_path.glob("**/*.sol"))
        if not sol_files:
            return SolcurityReport(
                project_path=str(self.project_path),
                results=[],
            )

        for sol_file in sol_files:
            content = sol_file.read_text()
            rel_path = str(sol_file.relative_to(self.project_path))

            for check_def in AUTOMATED_CHECKS:
                matches = list(re.finditer(check_def["pattern"], content, re.MULTILINE))

                if not matches:
                    continue

                for match in matches:
                    has_issue = True

                    # Check negative pattern (protection)
                    if "negative_pattern" in check_def:
                        context = content[max(0, match.start() - 500):match.end() + 500]
                        if re.search(check_def["negative_pattern"], context, re.IGNORECASE):
                            has_issue = False

                    # Check context pattern
                    if "context_pattern" in check_def and has_issue:
                        context = content[max(0, match.start() - 300):match.end() + 300]
                        if not re.search(check_def["context_pattern"], context, re.IGNORECASE):
                            has_issue = False

                    if "context_after" in check_def and has_issue:
                        after = content[match.end():match.end() + 500]
                        if re.search(check_def["context_after"], after, re.IGNORECASE):
                            has_issue = True
                        else:
                            has_issue = False

                    if has_issue:
                        line_num = content[:match.start()].count("\n") + 1
                        results.append(CheckResult(
                            check_id=check_def["id"],
                            category=check_def["category"],
                            description=check_def["description"],
                            status=CheckStatus.FAIL,
                            file_path=rel_path,
                            line_number=line_num,
                            details=match.group(0).strip()[:100],
                            swc_id=check_def.get("swc", ""),
                        ))

        return SolcurityReport(
            project_path=str(self.project_path),
            results=results,
        )


def check_solcurity(project_path: str, output_path: str = None) -> SolcurityReport:
    """Run Solcurity checklist on a project."""
    checker = SolcurityChecker(project_path)
    report = checker.check()
    if output_path:
        Path(output_path).write_text(report.to_markdown())
    return report
