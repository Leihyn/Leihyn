"""
Token Integration Analyzer - Trail of Bits Skill

Comprehensive token integration security analysis based on Trail of Bits'
token integration checklist. Checks for weird ERC20 patterns.

Based on: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path
import re


class TokenStandard(Enum):
    """Token standards."""
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    ERC777 = "erc777"


class RiskLevel(Enum):
    """Risk level for token patterns."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TokenPattern:
    """A weird token pattern to check for."""
    id: str
    name: str
    description: str
    risk_level: RiskLevel
    detection_pattern: str  # Regex or code pattern
    affected_tokens: list[str]  # Known affected tokens
    mitigation: str


@dataclass
class WeirdToken:
    """Detected weird token pattern."""
    pattern: TokenPattern
    file_path: str
    line_number: int
    code_snippet: str
    vulnerable_integration: bool  # Is the integration vulnerable?
    notes: str = ""

    def to_markdown(self) -> str:
        return f"""### [{self.pattern.risk_level.value.upper()}] {self.pattern.name}

**Pattern ID**: {self.pattern.id}
**Location**: `{self.file_path}:{self.line_number}`
**Vulnerable**: {'Yes' if self.vulnerable_integration else 'Potentially'}

**Description**: {self.pattern.description}

**Code**:
```solidity
{self.code_snippet}
```

**Known Affected Tokens**: {', '.join(self.pattern.affected_tokens)}

**Mitigation**: {self.pattern.mitigation}

{f'**Notes**: {self.notes}' if self.notes else ''}
"""


# Comprehensive list of weird ERC20 patterns from Trail of Bits
WEIRD_TOKEN_PATTERNS = [
    TokenPattern(
        id="WEIRD-001",
        name="Reentrant Calls (ERC777)",
        description="Token has hooks that can cause reentrancy on transfer",
        risk_level=RiskLevel.CRITICAL,
        detection_pattern=r"tokensToSend|tokensReceived|ERC777",
        affected_tokens=["ERC777 tokens", "imBTC", "WETH9"],
        mitigation="Use reentrancy guards on all token transfers",
    ),
    TokenPattern(
        id="WEIRD-002",
        name="Missing Return Values",
        description="Token doesn't return bool on transfer/approve (USDT pattern)",
        risk_level=RiskLevel.HIGH,
        detection_pattern=r"\.transfer\([^)]+\)\s*;|\.approve\([^)]+\)\s*;",
        affected_tokens=["USDT", "BNB", "OMG", "KNC"],
        mitigation="Use OpenZeppelin SafeERC20 wrapper",
    ),
    TokenPattern(
        id="WEIRD-003",
        name="Fee on Transfer",
        description="Token takes a fee on every transfer, received amount < sent amount",
        risk_level=RiskLevel.HIGH,
        detection_pattern=r"transferFrom.*amount\)",
        affected_tokens=["STA", "PAXG", "USDT (optional)"],
        mitigation="Calculate shares from balanceAfter - balanceBefore",
    ),
    TokenPattern(
        id="WEIRD-004",
        name="Balance Modifications Outside Transfers",
        description="Token balance can change without transfer (rebasing/yield-bearing)",
        risk_level=RiskLevel.HIGH,
        detection_pattern=r"balanceOf",
        affected_tokens=["Ampleforth (AMPL)", "stETH", "aTokens", "cTokens"],
        mitigation="Track shares instead of absolute balances",
    ),
    TokenPattern(
        id="WEIRD-005",
        name="Upgradeable Token",
        description="Token logic can be changed by admin",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"proxy|upgradeable|implementation",
        affected_tokens=["USDC", "USDT", "TUSD"],
        mitigation="Monitor for upgrades, have emergency procedures",
    ),
    TokenPattern(
        id="WEIRD-006",
        name="Flash Mintable",
        description="Token supply can temporarily increase via flash mint",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"flashMint|flashLoan",
        affected_tokens=["DAI", "WETH10"],
        mitigation="Don't rely on totalSupply for security checks",
    ),
    TokenPattern(
        id="WEIRD-007",
        name="Blocklist/Pausable",
        description="Token can block specific addresses or pause all transfers",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"blacklist|blocklist|pause|frozen",
        affected_tokens=["USDC", "USDT", "BUSD", "TUSD"],
        mitigation="Handle transfer failures gracefully",
    ),
    TokenPattern(
        id="WEIRD-008",
        name="Approval Race Protection",
        description="Token requires approval to be set to 0 before changing",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"require.*allowance.*==\s*0|safeApprove",
        affected_tokens=["USDT", "KNC"],
        mitigation="Use safeIncreaseAllowance/safeDecreaseAllowance",
    ),
    TokenPattern(
        id="WEIRD-009",
        name="Revert on Zero Transfer",
        description="Token reverts on zero-value transfers",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"require.*amount\s*>\s*0|revert.*zero",
        affected_tokens=["LEND"],
        mitigation="Check amount > 0 before transfer",
    ),
    TokenPattern(
        id="WEIRD-010",
        name="Revert on Zero Approval",
        description="Token reverts on zero-value approvals",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"approve.*require.*>\s*0",
        affected_tokens=["BNB"],
        mitigation="Check amount > 0 before approve",
    ),
    TokenPattern(
        id="WEIRD-011",
        name="Revert on Large Approval",
        description="Token reverts on approvals >= 2^96",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"type\(uint96\)\.max|2\*\*96",
        affected_tokens=["UNI", "COMP"],
        mitigation="Use type(uint96).max instead of type(uint256).max",
    ),
    TokenPattern(
        id="WEIRD-012",
        name="Non-String Metadata",
        description="Token name/symbol returns bytes32 instead of string",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"bytes32.*name|bytes32.*symbol",
        affected_tokens=["MKR", "SAI"],
        mitigation="Handle both string and bytes32 return types",
    ),
    TokenPattern(
        id="WEIRD-013",
        name="Low Decimals",
        description="Token has fewer than 18 decimals, precision issues",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"decimals.*[0-9]|DECIMALS.*[0-9]",
        affected_tokens=["USDC (6)", "USDT (6)", "WBTC (8)", "Gemini (2)"],
        mitigation="Normalize all token amounts to common precision",
    ),
    TokenPattern(
        id="WEIRD-014",
        name="High Decimals",
        description="Token has more than 18 decimals, overflow risk",
        risk_level=RiskLevel.MEDIUM,
        detection_pattern=r"decimals.*[2-9][0-9]|DECIMALS.*24",
        affected_tokens=["YAM-V2 (24)"],
        mitigation="Check for overflow in calculations",
    ),
    TokenPattern(
        id="WEIRD-015",
        name="Multiple Token Addresses",
        description="Token has multiple valid addresses (upgrades, migrations)",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"migrate|oldToken|newToken",
        affected_tokens=["SAI/DAI", "ANT v1/v2"],
        mitigation="Track canonical address, handle migrations",
    ),
    TokenPattern(
        id="WEIRD-016",
        name="Code Injection via Token Name",
        description="Token name/symbol contains executable code",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"<script|javascript:|data:",
        affected_tokens=["Malicious tokens"],
        mitigation="Sanitize token metadata before display",
    ),
    TokenPattern(
        id="WEIRD-017",
        name="Unusual Permit Function",
        description="Token has non-standard permit implementation",
        risk_level=RiskLevel.LOW,
        detection_pattern=r"permit\(|nonces\(",
        affected_tokens=["DAI (different params)", "RAI", "GLM"],
        mitigation="Check permit signature carefully per token",
    ),
    TokenPattern(
        id="WEIRD-018",
        name="Transfer Less Than Amount",
        description="Token transfers less than requested amount",
        risk_level=RiskLevel.HIGH,
        detection_pattern=r"transferFrom",
        affected_tokens=["cUSDCv3", "Compound v3 tokens"],
        mitigation="Check actual balance change, not amount parameter",
    ),
]


@dataclass
class TokenIntegrationReport:
    """Complete token integration analysis report."""
    project_name: str
    files_analyzed: list[str]
    token_standard: Optional[TokenStandard]
    is_implementation: bool  # True if implementing a token
    is_integration: bool  # True if integrating with tokens
    weird_tokens_found: list[WeirdToken]
    safe_patterns_used: list[str]
    missing_protections: list[str]

    def to_markdown(self) -> str:
        lines = [
            f"# Token Integration Analysis: {self.project_name}",
            "",
            "## Overview",
            "",
            f"- **Token Standard**: {self.token_standard.value if self.token_standard else 'Multiple/Unknown'}",
            f"- **Is Token Implementation**: {'Yes' if self.is_implementation else 'No'}",
            f"- **Is Token Integration**: {'Yes' if self.is_integration else 'No'}",
            f"- **Files Analyzed**: {len(self.files_analyzed)}",
            "",
            "## Weird Token Patterns Found",
            "",
            f"**Total**: {len(self.weird_tokens_found)}",
            "",
        ]

        # Group by risk level
        for risk in RiskLevel:
            findings = [w for w in self.weird_tokens_found if w.pattern.risk_level == risk]
            if findings:
                lines.append(f"### {risk.value.upper()} ({len(findings)})")
                lines.append("")
                for w in findings:
                    lines.append(w.to_markdown())
                    lines.append("---")
                    lines.append("")

        if self.safe_patterns_used:
            lines.append("## Safe Patterns Detected")
            lines.append("")
            for pattern in self.safe_patterns_used:
                lines.append(f"- {pattern}")
            lines.append("")

        if self.missing_protections:
            lines.append("## Missing Protections")
            lines.append("")
            for protection in self.missing_protections:
                lines.append(f"- {protection}")

        return "\n".join(lines)


class TokenIntegrationAnalyzer:
    """
    Analyze token integrations for security issues.

    Uses Trail of Bits' token integration checklist:
    1. General Considerations
    2. Contract Composition
    3. Owner Privileges
    4. ERC20 Conformity
    5. ERC20 Extension Risks
    6. Token Scarcity Analysis
    7. Weird ERC20 Patterns (24+ patterns)
    8. Token Integration Safety
    9. ERC721 Conformity
    10. ERC721 Common Risks
    """

    # Safe patterns to look for
    SAFE_PATTERNS = [
        (r"SafeERC20", "Using SafeERC20 for safe transfers"),
        (r"safeTransfer\(", "Using safeTransfer"),
        (r"safeTransferFrom\(", "Using safeTransferFrom"),
        (r"safeApprove\(|safeIncreaseAllowance\(", "Using safe approval methods"),
        (r"ReentrancyGuard|nonReentrant", "Using reentrancy protection"),
        (r"balanceOf.*before.*balanceOf.*after", "Checking balance change"),
    ]

    # Missing protections to flag
    REQUIRED_PROTECTIONS = [
        "SafeERC20 for external token calls",
        "Reentrancy guards for token callbacks",
        "Balance change verification for fee-on-transfer tokens",
        "Decimal normalization for mixed-decimal tokens",
    ]

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def analyze(self) -> TokenIntegrationReport:
        """Analyze project for token integration issues."""
        weird_tokens: list[WeirdToken] = []
        files_analyzed: list[str] = []
        safe_patterns: list[str] = []
        missing_protections: list[str] = []

        is_implementation = False
        is_integration = False
        token_standard = None

        # Find Solidity files
        for file_path in self.project_path.glob("**/*.sol"):
            if "test" in str(file_path).lower() or "mock" in str(file_path).lower():
                continue

            rel_path = str(file_path.relative_to(self.project_path))
            files_analyzed.append(rel_path)

            content = file_path.read_text()

            # Detect if this is a token implementation
            if re.search(r"ERC20|ERC721|ERC1155", content):
                if re.search(r"is\s+ERC20|contract\s+\w+Token", content):
                    is_implementation = True
                    token_standard = TokenStandard.ERC20

            # Detect if this integrates with tokens
            if re.search(r"IERC20|transferFrom|safeTransferFrom", content):
                is_integration = True

            # Check for weird patterns
            for pattern in WEIRD_TOKEN_PATTERNS:
                if re.search(pattern.detection_pattern, content, re.IGNORECASE):
                    # Find line number
                    match = re.search(pattern.detection_pattern, content, re.IGNORECASE)
                    if match:
                        line_num = content[:match.start()].count('\n') + 1
                        snippet = self._get_context(content, match.start())

                        # Check if protection is in place
                        vulnerable = not any(
                            re.search(safe[0], content) for safe in self.SAFE_PATTERNS
                        )

                        weird_tokens.append(WeirdToken(
                            pattern=pattern,
                            file_path=rel_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            vulnerable_integration=vulnerable,
                        ))

            # Check for safe patterns
            for pattern, description in self.SAFE_PATTERNS:
                if re.search(pattern, content):
                    if description not in safe_patterns:
                        safe_patterns.append(description)

        # Check for missing protections
        all_content = "\n".join(
            (self.project_path / f).read_text() for f in files_analyzed
        ) if files_analyzed else ""

        if is_integration:
            if not re.search(r"SafeERC20", all_content):
                missing_protections.append("SafeERC20 wrapper not used")
            if not re.search(r"ReentrancyGuard|nonReentrant", all_content):
                missing_protections.append("No reentrancy protection found")
            if not re.search(r"balanceOf.*before|before.*balanceOf", all_content, re.IGNORECASE):
                missing_protections.append("No balance change verification")

        return TokenIntegrationReport(
            project_name=self.project_path.name,
            files_analyzed=files_analyzed,
            token_standard=token_standard,
            is_implementation=is_implementation,
            is_integration=is_integration,
            weird_tokens_found=weird_tokens,
            safe_patterns_used=safe_patterns,
            missing_protections=missing_protections,
        )

    def _get_context(self, content: str, pos: int, lines: int = 5) -> str:
        """Get code context around a position."""
        start = content.rfind('\n', 0, pos)
        for _ in range(lines - 1):
            new_start = content.rfind('\n', 0, start)
            if new_start == -1:
                break
            start = new_start

        end = content.find('\n', pos)
        for _ in range(lines - 1):
            new_end = content.find('\n', end + 1)
            if new_end == -1:
                break
            end = new_end

        return content[start:end].strip()


def analyze_token_integration(
    project_path: str,
    output_path: Optional[str] = None,
) -> TokenIntegrationReport:
    """
    Analyze token integration security.

    Args:
        project_path: Path to project root
        output_path: Optional path for markdown report

    Returns:
        TokenIntegrationReport with findings
    """
    analyzer = TokenIntegrationAnalyzer(project_path)
    report = analyzer.analyze()

    if output_path:
        Path(output_path).write_text(report.to_markdown())

    return report
