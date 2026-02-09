"""
Known Bug Replay Hunter - Replays 14 high-signal bug classes from real audits.

Database of battle-tested bug patterns from Code4rena and Sherlock Medium/High
findings. Two-stage detection: fast regex pre-filter (cheap) followed by LLM
verification (only on matches). Catches first-depositor attacks, donation attacks,
unsafe casts, read-only reentrancy, and more.

Why this works: these 14 patterns account for ~40% of all M/H findings in real
audit contests. The regex pre-filter costs nothing, and LLM verification only
fires on actual matches -- so the total cost is proportional to real bugs found.

Supports: Primarily Solidity (regex patterns are Solidity-focused)
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


@dataclass
class BugClass:
    """A known bug class from real audit findings."""
    name: str
    severity: str  # "High" or "Medium"
    vulnerability_type: VulnerabilityType
    description: str
    regex_patterns: list[str]
    false_positive_checks: list[str]
    verification_prompt: str
    references: list[str]


def _get_bug_classes() -> list[BugClass]:
    """Return the 14 hardcoded bug classes."""
    return [
        # 0: First Depositor / Share Inflation
        BugClass(
            name="First Depositor / Share Inflation",
            severity="High",
            vulnerability_type=VulnerabilityType.FIRST_DEPOSITOR,
            description=(
                "First depositor can manipulate share price by depositing a tiny amount "
                "then donating tokens directly, inflating the share price so subsequent "
                "depositors receive 0 shares due to rounding."
            ),
            regex_patterns=[
                r"totalSupply\s*[=<>!]+\s*0",
                r"ERC4626",
                r"totalAssets\s*\(\)",
                r"previewDeposit",
                r"convertToShares",
                r"_mint\s*\([^,]+,\s*[^)]*(?:assets|amount|deposit)",
            ],
            false_positive_checks=[
                r"_initialDeposit",
                r"MINIMUM_LIQUIDITY",
                r"_MIN_DEPOSIT",
                r"virtual\s+shares",
                r"OFFSET",
            ],
            verification_prompt=(
                "Does this contract implement an ERC4626-style vault or share-based system "
                "where the first depositor can manipulate the exchange rate? Look for: "
                "(1) share minting proportional to totalSupply, (2) no minimum deposit or "
                "virtual offset, (3) ability to donate tokens directly to the contract. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["ERC4626 inflation attack", "OpenZeppelin virtual shares"],
        ),
        # 1: Donation Attack
        BugClass(
            name="Donation Attack",
            severity="High",
            vulnerability_type=VulnerabilityType.DONATION_ATTACK,
            description=(
                "Contract uses balanceOf(address(this)) for pricing or accounting. "
                "An attacker can donate tokens directly to manipulate these calculations."
            ),
            regex_patterns=[
                r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
                r"\.balance\b(?!Of)",
                r"getReserves.*balanceOf",
            ],
            false_positive_checks=[
                r"skim\s*\(",
                r"sync\s*\(",
                r"_update\s*\(",
                r"lastBalance",
                r"trackedBalance",
            ],
            verification_prompt=(
                "Does this contract use balanceOf(address(this)) in a pricing or "
                "accounting calculation where an attacker could donate tokens to "
                "manipulate the result? Check if: (1) the balance is used in share "
                "calculations, price computations, or reserve tracking, (2) there's no "
                "internal balance tracking that ignores donations. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Compound cToken donation", "Balancer pool donation"],
        ),
        # 2: Unsafe Narrowing Cast
        BugClass(
            name="Unsafe Narrowing Cast",
            severity="High",
            vulnerability_type=VulnerabilityType.UNSAFE_CASTING,
            description=(
                "Casting to a smaller type (uint128, uint96, int128, etc.) without "
                "checking if the value fits. Silently truncates, causing incorrect "
                "balances, prices, or timestamps."
            ),
            regex_patterns=[
                r"uint128\s*\(",
                r"uint96\s*\(",
                r"uint64\s*\(",
                r"uint32\s*\(",
                r"int128\s*\(",
                r"int96\s*\(",
            ],
            false_positive_checks=[
                r"SafeCast",
                r"safeCast",
                r"toUint128",
                r"toUint96",
                r"require\s*\([^;]*<\s*type\s*\(",
            ],
            verification_prompt=(
                "Does this code perform a narrowing cast (e.g., uint256 to uint128) "
                "without using SafeCast or checking bounds? Look for: (1) values that "
                "could realistically exceed the target type's max, (2) no prior require "
                "or assert checking the value fits. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Uniswap V3 unsafe cast bugs", "EIP-2098 signature truncation"],
        ),
        # 3: Read-Only Reentrancy
        BugClass(
            name="Read-Only Reentrancy",
            severity="High",
            vulnerability_type=VulnerabilityType.REENTRANCY_READ_ONLY,
            description=(
                "A view function returns stale data during an external call's callback. "
                "Attacker re-enters through a view to get a price based on mid-update state."
            ),
            regex_patterns=[
                r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s+view",
                r"\.call\{",
                r"\.transfer\(",
                r"_burn\s*\([^)]*\)\s*;[^}]*\.call",
            ],
            false_positive_checks=[
                r"nonReentrant",
                r"ReentrancyGuard",
                r"_reentrancyGuard",
                r"lock\s+modifier",
            ],
            verification_prompt=(
                "Is there a view/pure function that reads contract state which could be "
                "stale during an external call? Look for: (1) a state-changing function "
                "that makes an external call (ETH transfer, token callback, etc.), "
                "(2) a view function that reads the same state that's mid-update, "
                "(3) the view is used by an external protocol for pricing. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Curve read-only reentrancy", "Balancer pool reentrancy"],
        ),
        # 4: Uninitialized Proxy
        BugClass(
            name="Uninitialized Proxy",
            severity="High",
            vulnerability_type=VulnerabilityType.UNINITIALIZED_PROXY,
            description=(
                "Implementation contract doesn't call _disableInitializers() in its "
                "constructor. Attacker can initialize the implementation directly and "
                "potentially selfdestruct it, bricking all proxies."
            ),
            regex_patterns=[
                r"function\s+initialize\s*\(",
                r"initializer\b",
                r"Initializable",
                r"UUPSUpgradeable",
                r"TransparentUpgradeableProxy",
            ],
            false_positive_checks=[
                r"_disableInitializers\s*\(\s*\)",
                r"constructor\s*\([^)]*\)\s*[^{]*\{[^}]*_disableInitializers",
            ],
            verification_prompt=(
                "Does this upgradeable contract's implementation call "
                "_disableInitializers() in its constructor? Without this, an attacker "
                "can call initialize() on the implementation directly. Check: "
                "(1) is there a constructor that calls _disableInitializers()? "
                "(2) or is the initializer modifier properly gated? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Wormhole uninitialized proxy", "Audius governance attack"],
        ),
        # 5: Flash Loan Price Manipulation
        BugClass(
            name="Flash Loan Price Manipulation",
            severity="High",
            vulnerability_type=VulnerabilityType.FLASH_LOAN,
            description=(
                "Contract uses spot balanceOf or reserves for pricing without TWAP "
                "or oracle protection. Attacker can flash-loan to manipulate the "
                "instantaneous price within a single transaction."
            ),
            regex_patterns=[
                r"balanceOf\s*\([^)]*\)\s*[*/]",
                r"getReserves\s*\(\s*\)\s*;",
                r"reserve[01]\s*[*/]",
                r"slot0\s*\(\s*\)",
            ],
            false_positive_checks=[
                r"[Tt][Ww][Aa][Pp]",
                r"observe\s*\(",
                r"consult\s*\(",
                r"latestRoundData",
                r"getPrice.*[Oo]racle",
            ],
            verification_prompt=(
                "Does this contract use a spot price (balanceOf, getReserves, slot0) "
                "for a critical calculation without TWAP or oracle protection? "
                "Check: (1) is the price used for lending, liquidation, or swaps? "
                "(2) is there ANY time-weighted or oracle-based price check? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["bZx flash loan", "Harvest Finance attack"],
        ),
        # 6: Missing Health Check After State Change
        BugClass(
            name="Missing Health Check After State Change",
            severity="High",
            vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
            description=(
                "A function modifies reserves, collateral, or debt without re-checking "
                "the health factor / invariant afterwards. Donation or direct transfer "
                "can put the protocol in an unhealthy state."
            ),
            regex_patterns=[
                r"reserve[s]?\s*[+-]=",
                r"totalBorrow[s]?\s*[+-]=",
                r"collateral\s*[+-]=",
                r"_updateReserve",
                r"donate\s*\(",
            ],
            false_positive_checks=[
                r"_accrueInterest.*healthFactor",
                r"require\s*\([^;]*health",
                r"_checkHealth",
                r"isHealthy\s*\(",
            ],
            verification_prompt=(
                "After this state modification (reserve/collateral/debt change), "
                "is there a health check that ensures the protocol remains solvent? "
                "Look for: (1) missing healthFactor/collateralRatio check after update, "
                "(2) direct reserve manipulation without validation. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Aave health factor bypass", "Compound reserve manipulation"],
        ),
        # 7: Division Before Multiplication
        BugClass(
            name="Division Before Multiplication",
            severity="Medium",
            vulnerability_type=VulnerabilityType.PRECISION_LOSS,
            description=(
                "Performing division before multiplication causes precision loss. "
                "In Solidity, integer division truncates, so (a / b) * c loses the "
                "remainder of a/b, while (a * c) / b preserves it."
            ),
            regex_patterns=[
                r"\w+\s*/\s*\w+\s*\)\s*\*\s*\w+",
                r"\w+\s*/\s*\w+\s*\*\s*\w+",
            ],
            false_positive_checks=[
                r"FullMath",
                r"mulDiv",
                r"PRBMath",
                r"FixedPointMathLib",
            ],
            verification_prompt=(
                "Does this code perform division before multiplication in a way that "
                "causes meaningful precision loss? Check: (1) is the division result "
                "used in further multiplication? (2) could reordering to multiply first "
                "preserve value? (3) is this in a critical path (fee calculation, share "
                "pricing, interest accrual)? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Solidity precision loss patterns"],
        ),
        # 8: Fee-On-Transfer Token Not Handled
        BugClass(
            name="Fee-On-Transfer Token Not Handled",
            severity="Medium",
            vulnerability_type=VulnerabilityType.FEE_ON_TRANSFER,
            description=(
                "Contract calls transferFrom then uses the original amount for "
                "accounting, not the actual received amount. Fee-on-transfer tokens "
                "deliver less than requested, creating a deficit."
            ),
            regex_patterns=[
                r"transferFrom\s*\([^;]+;\s*\n\s*\w+\s*[+-]=\s*(?:amount|_amount|value)",
                r"safeTransferFrom\s*\([^;]+;\s*\n\s*\w+\s*[+-]=",
                r"transferFrom.*amount\)",
            ],
            false_positive_checks=[
                r"balanceOf.*before.*after",
                r"balanceBefore.*balanceAfter",
                r"_receivedAmount",
                r"received\s*=\s*balanceOf",
            ],
            verification_prompt=(
                "After calling transferFrom, does this code use the original amount "
                "parameter for accounting instead of measuring the actual received "
                "amount? Look for: (1) transferFrom(from, to, amount) followed by "
                "balance += amount, (2) no before/after balance check. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["USDT fee-on-transfer", "STA token deflationary issues"],
        ),
        # 9: Rebasing Token Breaks Accounting
        BugClass(
            name="Rebasing Token Breaks Accounting",
            severity="Medium",
            vulnerability_type=VulnerabilityType.REBASING_TOKEN,
            description=(
                "Contract stores token balances in a mapping but interacts with "
                "rebasing tokens (stETH, AMPL, etc.) whose balances change without "
                "transfers. Stored balance diverges from actual balance."
            ),
            regex_patterns=[
                r"mapping\s*\([^)]*=>\s*uint256\s*\)\s*(?:public|private|internal)?\s*balance",
                r"balances\s*\[",
                r"userBalance\s*\[",
                r"deposits\s*\[",
            ],
            false_positive_checks=[
                r"wstETH",
                r"wrap\s*\(",
                r"shares\s*\[",
                r"_shareBalance",
            ],
            verification_prompt=(
                "Does this contract store token amounts in a mapping that could diverge "
                "from actual balances if a rebasing token is used? Check: (1) is there "
                "a balance mapping updated only on deposit/withdraw? (2) could the "
                "protocol accept rebasing tokens (stETH, AMPL)? (3) is there share-based "
                "accounting instead? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Lido stETH rebasing", "AMPL integration issues"],
        ),
        # 10: Rounding In Wrong Direction
        BugClass(
            name="Rounding In Wrong Direction",
            severity="Medium",
            vulnerability_type=VulnerabilityType.ROUNDING_ERROR,
            description=(
                "Share/amount conversions round in favor of the user instead of the "
                "protocol. Over many operations, this drains the protocol. Deposits "
                "should round down (fewer shares), withdrawals should round up "
                "(more shares burned)."
            ),
            regex_patterns=[
                r"shares\s*=\s*\w+\s*\*\s*\w+\s*/\s*\w+",
                r"assets\s*=\s*\w+\s*\*\s*\w+\s*/\s*\w+",
                r"convertToShares",
                r"convertToAssets",
                r"previewRedeem",
                r"previewWithdraw",
            ],
            false_positive_checks=[
                r"[Mm]ulDiv[Uu]p",
                r"ceilDiv",
                r"roundUp",
                r"Math\.Rounding\.(Up|Ceil)",
            ],
            verification_prompt=(
                "Does this share/amount conversion round in the correct direction? "
                "Protocol safety requires: deposits -> round DOWN shares (user gets fewer), "
                "withdrawals -> round UP shares burned (user burns more). "
                "Check: (1) which direction does the division truncate? "
                "(2) is there a ceilDiv/mulDivUp for the withdrawal path? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["ERC4626 rounding", "OpenZeppelin Math.Rounding"],
        ),
        # 11: Missing Deadline In Swap
        BugClass(
            name="Missing Deadline In Swap",
            severity="Medium",
            vulnerability_type=VulnerabilityType.MISSING_DEADLINE,
            description=(
                "Swap call passes block.timestamp as deadline (always passes) or omits "
                "deadline entirely. Transactions can be held in mempool and executed "
                "at a worse price."
            ),
            regex_patterns=[
                r"deadline\s*:\s*block\.timestamp",
                r"block\.timestamp\s*\+?\s*\d*\s*[,)].*(?:swap|exact)",
                r"(?:swap|exactInput|exactOutput).*deadline",
            ],
            false_positive_checks=[
                r"deadline\s*[><=!]+\s*block\.timestamp",
                r"require\s*\([^;]*deadline",
                r"_checkDeadline",
            ],
            verification_prompt=(
                "Does this swap call use block.timestamp as the deadline (which always "
                "passes and provides no protection)? Or is the deadline parameter missing? "
                "A proper deadline should be a user-supplied future timestamp. "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["Uniswap deadline parameter", "MEV sandwich attacks"],
        ),
        # 12: Unbounded Loop DoS
        BugClass(
            name="Unbounded Loop DoS",
            severity="Medium",
            vulnerability_type=VulnerabilityType.UNBOUNDED_LOOP,
            description=(
                "Loop iterates over a user-growable array without a max bound. "
                "An attacker can grow the array until the loop exceeds the block gas "
                "limit, permanently DoS-ing the function."
            ),
            regex_patterns=[
                r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length",
                r"for\s*\([^)]*\.length\s*[;)]",
                r"while\s*\(\s*\w+\s*<\s*\w+\.length",
            ],
            false_positive_checks=[
                r"MAX_",
                r"maxLength",
                r"require\s*\([^;]*\.length\s*<",
                r"if\s*\([^;]*\.length\s*>",
            ],
            verification_prompt=(
                "Does this loop iterate over an array whose length can grow unboundedly "
                "via user action? Check: (1) can users push to this array? (2) is there "
                "a MAX_LENGTH or similar cap? (3) could the loop exceed block gas limit? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["GovernorBravo proposal DoS", "Airdrop claim loops"],
        ),
        # 13: Incorrect EIP-712 Domain Separator
        BugClass(
            name="Incorrect EIP-712 Domain Separator",
            severity="Medium",
            vulnerability_type=VulnerabilityType.MISSING_CHAIN_ID,
            description=(
                "EIP-712 domain separator is cached at deployment but doesn't recompute "
                "on chain ID change (hard fork). Signatures from one chain become valid "
                "on the other."
            ),
            regex_patterns=[
                r"DOMAIN_SEPARATOR",
                r"_domainSeparator",
                r"keccak256.*EIP712Domain",
                r"immutable.*[Dd]omain",
            ],
            false_positive_checks=[
                r"block\.chainid\s*!=\s*_?INITIAL_CHAIN_ID",
                r"_domainSeparatorV4",
                r"EIP712\(",
                r"if\s*\([^)]*chainid",
            ],
            verification_prompt=(
                "Does this EIP-712 implementation cache the domain separator without "
                "checking if the chain ID has changed? A hard fork would make signatures "
                "from one chain valid on the other. Check: (1) is DOMAIN_SEPARATOR "
                "computed once and stored as immutable? (2) is there a chain ID check "
                "to recompute it? "
                "Is it VULNERABLE or NOT_VULNERABLE?"
            ),
            references=["EIP-712 replay after fork", "Solmate EIP-712"],
        ),
    ]


SYSTEM_PROMPT = """You are a vulnerability hunter who replays known bug patterns from real audit findings.

You have a database of 14 high-signal bug classes from Code4rena and Sherlock Medium/High findings.
For each contract, you systematically scan for ALL 14 bug classes using regex pre-filters,
then verify matches with deeper analysis.

## Process
1. List all contracts in scope
2. For each contract, scan ALL 14 bug classes with `scan_bug_class`
3. For any matches, verify with `verify_match` to eliminate false positives
4. Report confirmed findings with `report_finding`

## Rules
- Be SYSTEMATIC: scan every contract against every bug class
- Do NOT skip bug classes -- the regex is cheap
- Only use `verify_match` when `scan_bug_class` returns matches
- Report with confidence 0.85 if LLM-verified, 0.6 if regex-only
- Include the specific lines and context in findings"""


class KnownBugReplayHunter(AnalysisAgent):
    """
    Replays 14 known bug classes from real C4/Sherlock M/H findings.

    Two-stage detection: fast regex pre-filter (nearly free) then LLM
    verification (only on matches). Catches the bug patterns that account
    for ~40% of real Medium/High findings in audit contests.
    """

    role = "hunter"
    name = "known_bug_replay"
    description = "Scans for 14 known high-signal bug patterns from real audit findings"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    @staticmethod
    def _get_bug_classes() -> list[BugClass]:
        """Get all bug classes (static method for external inspection)."""
        return _get_bug_classes()

    def __init__(self, state: AuditState, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        super().__init__(state=state, **kwargs)
        self.findings = []
        self.bug_classes = _get_bug_classes()
        self.tools = self._build_tools()

    def _build_tools(self) -> list[Tool]:
        """Build tools for known bug replay."""
        bug_names = [f"{i}: {bc.name} ({bc.severity})" for i, bc in enumerate(self.bug_classes)]

        return [
            Tool(
                name="read_file",
                description="Read a source code file from the target project",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="list_contracts",
                description="List all contracts found during recon with their functions and state variables",
                input_schema={"type": "object", "properties": {}},
                handler=self._list_contracts,
            ),
            Tool(
                name="scan_bug_class",
                description=(
                    "Run regex pre-filter for one bug class against one contract's source. "
                    "Returns matches with line numbers and context, plus false-positive check results.\n\n"
                    "Available bug classes:\n" + "\n".join(bug_names)
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "bug_class_index": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 13,
                            "description": "Index of the bug class (0-13)",
                        },
                        "contract_name": {
                            "type": "string",
                            "description": "Name of the contract to scan",
                        },
                        "contract_source": {
                            "type": "string",
                            "description": "Source code of the contract",
                        },
                    },
                    "required": ["bug_class_index", "contract_name", "contract_source"],
                },
                handler=self._scan_bug_class,
            ),
            Tool(
                name="verify_match",
                description=(
                    "Send a regex match + code context to LLM for verification. "
                    "Returns VULNERABLE, NOT_VULNERABLE, or UNCERTAIN."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "bug_class_index": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 13,
                            "description": "Index of the bug class",
                        },
                        "contract_name": {
                            "type": "string",
                            "description": "Name of the contract",
                        },
                        "match_context": {
                            "type": "string",
                            "description": "The matched code with surrounding context",
                        },
                        "match_lines": {
                            "type": "string",
                            "description": "Line numbers of the match",
                        },
                    },
                    "required": ["bug_class_index", "contract_name", "match_context"],
                },
                handler=self._verify_match,
            ),
            Tool(
                name="report_finding",
                description="Report a confirmed bug finding",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "contract": {"type": "string"},
                        "function": {"type": "string"},
                        "description": {"type": "string"},
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "bug_class_name": {
                            "type": "string",
                            "description": "Name of the matched bug class",
                        },
                        "matched_lines": {
                            "type": "string",
                            "description": "Line numbers where the pattern was found",
                        },
                        "llm_verified": {
                            "type": "boolean",
                            "description": "Whether LLM verification confirmed the bug",
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                    },
                    "required": ["title", "severity", "contract", "description"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run known bug replay analysis."""
        from ...core.llm import get_llm_client
        llm = get_llm_client()

        contracts_info = self._format_contracts_info()
        bug_class_summary = self._format_bug_classes_summary()

        initial_prompt = f"""Systematically scan this codebase for 14 known bug patterns from real audit findings.

## Target
{self.state.target_path}

## Contracts
{contracts_info}

## Bug Classes Available (14 total)
{bug_class_summary}

## Your Task

1. Use `list_contracts` to see all contracts
2. Read each important contract with `read_file`
3. For EACH contract, scan ALL 14 bug classes with `scan_bug_class`:
   - Pass the contract source and bug class index (0-13)
   - The tool runs regex pre-filters and checks for false positive patterns
4. For any match that isn't a false positive, verify with `verify_match`
5. Report confirmed findings with `report_finding`

## Systematic Approach
For each contract:
```
for bug_class in range(14):
    scan_bug_class(bug_class, contract_name, source)
    if matches and not false_positive:
        verify_match(bug_class, contract_name, context)
        if VULNERABLE:
            report_finding(...)
```

## Important
- Do NOT skip any bug class -- the regex scan is cheap
- Focus on contracts that handle value (vaults, pools, lending, swaps)
- Use verify_match only when scan returns actual matches
- Confidence: 0.85 for LLM-verified, 0.6 for regex-only matches
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            max_iterations=20,
            use_routing_model=True,
        )

        if self.verbose:
            print(f"  KnownBugReplay completed: {len(self.findings)} findings")

        return self.findings

    def _format_contracts_info(self) -> str:
        """Format contract info for prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:15]:
            lines.append(f"- **{contract.name}** ({contract.path})")
            if contract.functions:
                externals = [f for f in contract.functions if f.visibility in ("external", "public")]
                lines.append(f"  External functions: {len(externals)}")
        return "\n".join(lines)

    def _format_bug_classes_summary(self) -> str:
        """Format a summary of all bug classes."""
        lines = []
        for i, bc in enumerate(self.bug_classes):
            lines.append(f"**{i}. {bc.name}** [{bc.severity}]")
            lines.append(f"   {bc.description[:100]}...")
        return "\n".join(lines)

    # === Tool Handlers ===

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            content = file_path.read_text()
            if len(content) > 30000:
                return content[:30000] + "\n\n... [truncated, file too large]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    async def _list_contracts(self) -> str:
        """List all contracts with their functions."""
        if not self.state.contracts:
            return "No contracts found. Run recon first."

        output = "Contracts in scope:\n\n"
        for contract in self.state.contracts:
            output += f"## {contract.name}\n"
            output += f"Path: {contract.path}\n"

            if contract.inheritance:
                output += f"Inherits: {', '.join(contract.inheritance)}\n"

            if contract.functions:
                output += f"Functions: {len(contract.functions)}\n"
                externals = [f for f in contract.functions if f.visibility in ("external", "public")]
                for func in externals[:10]:
                    params = ", ".join(
                        f"{p.get('type', '?')} {p.get('name', '?')}"
                        for p in func.parameters
                    )
                    output += f"  - {func.visibility} {func.name}({params}) {func.mutability}\n"

            output += "\n---\n\n"

        return output

    async def _scan_bug_class(self, bug_class_index: int, contract_name: str, contract_source: str) -> str:
        """Run regex pre-filter for one bug class against one contract."""
        if bug_class_index < 0 or bug_class_index >= len(self.bug_classes):
            return f"Invalid bug class index: {bug_class_index}. Must be 0-{len(self.bug_classes)-1}."

        bc = self.bug_classes[bug_class_index]
        source_lines = contract_source.split("\n")

        # Run regex patterns
        matches = []
        for pattern in bc.regex_patterns:
            try:
                for match in re.finditer(pattern, contract_source, re.IGNORECASE):
                    line_num = contract_source[:match.start()].count("\n") + 1
                    # Get context (3 lines before and after)
                    start_line = max(0, line_num - 4)
                    end_line = min(len(source_lines), line_num + 3)
                    context_lines = source_lines[start_line:end_line]
                    context = "\n".join(
                        f"{'>>>' if i + start_line + 1 == line_num else '   '} {i + start_line + 1}: {line}"
                        for i, line in enumerate(context_lines)
                    )
                    matches.append({
                        "pattern": pattern,
                        "line": line_num,
                        "matched_text": match.group()[:100],
                        "context": context,
                    })
            except re.error:
                continue

        if not matches:
            return f"No matches for bug class {bug_class_index} ({bc.name}) in {contract_name}."

        # Check for false positive patterns
        fp_hits = []
        for fp_pattern in bc.false_positive_checks:
            try:
                if re.search(fp_pattern, contract_source, re.IGNORECASE):
                    fp_hits.append(fp_pattern)
            except re.error:
                continue

        # Deduplicate by line number
        seen_lines = set()
        unique_matches = []
        for m in matches:
            if m["line"] not in seen_lines:
                seen_lines.add(m["line"])
                unique_matches.append(m)

        output = f"## Bug Class {bug_class_index}: {bc.name} [{bc.severity}]\n"
        output += f"Contract: {contract_name}\n"
        output += f"Matches: {len(unique_matches)}\n\n"

        for m in unique_matches[:10]:
            output += f"### Line {m['line']} (pattern: `{m['pattern']}`)\n"
            output += f"Matched: `{m['matched_text']}`\n"
            output += f"```\n{m['context']}\n```\n\n"

        if fp_hits:
            output += f"\n**False Positive Indicators Found:**\n"
            for fp in fp_hits:
                output += f"  - Pattern `{fp}` found -- this MAY be a false positive\n"
            output += "\nUse `verify_match` to confirm whether this is a real vulnerability.\n"
        else:
            output += "\n**No false positive indicators found** -- likely a real match. Verify with `verify_match`.\n"

        return output

    async def _verify_match(
        self,
        bug_class_index: int,
        contract_name: str,
        match_context: str,
        match_lines: str = "",
    ) -> str:
        """Send match + context to LLM for verification."""
        if bug_class_index < 0 or bug_class_index >= len(self.bug_classes):
            return f"Invalid bug class index: {bug_class_index}"

        bc = self.bug_classes[bug_class_index]

        from ...core.llm import get_llm_client
        llm = get_llm_client()

        prompt = f"""## Bug Class: {bc.name} [{bc.severity}]

{bc.description}

## Contract: {contract_name}
{f"Lines: {match_lines}" if match_lines else ""}

## Code Context
```solidity
{match_context[:8000]}
```

## Question
{bc.verification_prompt}

Respond with EXACTLY one of:
- VULNERABLE: [brief explanation]
- NOT_VULNERABLE: [brief explanation]
- UNCERTAIN: [brief explanation]"""

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a smart contract security expert. Analyze the code and determine if it is vulnerable to the described bug pattern. Be precise and avoid false positives.",
            max_tokens=1024,
        )

        return response.content

    def _report_finding(self, params: dict) -> str:
        """Report a confirmed bug finding."""
        title = params["title"]
        severity_str = params["severity"]
        contract = params["contract"]
        description = params["description"]

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        # Determine vulnerability type from bug class name if available
        bug_class_name = params.get("bug_class_name", "")
        vuln_type = VulnerabilityType.BUSINESS_LOGIC

        # Try to match bug class name to a specific VulnerabilityType
        for bc in self.bug_classes:
            if bc.name == bug_class_name:
                vuln_type = bc.vulnerability_type
                break

        full_description = description
        if bug_class_name:
            full_description += f"\n\n**Known Bug Pattern:** {bug_class_name}"
        if params.get("matched_lines"):
            full_description += f"\n\n**Matched Lines:** {params['matched_lines']}"

        llm_verified = params.get("llm_verified", False)
        confidence = params.get("confidence", 0.85 if llm_verified else 0.6)

        finding = Finding(
            id=f"KNOWN-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity_str, Severity.HIGH),
            vulnerability_type=vuln_type,
            description=full_description,
            contract=contract,
            function=params.get("function"),
            impact=params.get("impact", ""),
            recommendation=params.get("recommendation", ""),
            validated=llm_verified,
            found_by=AgentRole.VULNERABILITY_HUNTER,
            confidence=confidence,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity_str}] {title} (confidence: {confidence:.2f})"
