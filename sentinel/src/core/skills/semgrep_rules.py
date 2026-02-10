"""
Pre-built Semgrep rule library for Solidity vulnerability confirmation.

Each rule maps to a VulnerabilityType and encodes a detection heuristic from
kadenzipfel/smart-contract-vulnerabilities. FindingConfirmer tries these
static rules BEFORE falling back to LLM-generated patterns — faster, free,
deterministic.

Rules are intentionally broad: they confirm "this code pattern exists in the
project" rather than "this is definitely exploitable." The FindingConfirmer
then cross-references the match location with the finding's claimed contract
to determine confirmation vs. contradiction.

Source: https://github.com/kadenzipfel/smart-contract-vulnerabilities/tree/master/references
"""

from dataclasses import dataclass, field
from typing import Optional

from ..types import VulnerabilityType
from .semgrep_integration import SemgrepRule, SemgrepSeverity


@dataclass
class VulnRuleSet:
    """A set of Semgrep rules for a specific vulnerability type."""
    vuln_type: VulnerabilityType
    rules: list[SemgrepRule]
    false_positive_hints: list[str] = field(default_factory=list)


def _rule(rule_id: str, pattern: str, message: str, severity: SemgrepSeverity = SemgrepSeverity.WARNING) -> SemgrepRule:
    """Shorthand for creating a simple pattern rule."""
    return SemgrepRule(
        id=rule_id,
        languages=["solidity"],
        message=message,
        severity=severity,
        pattern=pattern,
    )


def _patterns_rule(rule_id: str, patterns: list[dict], message: str, severity: SemgrepSeverity = SemgrepSeverity.WARNING) -> SemgrepRule:
    """Shorthand for creating a multi-pattern rule."""
    return SemgrepRule(
        id=rule_id,
        languages=["solidity"],
        message=message,
        severity=severity,
        patterns=patterns,
    )


# ── Reentrancy ──────────────────────────────────────────────────────────────

REENTRANCY_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.REENTRANCY,
    rules=[
        # State update after external call (classic reentrancy)
        _rule(
            "reentrancy-state-after-call",
            "$RECEIVER.call{value: $AMT}($DATA)",
            "External call via .call{value:} — check if state is updated after this call (reentrancy risk)",
        ),
        _rule(
            "reentrancy-send",
            "$RECEIVER.send($AMT)",
            "ETH send — check if state is updated after this call",
        ),
        _rule(
            "reentrancy-transfer",
            "$RECEIVER.transfer($AMT)",
            "ETH transfer — check if state is updated after this call",
        ),
        # SafeMint callback reentrancy
        _rule(
            "reentrancy-safemint",
            "_safeMint($TO, $ID)",
            "ERC721 _safeMint triggers onERC721Received callback — reentrancy risk if state updated after",
        ),
        _rule(
            "reentrancy-safetransfer",
            "safeTransferFrom($FROM, $TO, $ID, ...)",
            "Safe transfer triggers callback — reentrancy risk",
        ),
    ],
    false_positive_hints=[
        "State is updated BEFORE the external call (checks-effects-interactions pattern)",
        "nonReentrant modifier is applied to the function",
        "External call target is trusted/immutable (e.g., WETH)",
        "Function is view/pure and cannot modify state",
    ],
)


# ── Access Control ──────────────────────────────────────────────────────────

ACCESS_CONTROL_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.ACCESS_CONTROL,
    rules=[
        # tx.origin authorization
        _rule(
            "access-control-txorigin",
            "require(tx.origin == $ADDR, ...)",
            "tx.origin used for authorization — vulnerable to phishing via malicious contract",
            SemgrepSeverity.ERROR,
        ),
        _rule(
            "access-control-txorigin-if",
            "if (tx.origin == $ADDR) { ... }",
            "tx.origin used for authorization",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "tx.origin used only for logging/analytics, not authorization",
        "tx.origin == msg.sender used for EOA check (different pattern, separate vuln)",
        "Combined with msg.sender as primary check",
    ],
)


# ── Arithmetic / Precision ──────────────────────────────────────────────────

PRECISION_LOSS_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.PRECISION_LOSS,
    rules=[
        # Division before multiplication
        _rule(
            "precision-div-before-mul",
            "$X = $A / $B * $C",
            "Division before multiplication — precision loss from integer truncation",
            SemgrepSeverity.WARNING,
        ),
    ],
    false_positive_hints=[
        "Multiplication is performed before division in the correct order",
        "Fixed-point math (WAD=1e18, RAY=1e27) is used",
        "Numerator is guaranteed larger than denominator by prior validation",
        "Precision loss is intentionally accepted and documented (dust amounts)",
    ],
)

INTEGER_OVERFLOW_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
    rules=[
        # Unchecked arithmetic
        _rule(
            "overflow-unchecked-add",
            "unchecked { ... $X + $Y ... }",
            "Arithmetic inside unchecked block — no overflow protection",
        ),
        _rule(
            "overflow-unchecked-mul",
            "unchecked { ... $X * $Y ... }",
            "Multiplication inside unchecked block — no overflow protection",
        ),
    ],
    false_positive_hints=[
        "unchecked block used only for loop counter increments (i++) where overflow is impossible",
        "Values are bounds-checked before entering unchecked block",
        "Solidity >=0.8.0 arithmetic outside unchecked/assembly blocks",
    ],
)

UNSAFE_CASTING_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.UNSAFE_CASTING,
    rules=[
        _rule("unsafe-cast-uint8", "uint8($X)", "Unsafe downcast to uint8 — truncates if value > 255"),
        _rule("unsafe-cast-uint16", "uint16($X)", "Unsafe downcast to uint16"),
        _rule("unsafe-cast-uint32", "uint32($X)", "Unsafe downcast to uint32"),
        _rule("unsafe-cast-uint64", "uint64($X)", "Unsafe downcast to uint64"),
        _rule("unsafe-cast-uint96", "uint96($X)", "Unsafe downcast to uint96"),
        _rule("unsafe-cast-uint128", "uint128($X)", "Unsafe downcast to uint128"),
        _rule("unsafe-cast-int256", "int256($X)", "Cast to signed int256 — may produce negative from large uint"),
    ],
    false_positive_hints=[
        "Value is validated to fit target type before casting (e.g., require(x <= type(uint8).max))",
        "SafeCast library from OpenZeppelin is used",
        "Cast is on a value with proven bounds (e.g., block.timestamp fits uint64)",
    ],
)


# ── Signature / Crypto ──────────────────────────────────────────────────────

ECRECOVER_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.ECRECOVER_ZERO,
    rules=[
        # Raw ecrecover without zero-address check
        _rule(
            "ecrecover-no-zero-check",
            "ecrecover($HASH, $V, $R, $S)",
            "Raw ecrecover — returns address(0) for invalid sigs. Use ECDSA.recover instead.",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "require(recovered != address(0)) check is present after ecrecover",
        "OpenZeppelin's ECDSA.recover is used (handles null address internally)",
        "Expected signer is validated non-zero at set time",
    ],
)

SIGNATURE_REPLAY_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.SIGNATURE_REPLAY,
    rules=[
        # encodePacked without chainid/address for signature
        _rule(
            "sig-replay-no-chainid",
            "keccak256(abi.encodePacked(...))",
            "abi.encodePacked hash — check if chainid, address(this), and nonce are included for replay protection",
        ),
    ],
    false_positive_hints=[
        "EIP-712 domain separator is used with proper nonce tracking",
        "Signed message includes nonce, address(this), and block.chainid",
        "EIP-2612 permit pattern with deadline and nonce",
    ],
)

SIGNATURE_MALLEABILITY_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.SIGNATURE_MALLEABILITY,
    rules=[
        # Signature dedup by raw bytes
        _rule(
            "sig-malleability-bytes-key",
            "mapping(bytes => bool)",
            "Signatures tracked by raw bytes — attacker can compute complementary (r, n-s) signature to bypass",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Signatures deduplicated by message hash or nonce, not raw bytes",
        "OpenZeppelin's ECDSA.recover is used (rejects high-s signatures)",
    ],
)

HASH_COLLISION_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.HASH_COLLISION,
    rules=[
        _rule(
            "hash-collision-encodepacked",
            "keccak256(abi.encodePacked($A, $B, ...))",
            "abi.encodePacked with multiple args — if adjacent args are variable-length types (string, bytes), hash collision is possible. Use abi.encode instead.",
        ),
    ],
    false_positive_hints=[
        "All arguments are fixed-length types (address, uint256, bytes32, bool)",
        "abi.encode() is used instead (includes length prefixes)",
        "Only one argument is variable-length",
        "Hash is not used for security-sensitive purposes",
    ],
)


# ── Token Issues ────────────────────────────────────────────────────────────

ERC20_RETURN_VALUE_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.ERC20_RETURN_VALUE,
    rules=[
        # Raw IERC20 transfer without SafeERC20
        _rule(
            "erc20-raw-transfer",
            "$TOKEN.transfer($TO, $AMT)",
            "Raw ERC20 transfer — reverts on non-compliant tokens (USDT). Use SafeERC20.safeTransfer.",
        ),
        _rule(
            "erc20-raw-transferfrom",
            "$TOKEN.transferFrom($FROM, $TO, $AMT)",
            "Raw ERC20 transferFrom — use SafeERC20.safeTransferFrom.",
        ),
        _rule(
            "erc20-raw-approve",
            "$TOKEN.approve($SPENDER, $AMT)",
            "Raw ERC20 approve — use SafeERC20.safeApprove or forceApprove.",
        ),
    ],
    false_positive_hints=[
        "SafeERC20 from OpenZeppelin is used (wraps non-compliant return values)",
        "The token is a known compliant implementation (e.g., contract's own token)",
        "Balance before/after pattern accounts for fee-on-transfer",
    ],
)


# ── Slippage / MEV ──────────────────────────────────────────────────────────

MISSING_SLIPPAGE_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.MISSING_SLIPPAGE,
    rules=[
        # Hardcoded 0 for amountOutMin
        _rule(
            "slippage-zero-min",
            "$ROUTER.swap(..., 0, ...)",
            "Hardcoded 0 for minimum output amount — no slippage protection",
            SemgrepSeverity.ERROR,
        ),
        _rule(
            "slippage-zero-min-exact",
            "amountOutMin: 0",
            "amountOutMin set to 0 — no slippage protection, vulnerable to sandwich attacks",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "minAmountOut and deadline parameters are present and validated",
        "Function uses a separate slippage check via oracle price",
        "Transaction submitted via private mempool (Flashbots)",
    ],
)

MISSING_DEADLINE_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.MISSING_DEADLINE,
    rules=[
        # type(uint256).max as deadline = no deadline
        _rule(
            "deadline-max-uint",
            "deadline: type(uint256).max",
            "Deadline set to max uint256 — effectively no deadline protection",
        ),
        _rule(
            "deadline-block-timestamp",
            "deadline: block.timestamp",
            "Deadline set to block.timestamp — always passes, provides no protection",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "A proper deadline parameter is passed from the caller",
        "The transaction has other time-based protections",
    ],
)


# ── DoS ─────────────────────────────────────────────────────────────────────

UNBOUNDED_LOOP_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.UNBOUNDED_LOOP,
    rules=[
        _rule(
            "dos-require-in-loop",
            "for (...) { ... require($CALL, ...) ... }",
            "require() inside loop — one failure blocks all iterations (DoS risk)",
        ),
    ],
    false_positive_hints=[
        "Loop iterates over fixed-size or bounded array",
        "Function supports paginated/batched execution",
        "Loop count controlled by caller with reasonable max",
    ],
)

DOS_BALANCE_EQUALITY_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.DOS,
    rules=[
        # Strict balance equality check
        _rule(
            "dos-strict-balance",
            "require(address(this).balance == $EXPECTED, ...)",
            "Strict balance equality — can be broken by force-sent ETH via selfdestruct. Use >= instead.",
            SemgrepSeverity.ERROR,
        ),
        _rule(
            "dos-strict-balance-if",
            "if (address(this).balance == $EXPECTED)",
            "Strict balance equality check — breakable by force-sent ETH",
        ),
    ],
    false_positive_hints=[
        "Balance checks use >= instead of ==",
        "The contract cannot receive unexpected ETH (no receive/fallback)",
    ],
)


# ── Delegatecall ────────────────────────────────────────────────────────────

DELEGATECALL_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.DELEGATECALL,
    rules=[
        _rule(
            "delegatecall-user-target",
            "$TARGET.delegatecall($DATA)",
            "delegatecall — verify target is not user-controlled. Malicious target can overwrite storage.",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Target is hardcoded or immutable",
        "Target set only in constructor and cannot be changed",
        "Standard proxy pattern (EIP-1967, UUPS) with proper access control on upgrades",
    ],
)


# ── Weak Randomness ─────────────────────────────────────────────────────────

WEAK_RANDOMNESS_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.WEAK_RANDOMNESS,
    rules=[
        _rule(
            "weak-random-timestamp",
            "keccak256(abi.encodePacked(block.timestamp, ...))",
            "block.timestamp used as randomness source — predictable by validators",
            SemgrepSeverity.ERROR,
        ),
        _rule(
            "weak-random-blockhash",
            "keccak256(abi.encodePacked(blockhash($N), ...))",
            "blockhash used as randomness source — predictable and expires after 256 blocks",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Chainlink VRF or other verifiable randomness oracle is used",
        "Commit-reveal scheme where timestamp alone doesn't determine outcome",
        "block.timestamp used only for non-security-critical logging",
    ],
)


# ── msg.value in loop ───────────────────────────────────────────────────────

MSGVALUE_LOOP_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.ARITHMETIC,
    rules=[
        _rule(
            "msgvalue-in-loop",
            "for (...) { ... msg.value ... }",
            "msg.value reused inside loop — same value on every iteration, not decremented",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Function tracks remaining value in local variable and decrements per iteration",
        "Total cost validated against msg.value before the loop",
        "Loop guaranteed to execute exactly once",
    ],
)


# ── Unprotected Initializer ─────────────────────────────────────────────────

UNPROTECTED_INIT_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.UNPROTECTED_INITIALIZER,
    rules=[
        _rule(
            "unprotected-initialize",
            "function initialize(...) external { ... }",
            "initialize() without initializer modifier — can be called by anyone to hijack proxy",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Function has initializer modifier from OpenZeppelin",
        "Access control (onlyOwner, require(msg.sender == admin)) is present",
        "Contract is not behind a proxy",
    ],
)


# ── Selfdestruct ────────────────────────────────────────────────────────────

SELFDESTRUCT_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.SELFDESTRUCT_DOS,
    rules=[
        _rule(
            "selfdestruct-usage",
            "selfdestruct($ADDR)",
            "selfdestruct — deprecated post-Dencun. Can force-send ETH to break balance invariants.",
        ),
    ],
    false_positive_hints=[
        "Only callable by admin/owner with proper access control",
        "Contract is on a chain where selfdestruct is fully disabled",
    ],
)


# ── Time Manipulation ───────────────────────────────────────────────────────

TIME_MANIPULATION_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.TIME_MANIPULATION,
    rules=[
        _rule(
            "time-tight-window",
            "require(block.timestamp >= $A && block.timestamp <= $B, ...)",
            "Tight timestamp window — validator manipulation may include/exclude transactions",
        ),
    ],
    false_positive_hints=[
        "Time window is large (hours/days) — 15s manipulation irrelevant",
        "On PoS Ethereum, timestamps are slot-fixed",
        "Used with commit-reveal scheme",
    ],
)


# ── Off-by-one ──────────────────────────────────────────────────────────────

OFF_BY_ONE_RULES = VulnRuleSet(
    vuln_type=VulnerabilityType.OFF_BY_ONE,
    rules=[
        # Array access at .length (out of bounds)
        _rule(
            "off-by-one-length",
            "$ARR[$ARR.length]",
            "Array access at .length — out of bounds, should be .length - 1",
            SemgrepSeverity.ERROR,
        ),
    ],
    false_positive_hints=[
        "Boundary is intentionally exclusive (e.g., skipping sentinel element)",
        "Iterating over pairs where i < length - 1 is correct",
        "Comparison operator matches documented specification",
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
# Registry: all rule sets indexed by VulnerabilityType
# ═══════════════════════════════════════════════════════════════════════════

ALL_RULE_SETS: list[VulnRuleSet] = [
    REENTRANCY_RULES,
    ACCESS_CONTROL_RULES,
    PRECISION_LOSS_RULES,
    INTEGER_OVERFLOW_RULES,
    UNSAFE_CASTING_RULES,
    ECRECOVER_RULES,
    SIGNATURE_REPLAY_RULES,
    SIGNATURE_MALLEABILITY_RULES,
    HASH_COLLISION_RULES,
    ERC20_RETURN_VALUE_RULES,
    MISSING_SLIPPAGE_RULES,
    MISSING_DEADLINE_RULES,
    UNBOUNDED_LOOP_RULES,
    DOS_BALANCE_EQUALITY_RULES,
    DELEGATECALL_RULES,
    WEAK_RANDOMNESS_RULES,
    MSGVALUE_LOOP_RULES,
    UNPROTECTED_INIT_RULES,
    SELFDESTRUCT_RULES,
    TIME_MANIPULATION_RULES,
    OFF_BY_ONE_RULES,
]

# Lookup by VulnerabilityType
RULES_BY_TYPE: dict[VulnerabilityType, VulnRuleSet] = {
    rs.vuln_type: rs for rs in ALL_RULE_SETS
}


def get_rules_for_type(vuln_type: VulnerabilityType) -> Optional[VulnRuleSet]:
    """Get pre-built Semgrep rules for a vulnerability type, if available."""
    return RULES_BY_TYPE.get(vuln_type)


def get_false_positive_hints(vuln_type: VulnerabilityType) -> list[str]:
    """Get false positive hints for a vulnerability type (used to enrich LLM prompts)."""
    rule_set = RULES_BY_TYPE.get(vuln_type)
    return rule_set.false_positive_hints if rule_set else []


def get_all_rules() -> list[SemgrepRule]:
    """Get all pre-built rules as a flat list."""
    rules = []
    for rs in ALL_RULE_SETS:
        rules.extend(rs.rules)
    return rules
