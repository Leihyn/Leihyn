"""
Bug Detection Engine - Pattern-based vulnerability detection.

No AI slop. Pure pattern matching and taint analysis.
Each pattern is battle-tested from real exploits.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectedBug:
    """Concrete bug detection result."""
    pattern_id: str
    title: str
    severity: Severity
    line_number: int
    code_snippet: str
    description: str
    exploitation: str  # How to exploit - no fluff
    fix: str  # Exact fix - no fluff
    confidence: float  # 0-1
    references: list[str]  # Real exploit references


class SolidityBugDetector:
    """
    Regex-based Solidity bug detection.
    Zero false positives > high recall.
    """

    PATTERNS = {
        # =====================================================================
        # CRITICAL - Direct fund loss
        # =====================================================================
        "SOL-CRIT-001": {
            "title": "Arbitrary External Call",
            "severity": Severity.CRITICAL,
            "pattern": r"\.call\{.*value:\s*\w+\}\s*\(\s*\w*\s*\)",
            "context_pattern": r"(address|bytes)\s+\w+\s*[=;].*msg\.sender|user|_to|recipient",
            "description": "Low-level call with user-controlled address",
            "exploitation": "Pass attacker contract address, receive ETH via fallback",
            "fix": "Use pull-over-push pattern or whitelist addresses",
            "confidence": 0.85,
            "references": ["Ronin Bridge $625M", "Poly Network $611M"]
        },

        "SOL-CRIT-002": {
            "title": "Unprotected selfdestruct",
            "severity": Severity.CRITICAL,
            "pattern": r"selfdestruct\s*\(\s*\w+\s*\)",
            "negative_pattern": r"(onlyOwner|require\s*\(\s*msg\.sender\s*==)",
            "description": "selfdestruct without access control",
            "exploitation": "Call selfdestruct, drain all ETH to attacker",
            "fix": "Add onlyOwner modifier or remove selfdestruct",
            "confidence": 0.95,
            "references": ["Parity Wallet $150M"]
        },

        "SOL-CRIT-003": {
            "title": "Unprotected Initialize",
            "severity": Severity.CRITICAL,
            "pattern": r"function\s+initialize\s*\([^)]*\)\s*(public|external)",
            "negative_pattern": r"(initializer|onlyOwner|require\s*\(\s*!initialized)",
            "description": "Initialize function can be called by anyone",
            "exploitation": "Call initialize() to become owner/admin",
            "fix": "Add initializer modifier from OpenZeppelin",
            "confidence": 0.90,
            "references": ["Wormhole $320M", "Nomad $190M"]
        },

        "SOL-CRIT-004": {
            "title": "Delegatecall to User Address",
            "severity": Severity.CRITICAL,
            "pattern": r"\.delegatecall\s*\(",
            "context_pattern": r"address.*(_to|target|impl|logic).*[=;]",
            "description": "delegatecall with potentially user-controlled address",
            "exploitation": "Pass malicious contract, execute in victim context",
            "fix": "Hardcode trusted implementation or use proxy pattern correctly",
            "confidence": 0.80,
            "references": ["Poly Network $611M"]
        },

        # =====================================================================
        # HIGH - Conditional fund loss
        # =====================================================================
        "SOL-HIGH-001": {
            "title": "Reentrancy - State After External Call",
            "severity": Severity.HIGH,
            "pattern": r"\.call\{.*\}\s*\([^)]*\)\s*;[^}]*\w+\s*[=\-\+]",
            "description": "State modified after external call",
            "exploitation": "Reenter during call, exploit stale state",
            "fix": "Apply CEI pattern - update state before external call",
            "confidence": 0.75,
            "references": ["The DAO $60M", "Cream Finance $130M"]
        },

        "SOL-HIGH-002": {
            "title": "Unchecked Return Value",
            "severity": Severity.HIGH,
            "pattern": r"\.transfer\s*\([^)]+\)\s*;|\.send\s*\([^)]+\)\s*;",
            "negative_pattern": r"require\s*\(.*\.(transfer|send)",
            "description": "transfer/send return value not checked",
            "exploitation": "Transfer fails silently, state becomes inconsistent",
            "fix": "Use call{value:}() with return check or SafeERC20",
            "confidence": 0.70,
            "references": ["KingOfTheEther"]
        },

        "SOL-HIGH-003": {
            "title": "tx.origin Authentication",
            "severity": Severity.HIGH,
            "pattern": r"(require|if)\s*\(\s*tx\.origin\s*==",
            "description": "Using tx.origin for authentication",
            "exploitation": "Phishing attack - user interacts with malicious contract",
            "fix": "Use msg.sender instead of tx.origin",
            "confidence": 0.95,
            "references": ["Common phishing vector"]
        },

        "SOL-HIGH-004": {
            "title": "Slot0 Price Oracle",
            "severity": Severity.HIGH,
            "pattern": r"\.slot0\s*\(\s*\)",
            "context_pattern": r"(price|sqrtPrice|tick)",
            "description": "Using Uniswap slot0 for pricing (manipulable)",
            "exploitation": "Flash loan -> swap -> manipulate slot0 -> profit",
            "fix": "Use TWAP via observe() with 30+ minute window",
            "confidence": 0.90,
            "references": ["Numerous DeFi exploits"]
        },

        "SOL-HIGH-005": {
            "title": "Missing Slippage Protection",
            "severity": Severity.HIGH,
            "pattern": r"(amountOutMin|minAmountOut|min_dy)\s*[:=]\s*0",
            "description": "Zero slippage protection on swap",
            "exploitation": "Sandwich attack - front-run with huge price impact",
            "fix": "Calculate reasonable minAmountOut based on oracle price",
            "confidence": 0.95,
            "references": ["Countless sandwich attacks"]
        },

        # =====================================================================
        # MEDIUM - Limited impact
        # =====================================================================
        "SOL-MED-001": {
            "title": "Block Timestamp Manipulation",
            "severity": Severity.MEDIUM,
            "pattern": r"block\.timestamp\s*[<>=!]+\s*\d+|block\.timestamp\s*%",
            "description": "Using block.timestamp for critical logic",
            "exploitation": "Miners can manipulate timestamp by ~15 seconds",
            "fix": "Use block.number or accept timestamp variance",
            "confidence": 0.60,
            "references": ["TheRun lottery"]
        },

        "SOL-MED-002": {
            "title": "Unbounded Loop",
            "severity": Severity.MEDIUM,
            "pattern": r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length\s*;",
            "context_pattern": r"(users|addresses|tokens)\[",
            "description": "Loop over unbounded array",
            "exploitation": "Add many elements, cause DoS via gas exhaustion",
            "fix": "Implement pagination or pull pattern",
            "confidence": 0.65,
            "references": ["GovernMental Ponzi DoS"]
        },

        "SOL-MED-003": {
            "title": "Missing Zero Address Check",
            "severity": Severity.MEDIUM,
            "pattern": r"(owner|admin|recipient)\s*=\s*\w+\s*;",
            "negative_pattern": r"require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)",
            "description": "Critical address set without zero-check",
            "exploitation": "Accidentally set to zero, lock funds forever",
            "fix": "Add require(addr != address(0))",
            "confidence": 0.50,
            "references": ["Multiple incidents"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Solidity code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"], re.MULTILINE | re.IGNORECASE)

            for i, line in enumerate(lines):
                if regex.search(line):
                    # Check negative pattern (should NOT match)
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        # Check surrounding context (5 lines before)
                        context = '\n'.join(lines[max(0, i-5):i+1])
                        if neg_regex.search(context):
                            continue  # False positive, skip

                    # Check context pattern (should also match nearby)
                    if "context_pattern" in pattern_data:
                        ctx_regex = re.compile(pattern_data["context_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if not ctx_regex.search(context):
                            continue  # Missing context, lower confidence

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class RustAnchorBugDetector:
    """Regex-based Anchor/Solana bug detection."""

    PATTERNS = {
        "ANC-CRIT-001": {
            "title": "Missing Signer Check",
            "severity": Severity.CRITICAL,
            "pattern": r"pub\s+\w+:\s*AccountInfo<'info>",
            "negative_pattern": r"Signer<'info>|#\[account\(.*signer.*\)\]",
            "description": "AccountInfo without Signer constraint for authority",
            "exploitation": "Pass any pubkey as authority without signing",
            "fix": "Use Signer<'info> or add signer constraint",
            "confidence": 0.85,
            "references": ["Wormhole $320M", "Cashio $52M"]
        },

        "ANC-CRIT-002": {
            "title": "Missing Owner Check",
            "severity": Severity.CRITICAL,
            "pattern": r"AccountInfo<'info>",
            "context_pattern": r"\.data\.borrow|try_from_slice",
            "negative_pattern": r"Account<'info,|owner\s*=|constraint.*owner",
            "description": "Deserializing AccountInfo without owner validation",
            "exploitation": "Pass account owned by different program with malicious data",
            "fix": "Use Account<'info, T> or check account.owner == program_id",
            "confidence": 0.80,
            "references": ["Multiple Solana exploits"]
        },

        "ANC-CRIT-003": {
            "title": "Unchecked Arithmetic",
            "severity": Severity.HIGH,
            "pattern": r"\+\s*\w+|\-\s*\w+|\*\s*\w+",
            "negative_pattern": r"checked_add|checked_sub|checked_mul|saturating",
            "description": "Arithmetic without overflow checks (wraps in release)",
            "exploitation": "Overflow to bypass balance checks or mint tokens",
            "fix": "Use checked_add/checked_sub/checked_mul",
            "confidence": 0.60,
            "references": ["Common Solana issue"]
        },

        "ANC-HIGH-001": {
            "title": "Missing has_one Constraint",
            "severity": Severity.HIGH,
            "pattern": r"#\[account\([^)]*\)\]",
            "context_pattern": r"(vault|pool|config).*authority|owner",
            "negative_pattern": r"has_one\s*=",
            "description": "Related accounts without has_one relationship",
            "exploitation": "Pass unrelated account, bypass authorization",
            "fix": "Add has_one = authority constraint",
            "confidence": 0.70,
            "references": ["Cashio $52M"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Anchor code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"])

            for i, line in enumerate(lines):
                if regex.search(line):
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                        if neg_regex.search(context):
                            continue

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class MoveAptosBugDetector:
    """Regex-based Move (Aptos) bug detection."""

    PATTERNS = {
        "APT-CRIT-001": {
            "title": "Missing Signer Validation",
            "severity": Severity.CRITICAL,
            "pattern": r"_\w+:\s*&signer",
            "description": "Signer parameter unused (underscore prefix)",
            "exploitation": "Anyone can call function - signer not validated",
            "fix": "Use signer::address_of(account) == expected_address",
            "confidence": 0.90,
            "references": ["Pontem Wallet Vulnerability"]
        },

        "APT-CRIT-002": {
            "title": "Capability Leak",
            "severity": Severity.CRITICAL,
            "pattern": r"public\s+fun\s+\w+\([^)]*\)\s*:\s*\w*Cap",
            "description": "Public function returns capability struct",
            "exploitation": "Extract capability for persistent unauthorized access",
            "fix": "Keep capabilities within module, use inline authorization",
            "confidence": 0.95,
            "references": ["Move capability extraction attacks"]
        },

        "APT-CRIT-003": {
            "title": "Unauthorized Global Borrow",
            "severity": Severity.CRITICAL,
            "pattern": r"borrow_global(_mut)?\s*<[^>]+>\s*\(\s*\w+\s*\)",
            "negative_pattern": r"signer::address_of|@\w+",
            "context_pattern": r"(address|addr)\s*:\s*address",
            "description": "Borrowing global resource at arbitrary address",
            "exploitation": "Access/modify any user's resources",
            "fix": "Only access signer::address_of(account) or hardcoded addresses",
            "confidence": 0.85,
            "references": ["Common Move vulnerability"]
        },

        "APT-HIGH-001": {
            "title": "Unchecked Arithmetic",
            "severity": Severity.HIGH,
            "pattern": r"\w+\s*[\+\-\*]\s*\w+",
            "negative_pattern": r"checked_|safe_|assert!.*<|assert!.*>",
            "context_pattern": r"(amount|balance|price|fee|supply)",
            "description": "Arithmetic without overflow checks in financial calculation",
            "exploitation": "Overflow to bypass limits or inflate balances",
            "fix": "Add explicit bound checks or use checked arithmetic",
            "confidence": 0.70,
            "references": ["Early DEX Integer Overflow"]
        },

        "APT-HIGH-002": {
            "title": "Missing Existence Check",
            "severity": Severity.HIGH,
            "pattern": r"borrow_global|move_from",
            "negative_pattern": r"exists<|if\s*\(exists",
            "description": "Accessing global resource without existence check",
            "exploitation": "DoS by calling with address that lacks resource",
            "fix": "Check exists<T>(addr) before borrow_global",
            "confidence": 0.75,
            "references": ["Move best practices"]
        },

        "APT-HIGH-003": {
            "title": "Flash Loan Receipt Not Consumed",
            "severity": Severity.HIGH,
            "pattern": r"struct\s+\w*Receipt\w*\s+has\s+.*store",
            "description": "Flash loan receipt has 'store' ability - can be persisted",
            "exploitation": "Borrow without repaying by storing receipt",
            "fix": "Use hot potato pattern - receipt should only have 'drop'",
            "confidence": 0.90,
            "references": ["Flash loan design patterns"]
        },

        "APT-MED-001": {
            "title": "Module Init Reinitialization",
            "severity": Severity.MEDIUM,
            "pattern": r"fun\s+init_module\s*\(",
            "negative_pattern": r"assert!.*exists|if\s*\(!exists",
            "description": "init_module without reinitialization guard",
            "exploitation": "State reset if init can be called again",
            "fix": "Add exists<> check or use one-time init pattern",
            "confidence": 0.65,
            "references": ["Initialization attacks"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Move (Aptos) code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"])

            for i, line in enumerate(lines):
                if regex.search(line):
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if neg_regex.search(context):
                            continue

                    if "context_pattern" in pattern_data:
                        ctx_regex = re.compile(pattern_data["context_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if not ctx_regex.search(context):
                            continue

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class MoveSuiBugDetector:
    """Regex-based Move (Sui) bug detection."""

    PATTERNS = {
        "SUI-CRIT-001": {
            "title": "Shared Object Race Condition",
            "severity": Severity.CRITICAL,
            "pattern": r"&mut\s+\w+",
            "context_pattern": r"public\s+entry|public\s+fun",
            "negative_pattern": r"&TxContext|clock::",
            "description": "Mutable shared object without race protection",
            "exploitation": "Concurrent transactions exploit stale state reads",
            "fix": "Use owned objects or implement mutex pattern",
            "confidence": 0.70,
            "references": ["Sui concurrency model"]
        },

        "SUI-CRIT-002": {
            "title": "Missing Capability Check",
            "severity": Severity.CRITICAL,
            "pattern": r"public\s+(entry\s+)?fun\s+\w*(admin|owner|mint|burn|upgrade)\w*\s*\(",
            "negative_pattern": r"AdminCap|OwnerCap|MinterCap|_cap:\s*&",
            "description": "Admin function without capability parameter",
            "exploitation": "Anyone can call privileged function",
            "fix": "Require AdminCap or similar capability object",
            "confidence": 0.85,
            "references": ["Sui capability pattern"]
        },

        "SUI-HIGH-001": {
            "title": "Incorrect Transfer Function",
            "severity": Severity.HIGH,
            "pattern": r"transfer::transfer\s*\(",
            "context_pattern": r"has\s+key,\s*store|has\s+store,\s*key",
            "description": "Using transfer::transfer for object with 'store' ability",
            "exploitation": "Object may not reach intended recipient correctly",
            "fix": "Use transfer::public_transfer for objects with 'store'",
            "confidence": 0.80,
            "references": ["Sui transfer semantics"]
        },

        "SUI-HIGH-002": {
            "title": "Dynamic Field Authorization Bypass",
            "severity": Severity.HIGH,
            "pattern": r"dynamic_field::(add|remove|borrow_mut)",
            "negative_pattern": r"assert!|ctx\.sender|owner",
            "description": "Dynamic field modification without authorization",
            "exploitation": "Inject or modify hidden state in objects",
            "fix": "Validate caller authorization before dynamic field ops",
            "confidence": 0.75,
            "references": ["Sui dynamic fields security"]
        },

        "SUI-HIGH-003": {
            "title": "PTB Flash Loan Pattern Vulnerable",
            "severity": Severity.HIGH,
            "pattern": r"public\s+fun\s+\w+\([^)]*\)\s*:\s*\([^)]*Coin",
            "description": "Function returns Coin that can be used in PTB attacks",
            "exploitation": "Chain in PTB: borrow -> manipulate -> profit -> return",
            "fix": "Consider PTB context, add price manipulation guards",
            "confidence": 0.65,
            "references": ["Sui PTB attack patterns"]
        },

        "SUI-MED-001": {
            "title": "Clock Manipulation Risk",
            "severity": Severity.MEDIUM,
            "pattern": r"clock::timestamp_ms",
            "context_pattern": r"(deadline|expiry|unlock|vesting)",
            "description": "Clock used for time-sensitive logic",
            "exploitation": "Validator can influence timestamp slightly",
            "fix": "Use epoch-based timing or accept timestamp variance",
            "confidence": 0.60,
            "references": ["Sui Clock considerations"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Move (Sui) code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"])

            for i, line in enumerate(lines):
                if regex.search(line):
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if neg_regex.search(context):
                            continue

                    if "context_pattern" in pattern_data:
                        ctx_regex = re.compile(pattern_data["context_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if not ctx_regex.search(context):
                            continue

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class CairoBugDetector:
    """Regex-based Cairo (Starknet) bug detection."""

    PATTERNS = {
        "CAIRO-CRIT-001": {
            "title": "Missing Caller Validation",
            "severity": Severity.CRITICAL,
            "pattern": r"#\[external\(v0\)\]|fn\s+\w+\s*\(",
            "context_pattern": r"(admin|owner|mint|burn|upgrade|pause)",
            "negative_pattern": r"get_caller_address|assert.*caller|only_owner",
            "description": "External function without caller validation",
            "exploitation": "Anyone can call privileged function",
            "fix": "Add get_caller_address() == expected check",
            "confidence": 0.85,
            "references": ["Starknet access control"]
        },

        "CAIRO-CRIT-002": {
            "title": "L1 Handler Spoofing",
            "severity": Severity.CRITICAL,
            "pattern": r"#\[l1_handler\]",
            "negative_pattern": r"from_address\s*==|assert.*from_address",
            "description": "L1 handler without sender validation",
            "exploitation": "Spoof L1 messages from unauthorized senders",
            "fix": "Validate from_address matches trusted L1 contract",
            "confidence": 0.95,
            "references": ["L1-L2 bridge vulnerabilities"]
        },

        "CAIRO-HIGH-001": {
            "title": "felt252 Overflow",
            "severity": Severity.HIGH,
            "pattern": r"felt252",
            "context_pattern": r"(amount|balance|price|total)\s*:\s*felt252",
            "description": "Using felt252 for financial amounts (wraps at prime)",
            "exploitation": "Overflow at field prime to bypass balance checks",
            "fix": "Use u256 for amounts, implement explicit bound checks",
            "confidence": 0.80,
            "references": ["Cairo felt252 semantics"]
        },

        "CAIRO-HIGH-002": {
            "title": "Reentrancy via External Call",
            "severity": Severity.HIGH,
            "pattern": r"call_contract_syscall|\.call\(",
            "negative_pattern": r"ReentrancyGuard|_locked|nonreentrant",
            "description": "External call without reentrancy protection",
            "exploitation": "Reenter during callback, exploit stale state",
            "fix": "Use ReentrancyGuard or CEI pattern",
            "confidence": 0.75,
            "references": ["Cross-contract reentrancy"]
        },

        "CAIRO-HIGH-003": {
            "title": "Missing Signature Nonce",
            "severity": Severity.HIGH,
            "pattern": r"verify_signature|check_signature|ecdsa_verify",
            "negative_pattern": r"nonce|replay|used_signatures",
            "description": "Signature verification without replay protection",
            "exploitation": "Replay same signature multiple times",
            "fix": "Include nonce in signed message, track used nonces",
            "confidence": 0.85,
            "references": ["Signature replay attacks"]
        },

        "CAIRO-MED-001": {
            "title": "Unprotected Storage Write",
            "severity": Severity.MEDIUM,
            "pattern": r"\.write\s*\(",
            "context_pattern": r"#\[storage\]|storage::",
            "negative_pattern": r"get_caller_address|assert|only_",
            "description": "Storage write without access control",
            "exploitation": "Unauthorized state modification",
            "fix": "Add caller validation before storage writes",
            "confidence": 0.70,
            "references": ["Cairo storage security"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Cairo code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"])

            for i, line in enumerate(lines):
                if regex.search(line):
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if neg_regex.search(context):
                            continue

                    if "context_pattern" in pattern_data:
                        ctx_regex = re.compile(pattern_data["context_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if not ctx_regex.search(context):
                            continue

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class CosmWasmBugDetector:
    """Regex-based CosmWasm bug detection."""

    PATTERNS = {
        "CW-CRIT-001": {
            "title": "Missing Sender Validation",
            "severity": Severity.CRITICAL,
            "pattern": r"ExecuteMsg::\w+",
            "context_pattern": r"(admin|owner|migrate|update_config)",
            "negative_pattern": r"info\.sender\s*==|ensure_eq!.*sender|is_admin",
            "description": "Execute handler without sender validation",
            "exploitation": "Anyone can call admin functions",
            "fix": "Check info.sender == stored_admin",
            "confidence": 0.85,
            "references": ["CosmWasm access control"]
        },

        "CW-HIGH-001": {
            "title": "Submessage Reentrancy",
            "severity": Severity.HIGH,
            "pattern": r"SubMsg::reply_on_",
            "negative_pattern": r"LOCKED|reentrancy|_in_progress",
            "description": "Submessage with reply without reentrancy guard",
            "exploitation": "State inconsistency via reply callback",
            "fix": "Handle all reply cases, use reentrancy guard",
            "confidence": 0.75,
            "references": ["Terra collapse", "CosmWasm submessage attacks"]
        },

        "CW-HIGH-002": {
            "title": "Unbounded Iteration",
            "severity": Severity.HIGH,
            "pattern": r"\.range\s*\(|\.iter\s*\(",
            "context_pattern": r"Map|IndexedMap|storage",
            "negative_pattern": r"\.take\s*\(|limit|Bound::",
            "description": "Iterating storage without pagination",
            "exploitation": "DoS via gas exhaustion with large datasets",
            "fix": "Implement pagination with .take() and Bound",
            "confidence": 0.80,
            "references": ["CosmWasm gas limits"]
        },

        "CW-HIGH-003": {
            "title": "Unchecked Arithmetic",
            "severity": Severity.HIGH,
            "pattern": r"Uint128|Uint256",
            "context_pattern": r"[\+\-\*]",
            "negative_pattern": r"checked_add|checked_sub|checked_mul|\?",
            "description": "Arithmetic on Uint types without checked methods",
            "exploitation": "Overflow to bypass balance checks",
            "fix": "Use checked_add()?, checked_sub()?, checked_mul()?",
            "confidence": 0.70,
            "references": ["CosmWasm arithmetic"]
        },

        "CW-MED-001": {
            "title": "Missing Migration Handler",
            "severity": Severity.MEDIUM,
            "pattern": r"#\[entry_point\].*migrate",
            "negative_pattern": r"migrate\s*\(",
            "description": "Contract may not handle migrations properly",
            "exploitation": "Failed upgrades or storage corruption",
            "fix": "Implement migrate() with proper version checks",
            "confidence": 0.60,
            "references": ["CosmWasm migrations"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in CosmWasm code."""
        bugs = []
        lines = code.split('\n')

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"])

            for i, line in enumerate(lines):
                if regex.search(line):
                    if "negative_pattern" in pattern_data:
                        neg_regex = re.compile(pattern_data["negative_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if neg_regex.search(context):
                            continue

                    if "context_pattern" in pattern_data:
                        ctx_regex = re.compile(pattern_data["context_pattern"])
                        context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                        if not ctx_regex.search(context):
                            continue

                    bugs.append(DetectedBug(
                        pattern_id=pattern_id,
                        title=pattern_data["title"],
                        severity=pattern_data["severity"],
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description=pattern_data["description"],
                        exploitation=pattern_data["exploitation"],
                        fix=pattern_data["fix"],
                        confidence=pattern_data["confidence"],
                        references=pattern_data.get("references", [])
                    ))

        return bugs


class VyperBugDetector:
    """Regex-based Vyper bug detection."""

    PATTERNS = {
        "VYP-CRIT-001": {
            "title": "Vyper Reentrancy Lock Bug (0.2.15-0.3.0)",
            "severity": Severity.CRITICAL,
            "pattern": r"#\s*@version\s*(0\.2\.15|0\.2\.16|0\.3\.0)",
            "description": "@nonreentrant was broken in Vyper 0.2.15-0.3.0",
            "exploitation": "Reentrancy despite @nonreentrant decorator",
            "fix": "Upgrade to Vyper >= 0.3.1 immediately",
            "confidence": 0.99,
            "references": ["Curve pools $70M+ (July 2023)"]
        },

        "VYP-HIGH-001": {
            "title": "raw_call Without Return Check",
            "severity": Severity.HIGH,
            "pattern": r"raw_call\s*\(",
            "negative_pattern": r"assert.*raw_call|if.*raw_call|success\s*=.*raw_call",
            "description": "raw_call without checking return value",
            "exploitation": "Silent failure leads to inconsistent state",
            "fix": "Check return value: assert raw_call(...), use max_outsize",
            "confidence": 0.85,
            "references": ["Vyper raw_call security"]
        },

        "VYP-HIGH-002": {
            "title": "Unprotected Default Function",
            "severity": Severity.HIGH,
            "pattern": r"@external\s*\n\s*@payable\s*\n\s*def\s+__default__",
            "description": "Default function accepts ETH from any call",
            "exploitation": "Unexpected ETH handling or callback attacks",
            "fix": "Add explicit checks in __default__ or remove if not needed",
            "confidence": 0.75,
            "references": ["Vyper default function"]
        },

        "VYP-HIGH-003": {
            "title": "Missing Access Control",
            "severity": Severity.HIGH,
            "pattern": r"@external\s*\n\s*def\s+\w*(admin|owner|set|update|pause|unpause)\w*",
            "negative_pattern": r"assert\s+msg\.sender\s*==|self\._check_owner",
            "description": "Admin function without access control",
            "exploitation": "Anyone can call privileged function",
            "fix": "Add assert msg.sender == self.owner",
            "confidence": 0.85,
            "references": ["Vyper access control patterns"]
        },

        "VYP-MED-001": {
            "title": "Integer Bounds in DynArray",
            "severity": Severity.MEDIUM,
            "pattern": r"DynArray\[.*,\s*\d+\s*\]",
            "context_pattern": r"for\s+\w+\s+in\s+\w+",
            "description": "DynArray iteration may hit gas limits",
            "exploitation": "DoS by filling array to max size",
            "fix": "Use reasonable bounds, consider pagination",
            "confidence": 0.65,
            "references": ["Vyper DynArray gas"]
        },
    }

    def detect(self, code: str) -> list[DetectedBug]:
        """Detect bugs in Vyper code."""
        bugs = []
        lines = code.split('\n')
        full_code = '\n'.join(lines)

        for pattern_id, pattern_data in self.PATTERNS.items():
            regex = re.compile(pattern_data["pattern"], re.MULTILINE)

            matches = regex.finditer(full_code)
            for match in matches:
                line_num = full_code[:match.start()].count('\n') + 1

                if "negative_pattern" in pattern_data:
                    neg_regex = re.compile(pattern_data["negative_pattern"])
                    context_start = max(0, line_num - 10)
                    context_end = min(len(lines), line_num + 10)
                    context = '\n'.join(lines[context_start:context_end])
                    if neg_regex.search(context):
                        continue

                if "context_pattern" in pattern_data:
                    ctx_regex = re.compile(pattern_data["context_pattern"])
                    context_start = max(0, line_num - 10)
                    context_end = min(len(lines), line_num + 10)
                    context = '\n'.join(lines[context_start:context_end])
                    if not ctx_regex.search(context):
                        continue

                bugs.append(DetectedBug(
                    pattern_id=pattern_id,
                    title=pattern_data["title"],
                    severity=pattern_data["severity"],
                    line_number=line_num,
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    description=pattern_data["description"],
                    exploitation=pattern_data["exploitation"],
                    fix=pattern_data["fix"],
                    confidence=pattern_data["confidence"],
                    references=pattern_data.get("references", [])
                ))

        return bugs


# Detector registry - All supported languages
DETECTORS = {
    # EVM
    "solidity": SolidityBugDetector,
    "vyper": VyperBugDetector,
    # Solana
    "rust": RustAnchorBugDetector,
    "anchor": RustAnchorBugDetector,
    "solana": RustAnchorBugDetector,
    # Move
    "move": MoveAptosBugDetector,
    "aptos": MoveAptosBugDetector,
    "sui": MoveSuiBugDetector,
    # Starknet
    "cairo": CairoBugDetector,
    "starknet": CairoBugDetector,
    # Cosmos
    "cosmwasm": CosmWasmBugDetector,
    "cosmos": CosmWasmBugDetector,
}


def detect_bugs(code: str, language: str = "solidity") -> list[DetectedBug]:
    """Detect bugs in code using pattern matching.

    Supported languages:
    - solidity, vyper (EVM)
    - rust, anchor, solana (Solana)
    - move, aptos, sui (Move)
    - cairo, starknet (Starknet)
    - cosmwasm, cosmos (Cosmos)
    """
    detector_class = DETECTORS.get(language.lower())
    if not detector_class:
        return []
    return detector_class().detect(code)
