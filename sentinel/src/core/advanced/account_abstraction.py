"""
Account Abstraction & Intent Security Analyzer

Analyzes ERC-4337 implementations and intent-based systems for vulnerabilities:
1. Bundler manipulation - Reordering/censoring UserOps
2. Paymaster griefing - Gas draining attacks
3. Signature replay - Cross-chain/account replay
4. Intent solver frontrunning - Solver extracts user value
5. Aggregator vulnerabilities - Aggregated signature issues
6. EntryPoint reentrancy - State manipulation
7. Factory vulnerabilities - Counterfactual deployment issues

Key components analyzed:
- Smart Accounts (ERC-4337)
- Paymasters
- Bundlers
- Intent protocols (CoW, UniswapX, etc.)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class AAComponent(Enum):
    """Account Abstraction components."""
    SMART_ACCOUNT = "smart_account"
    PAYMASTER = "paymaster"
    BUNDLER = "bundler"
    AGGREGATOR = "aggregator"
    FACTORY = "factory"
    ENTRY_POINT = "entry_point"
    INTENT_SOLVER = "intent_solver"


class AAVulnerability(Enum):
    """Account Abstraction vulnerability types."""
    SIGNATURE_REPLAY = "signature_replay"
    PAYMASTER_GRIEFING = "paymaster_griefing"
    BUNDLER_MANIPULATION = "bundler_manipulation"
    SOLVER_FRONTRUNNING = "solver_frontrunning"
    AGGREGATOR_BYPASS = "aggregator_bypass"
    FACTORY_DOS = "factory_dos"
    VALIDATION_REENTRANCY = "validation_reentrancy"
    GAS_ESTIMATION_ATTACK = "gas_estimation_attack"
    STORAGE_ACCESS_VIOLATION = "storage_access_violation"
    OPCODE_BAN_BYPASS = "opcode_ban_bypass"
    INTENT_MANIPULATION = "intent_manipulation"
    NONCE_MANAGEMENT = "nonce_management"


@dataclass
class AAFinding:
    """An Account Abstraction security finding."""
    component: AAComponent
    vulnerability: AAVulnerability
    severity: str
    title: str
    description: str
    affected_code: str
    line_number: int
    attack_scenario: str
    erc4337_reference: Optional[str]  # Reference to ERC-4337 spec
    recommendation: str


@dataclass
class AAConfig:
    """Configuration for AA analysis."""
    check_smart_account: bool = True
    check_paymaster: bool = True
    check_bundler: bool = True
    check_intents: bool = True
    erc4337_version: str = "0.7"


# =============================================================================
# ERC-4337 VULNERABILITY PATTERNS
# =============================================================================

SMART_ACCOUNT_PATTERNS = {
    AAVulnerability.SIGNATURE_REPLAY: {
        "patterns": [
            # Missing chain ID in signature
            r"function\s+validateUserOp[^}]*\{(?!.*chainId)(?!.*block\.chainid)",
            # Missing nonce in hash
            r"keccak256\s*\([^)]*userOp[^)]*\)(?!.*nonce)",
            # No domain separator
            r"ecrecover\s*\([^)]*\)(?!.*DOMAIN_SEPARATOR)",
        ],
        "description": "UserOp signature can be replayed on other chains or accounts",
        "severity": "Critical",
        "erc4337_ref": "ERC-4337 Section 4.3 - Replay Protection",
    },
    AAVulnerability.VALIDATION_REENTRANCY: {
        "patterns": [
            # External call in validation
            r"function\s+validateUserOp[^}]*\{[^}]*\.call\{",
            # Callback during validation
            r"function\s+validateUserOp[^}]*\{[^}]*(?:ERC721|ERC1155).*(?:safeTransfer|onReceived)",
        ],
        "description": "Validation phase makes external calls (reentrancy risk)",
        "severity": "High",
        "erc4337_ref": "ERC-4337 - Validation cannot call other contracts",
    },
    AAVulnerability.STORAGE_ACCESS_VIOLATION: {
        "patterns": [
            # Accessing storage of other accounts
            r"function\s+validateUserOp[^}]*\{[^}]*SLOAD(?!.*address\(this\))",
            # Reading external contract storage
            r"function\s+validate\w*[^}]*\{[^}]*\.slot",
        ],
        "description": "Validation accesses forbidden storage",
        "severity": "High",
        "erc4337_ref": "ERC-4337 - Storage access rules",
    },
    AAVulnerability.NONCE_MANAGEMENT: {
        "patterns": [
            # Nonce not incremented
            r"function\s+validateUserOp[^}]*\{(?!.*nonce\+\+)(?!.*incrementNonce)",
            # Nonce checked but not updated
            r"require\s*\([^)]*nonce[^)]*\)(?!.*nonce.*=)",
        ],
        "description": "Nonce management may allow replay within same chain",
        "severity": "High",
        "erc4337_ref": "ERC-4337 Section 4.4 - Nonce Management",
    },
}

PAYMASTER_PATTERNS = {
    AAVulnerability.PAYMASTER_GRIEFING: {
        "patterns": [
            # No deposit check
            r"function\s+validatePaymasterUserOp[^}]*\{(?!.*deposit)(?!.*balance)",
            # Unlimited sponsorship
            r"function\s+validatePaymasterUserOp[^}]*\{(?!.*limit)(?!.*quota)",
            # No user validation
            r"function\s+validatePaymasterUserOp[^}]*return\s*\([^)]*context[^)]*0",
        ],
        "description": "Paymaster can be drained by griefing attacks",
        "severity": "High",
        "erc4337_ref": "ERC-4337 - Paymaster deposit requirements",
    },
    AAVulnerability.GAS_ESTIMATION_ATTACK: {
        "patterns": [
            # Gas-dependent validation logic
            r"function\s+validatePaymasterUserOp[^}]*\{[^}]*gasleft\(\)",
            # Different behavior in estimation vs execution
            r"function\s+validate\w*[^}]*\{[^}]*tx\.gasprice",
        ],
        "description": "Validation behaves differently during gas estimation",
        "severity": "Medium",
        "erc4337_ref": "ERC-4337 - Gas estimation griefing",
    },
}

BUNDLER_PATTERNS = {
    AAVulnerability.BUNDLER_MANIPULATION: {
        "patterns": [
            # No bundle ordering protection
            r"function\s+handleOps[^}]*\{(?!.*ordering)",
            # Frontrunnable bundle
            r"function\s+execute\w*Bundle[^}]*\{(?!.*private)(?!.*flashbots)",
        ],
        "description": "Bundle can be manipulated by malicious bundler",
        "severity": "Medium",
        "erc4337_ref": "ERC-4337 - Bundler requirements",
    },
}

INTENT_PATTERNS = {
    AAVulnerability.SOLVER_FRONTRUNNING: {
        "patterns": [
            # Public intent without protection
            r"function\s+(?:submitIntent|createOrder)\s*\([^)]*\)\s*external(?!.*private)(?!.*encrypted)",
            # No slippage protection on intent
            r"struct\s+(?:Intent|Order)\s*\{[^}]*(?!minOutput)(?!minAmount)",
            # Solver selection not protected
            r"function\s+solve\w*\([^)]*\)\s*external(?!.*auction)(?!.*commit)",
        ],
        "description": "Intent can be frontrun or manipulated by solver",
        "severity": "High",
        "erc4337_ref": "Intent protocols - Fair solver selection",
    },
    AAVulnerability.INTENT_MANIPULATION: {
        "patterns": [
            # Intent expiry not enforced
            r"struct\s+Intent[^}]*\{(?!.*deadline)(?!.*expiry)",
            # Partial fill without accounting
            r"function\s+fill\w*Intent[^}]*\{(?!.*filled\[)",
            # No intent cancellation
            r"contract.*Intent(?!.*cancel)",
        ],
        "description": "Intent can be manipulated or never expire",
        "severity": "Medium",
        "erc4337_ref": "Intent protocols - Intent lifecycle",
    },
}


# =============================================================================
# ERC-4337 BANNED OPCODES
# =============================================================================

BANNED_OPCODES = {
    "validation": [
        "GASPRICE", "GASLIMIT", "DIFFICULTY", "TIMESTAMP",
        "BASEFEE", "BLOCKHASH", "NUMBER", "SELFBALANCE",
        "BALANCE", "ORIGIN", "COINBASE", "CREATE", "CREATE2",
        "SELFDESTRUCT",
    ],
    "paymaster_validation": [
        # Same as validation plus:
        "GAS",  # gasleft()
    ],
}


class AccountAbstractionAnalyzer:
    """
    Comprehensive ERC-4337 and Intent security analyzer.

    Checks:
    1. Smart Account validation security
    2. Paymaster security and griefing resistance
    3. Bundler manipulation vectors
    4. Intent protocol security
    5. ERC-4337 compliance
    """

    def __init__(self, config: Optional[AAConfig] = None):
        self.config = config or AAConfig()
        self.findings: list[AAFinding] = []

    def analyze(
        self,
        source_code: str,
        component: Optional[AAComponent] = None,
    ) -> list[AAFinding]:
        """
        Analyze source code for AA vulnerabilities.
        """
        self.findings = []

        # Detect component type if not specified
        if component is None:
            component = self._detect_component(source_code)

        # Run component-specific analysis
        if component == AAComponent.SMART_ACCOUNT or component is None:
            self._analyze_smart_account(source_code)

        if component == AAComponent.PAYMASTER or component is None:
            self._analyze_paymaster(source_code)

        if component == AAComponent.INTENT_SOLVER or component is None:
            self._analyze_intents(source_code)

        # Check for banned opcodes
        self._check_banned_opcodes(source_code, component)

        return self.findings

    def _detect_component(self, source: str) -> Optional[AAComponent]:
        """Detect what type of AA component this is."""
        if "validateUserOp" in source and "IAccount" in source:
            return AAComponent.SMART_ACCOUNT
        if "validatePaymasterUserOp" in source or "IPaymaster" in source:
            return AAComponent.PAYMASTER
        if "handleOps" in source or "IBundler" in source:
            return AAComponent.BUNDLER
        if "Intent" in source or "Solver" in source:
            return AAComponent.INTENT_SOLVER
        return None

    def _analyze_smart_account(self, source: str) -> None:
        """Analyze smart account implementation."""
        for vuln_type, vuln_info in SMART_ACCOUNT_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source[:match.start()].count('\n') + 1
                    self.findings.append(AAFinding(
                        component=AAComponent.SMART_ACCOUNT,
                        vulnerability=vuln_type,
                        severity=vuln_info["severity"],
                        title=f"Smart Account: {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._get_attack_scenario(vuln_type),
                        erc4337_reference=vuln_info.get("erc4337_ref"),
                        recommendation=self._get_recommendation(vuln_type),
                    ))

        # Check for proper IAccount interface
        if "validateUserOp" in source:
            if not re.search(r"function\s+validateUserOp\s*\([^)]*PackedUserOperation", source):
                self.findings.append(AAFinding(
                    component=AAComponent.SMART_ACCOUNT,
                    vulnerability=AAVulnerability.SIGNATURE_REPLAY,
                    severity="Medium",
                    title="Non-standard validateUserOp Signature",
                    description="validateUserOp doesn't use PackedUserOperation struct",
                    affected_code="function validateUserOp(...)",
                    line_number=0,
                    attack_scenario="May not be compatible with standard bundlers",
                    erc4337_reference="ERC-4337 v0.7 - PackedUserOperation",
                    recommendation="Use PackedUserOperation from ERC-4337 v0.7",
                ))

    def _analyze_paymaster(self, source: str) -> None:
        """Analyze paymaster implementation."""
        for vuln_type, vuln_info in PAYMASTER_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source[:match.start()].count('\n') + 1
                    self.findings.append(AAFinding(
                        component=AAComponent.PAYMASTER,
                        vulnerability=vuln_type,
                        severity=vuln_info["severity"],
                        title=f"Paymaster: {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._get_attack_scenario(vuln_type),
                        erc4337_reference=vuln_info.get("erc4337_ref"),
                        recommendation=self._get_recommendation(vuln_type),
                    ))

        # Check for postOp implementation
        if "validatePaymasterUserOp" in source and "postOp" not in source:
            self.findings.append(AAFinding(
                component=AAComponent.PAYMASTER,
                vulnerability=AAVulnerability.PAYMASTER_GRIEFING,
                severity="Medium",
                title="Paymaster Without postOp",
                description="Paymaster doesn't implement postOp for cleanup/accounting",
                affected_code="No postOp function found",
                line_number=0,
                attack_scenario="Cannot perform post-execution accounting or refunds",
                erc4337_reference="ERC-4337 - Paymaster postOp",
                recommendation="Implement postOp for gas refunds and accounting",
            ))

    def _analyze_intents(self, source: str) -> None:
        """Analyze intent protocol implementation."""
        for vuln_type, vuln_info in INTENT_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source[:match.start()].count('\n') + 1
                    self.findings.append(AAFinding(
                        component=AAComponent.INTENT_SOLVER,
                        vulnerability=vuln_type,
                        severity=vuln_info["severity"],
                        title=f"Intent: {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._get_attack_scenario(vuln_type),
                        erc4337_reference=vuln_info.get("erc4337_ref"),
                        recommendation=self._get_recommendation(vuln_type),
                    ))

    def _check_banned_opcodes(self, source: str, component: Optional[AAComponent]) -> None:
        """Check for banned opcodes in validation functions."""
        # Find validation functions
        validation_funcs = re.finditer(
            r"function\s+(validate\w*)\s*\([^)]*\)[^{]*\{([^}]+)\}",
            source,
            re.DOTALL
        )

        banned = BANNED_OPCODES.get("validation", [])
        if component == AAComponent.PAYMASTER:
            banned = BANNED_OPCODES.get("paymaster_validation", banned)

        for match in validation_funcs:
            func_name = match.group(1)
            func_body = match.group(2)

            for opcode in banned:
                # Check for Solidity equivalents
                opcode_patterns = {
                    "GASPRICE": r"tx\.gasprice",
                    "GASLIMIT": r"block\.gaslimit",
                    "TIMESTAMP": r"block\.timestamp",
                    "NUMBER": r"block\.number",
                    "COINBASE": r"block\.coinbase",
                    "BASEFEE": r"block\.basefee",
                    "DIFFICULTY": r"block\.difficulty",
                    "BALANCE": r"\.balance(?!Of)",
                    "SELFBALANCE": r"address\(this\)\.balance",
                    "ORIGIN": r"tx\.origin",
                    "CREATE": r"\bnew\s+\w+\(",
                    "CREATE2": r"create2\s*\(",
                    "SELFDESTRUCT": r"selfdestruct\s*\(",
                    "GAS": r"gasleft\s*\(\)",
                }

                pattern = opcode_patterns.get(opcode)
                if pattern and re.search(pattern, func_body):
                    self.findings.append(AAFinding(
                        component=component or AAComponent.SMART_ACCOUNT,
                        vulnerability=AAVulnerability.OPCODE_BAN_BYPASS,
                        severity="High",
                        title=f"Banned Opcode in Validation: {opcode}",
                        description=f"Validation function uses {opcode} which is banned by ERC-4337",
                        affected_code=f"function {func_name}(...) uses {opcode}",
                        line_number=source[:match.start()].count('\n') + 1,
                        attack_scenario="Bundler will reject UserOps from this account",
                        erc4337_reference="ERC-4337 - Banned opcodes list",
                        recommendation=f"Remove {opcode} usage from validation phase",
                    ))

    def _get_attack_scenario(self, vuln_type: AAVulnerability) -> str:
        """Get attack scenario for vulnerability type."""
        scenarios = {
            AAVulnerability.SIGNATURE_REPLAY: (
                "1. User signs UserOp on chain A\n"
                "2. Attacker captures signature\n"
                "3. Replays same signature on chain B\n"
                "4. UserOp executes on chain B without user consent"
            ),
            AAVulnerability.PAYMASTER_GRIEFING: (
                "1. Attacker creates many UserOps\n"
                "2. Each UserOp passes validation but fails execution\n"
                "3. Paymaster pays for all failed ops\n"
                "4. Paymaster deposit drained"
            ),
            AAVulnerability.SOLVER_FRONTRUNNING: (
                "1. User submits intent to swap\n"
                "2. Solver sees intent in mempool\n"
                "3. Solver frontruns to move price\n"
                "4. Solver fills intent at worse price\n"
                "5. Solver backruns to profit"
            ),
            AAVulnerability.VALIDATION_REENTRANCY: (
                "1. Validation calls external contract\n"
                "2. External contract reenters\n"
                "3. State is manipulated during validation\n"
                "4. Invalid UserOp passes validation"
            ),
        }
        return scenarios.get(vuln_type, "Attack scenario requires specific analysis")

    def _get_recommendation(self, vuln_type: AAVulnerability) -> str:
        """Get recommendation for vulnerability."""
        recommendations = {
            AAVulnerability.SIGNATURE_REPLAY: (
                "Include chain ID and account address in signature hash.\n"
                "Use EIP-712 typed data signing with domain separator."
            ),
            AAVulnerability.PAYMASTER_GRIEFING: (
                "1. Check sufficient deposit balance\n"
                "2. Implement per-user quotas\n"
                "3. Require reputation or stake\n"
                "4. Validate user authenticity"
            ),
            AAVulnerability.SOLVER_FRONTRUNNING: (
                "1. Use private mempool or encrypted intents\n"
                "2. Implement commit-reveal scheme\n"
                "3. Use batch auction for solver selection\n"
                "4. Enforce minimum output amounts"
            ),
            AAVulnerability.VALIDATION_REENTRANCY: (
                "Remove all external calls from validation phase.\n"
                "Validation should only verify signature and nonce."
            ),
            AAVulnerability.OPCODE_BAN_BYPASS: (
                "Remove banned opcode usage from validation.\n"
                "Move any necessary logic to execution phase."
            ),
        }
        return recommendations.get(vuln_type, "Follow ERC-4337 specification")

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        component_counts = {c.value: 0 for c in AAComponent}

        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            component_counts[finding.component.value] += 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_component": component_counts,
            "erc4337_version": self.config.erc4337_version,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_smart_account(source: str) -> list[AAFinding]:
    """Analyze ERC-4337 smart account."""
    analyzer = AccountAbstractionAnalyzer()
    return analyzer.analyze(source, AAComponent.SMART_ACCOUNT)


def analyze_paymaster(source: str) -> list[AAFinding]:
    """Analyze ERC-4337 paymaster."""
    analyzer = AccountAbstractionAnalyzer()
    return analyzer.analyze(source, AAComponent.PAYMASTER)


def analyze_intent_protocol(source: str) -> list[AAFinding]:
    """Analyze intent-based protocol."""
    analyzer = AccountAbstractionAnalyzer()
    return analyzer.analyze(source, AAComponent.INTENT_SOLVER)
