"""
Cross-Chain & Bridge Security Analyzer

Analyzes bridge protocols for vulnerabilities that have caused $2B+ in losses:
- Ronin Bridge ($625M)
- Wormhole ($320M)
- Nomad ($190M)
- Harmony Horizon ($100M)

Key attack vectors:
1. Message validation failures
2. Signature verification bypasses
3. Replay attacks across chains
4. Finality assumption violations
5. Relayer/validator compromise
6. L2 sequencer centralization risks
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class BridgeType(Enum):
    """Types of bridge architectures."""
    LOCK_AND_MINT = "lock_and_mint"          # Lock on source, mint on dest
    BURN_AND_MINT = "burn_and_mint"          # Burn on source, mint on dest
    LIQUIDITY_POOL = "liquidity_pool"        # LP-based bridges
    ATOMIC_SWAP = "atomic_swap"              # HTLC-based
    OPTIMISTIC = "optimistic"                # Fraud proof based
    ZK_ROLLUP = "zk_rollup"                  # Validity proof based
    NATIVE = "native"                        # L1 <-> L2 canonical


class ChainType(Enum):
    """Chain types with different security assumptions."""
    L1 = "l1"                                # Ethereum mainnet
    OPTIMISTIC_L2 = "optimistic_l2"          # Arbitrum, Optimism
    ZK_L2 = "zk_l2"                          # zkSync, StarkNet
    SIDECHAIN = "sidechain"                  # Polygon PoS
    ALT_L1 = "alt_l1"                        # Solana, Avalanche


class BridgeVulnerability(Enum):
    """Known bridge vulnerability categories."""
    MESSAGE_VALIDATION = "message_validation"
    SIGNATURE_VERIFICATION = "signature_verification"
    REPLAY_ATTACK = "replay_attack"
    FINALITY_ASSUMPTION = "finality_assumption"
    RELAYER_TRUST = "relayer_trust"
    SEQUENCER_CENTRALIZATION = "sequencer_centralization"
    ESCAPE_HATCH_MISSING = "escape_hatch_missing"
    MERKLE_PROOF_VALIDATION = "merkle_proof_validation"
    NONCE_MANAGEMENT = "nonce_management"
    CHAIN_ID_VALIDATION = "chain_id_validation"


@dataclass
class BridgeFinding:
    """A bridge-specific security finding."""
    vulnerability: BridgeVulnerability
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    affected_code: str
    line_number: int
    attack_scenario: str
    historical_exploit: Optional[str]  # Reference to similar past exploit
    recommendation: str
    poc_concept: str


@dataclass
class BridgeConfig:
    """Configuration for bridge analysis."""
    bridge_type: BridgeType = BridgeType.LOCK_AND_MINT
    source_chain: ChainType = ChainType.L1
    dest_chain: ChainType = ChainType.OPTIMISTIC_L2
    check_escape_hatch: bool = True
    check_finality: bool = True
    check_relayer_trust: bool = True


# =============================================================================
# VULNERABILITY PATTERNS
# =============================================================================

BRIDGE_VULNERABILITY_PATTERNS = {
    BridgeVulnerability.MESSAGE_VALIDATION: {
        "patterns": [
            # Missing sender validation
            r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)[^{]*\{[^}]*(?!require\s*\([^)]*msg\.sender)",
            # Unchecked message origin
            r"processMessage\s*\([^)]*\)\s*(?!.*verifyOrigin)",
            # Missing message hash verification
            r"receiveMessage\s*\([^)]*\)\s*(?!.*keccak256)",
        ],
        "description": "Message origin or content not properly validated",
        "historical": "Nomad Bridge - arbitrary message injection ($190M)",
    },
    BridgeVulnerability.SIGNATURE_VERIFICATION: {
        "patterns": [
            # ecrecover without zero check
            r"ecrecover\s*\([^)]+\)\s*(?!.*!=\s*address\(0\))",
            # Missing signature length check
            r"function\s+verify\w*\([^)]*bytes\s+(?:memory\s+)?signature[^)]*\)(?!.*\.length)",
            # Single signature for multisig
            r"require\s*\(\s*signatures\.length\s*>=\s*1\s*\)",
        ],
        "description": "Signature verification can be bypassed",
        "historical": "Ronin Bridge - compromised validators ($625M)",
    },
    BridgeVulnerability.REPLAY_ATTACK: {
        "patterns": [
            # Missing nonce tracking
            r"function\s+execute\w*\([^)]*\)(?!.*nonce)(?!.*usedNonces)",
            # No chain ID in message hash
            r"keccak256\s*\([^)]*\)(?!.*chainId)(?!.*block\.chainid)",
            # Missing processed message tracking
            r"processMessage(?!.*processed\[)",
        ],
        "description": "Message can be replayed on same or different chain",
        "historical": "Multiple bridges - cross-chain replay attacks",
    },
    BridgeVulnerability.FINALITY_ASSUMPTION: {
        "patterns": [
            # No confirmation delay
            r"function\s+finalize\w*\([^)]*\)(?!.*block\.number.*confirmations)",
            # Immediate execution without delay
            r"receiveMessage[^}]*\{[^}]*(?:transfer|call)\s*\(",
        ],
        "description": "Message processed before source chain finality",
        "historical": "Various - reorg attacks on bridges",
    },
    BridgeVulnerability.MERKLE_PROOF_VALIDATION: {
        "patterns": [
            # Unchecked proof length
            r"function\s+verify\w*Proof\([^)]*bytes32\[\]\s+(?:memory\s+)?proof[^)]*\)(?!.*proof\.length)",
            # Missing leaf validation
            r"MerkleProof\.verify\([^)]*\)(?!.*keccak256\s*\(\s*abi\.encode)",
        ],
        "description": "Merkle proof validation insufficient",
        "historical": "BNB Bridge - fake proof acceptance ($570M attempted)",
    },
    BridgeVulnerability.ESCAPE_HATCH_MISSING: {
        "patterns": [
            # No emergency withdrawal
            r"contract\s+\w+Bridge(?!.*emergencyWithdraw)(?!.*rescue)",
            # No pause mechanism
            r"contract\s+\w+Bridge(?!.*Pausable)(?!.*pause\s*\()",
        ],
        "description": "No emergency exit mechanism for stuck funds",
        "historical": "Various - funds stuck in bridges permanently",
    },
    BridgeVulnerability.SEQUENCER_CENTRALIZATION: {
        "patterns": [
            # Single sequencer
            r"address\s+(?:public\s+)?sequencer\s*;",
            # No sequencer rotation
            r"onlySequencer(?!.*sequencerRotation)",
        ],
        "description": "Centralized sequencer can censor or reorder",
        "historical": "L2 centralization risks - ongoing concern",
    },
}


# =============================================================================
# L2 SPECIFIC RISKS
# =============================================================================

L2_RISK_PATTERNS = {
    "optimistic_l2": {
        "challenge_period": {
            "pattern": r"challengePeriod\s*=\s*(\d+)",
            "check": lambda x: int(x) < 7 * 24 * 3600,  # < 7 days is risky
            "risk": "Challenge period too short for fraud proofs",
        },
        "sequencer_downtime": {
            "pattern": r"sequencerInactivityThreshold",
            "check": lambda x: True,  # Must exist
            "risk": "No handling for sequencer downtime",
        },
        "force_inclusion": {
            "pattern": r"forceInclusion|delayedInbox",
            "check": lambda x: True,  # Must exist
            "risk": "No force inclusion mechanism - censorship possible",
        },
    },
    "zk_l2": {
        "prover_centralization": {
            "pattern": r"address\s+(?:public\s+)?prover\s*;",
            "check": lambda x: True,
            "risk": "Centralized prover can halt chain",
        },
        "escape_hatch": {
            "pattern": r"emergencyMode|exodus",
            "check": lambda x: True,
            "risk": "No escape hatch if prover stops",
        },
    },
}


# =============================================================================
# BRIDGE INVARIANTS
# =============================================================================

BRIDGE_INVARIANTS = {
    "conservation": {
        "description": "Total locked on source == Total minted on dest",
        "check": "assert(sourceChain.totalLocked() == destChain.totalMinted())",
        "critical": True,
    },
    "no_double_spend": {
        "description": "Each deposit can only be claimed once",
        "check": "assert(!processedDeposits[depositId] || claimed[depositId] == 0)",
        "critical": True,
    },
    "finality_respected": {
        "description": "Only finalized messages are processed",
        "check": "assert(message.blockNumber + confirmations <= block.number)",
        "critical": True,
    },
    "authorized_relayers": {
        "description": "Only authorized relayers can relay messages",
        "check": "assert(isAuthorizedRelayer[msg.sender])",
        "critical": True,
    },
    "chain_id_correct": {
        "description": "Messages are for the correct destination chain",
        "check": "assert(message.destChainId == block.chainid)",
        "critical": True,
    },
}


class BridgeSecurityAnalyzer:
    """
    Comprehensive bridge security analyzer.

    Analyzes cross-chain bridge protocols for:
    - Message validation vulnerabilities
    - Signature verification issues
    - Replay attack vectors
    - Finality assumption problems
    - L2-specific risks
    - Missing escape hatches
    """

    def __init__(self, config: Optional[BridgeConfig] = None):
        self.config = config or BridgeConfig()
        self.findings: list[BridgeFinding] = []

    def analyze(self, source_code: str, contract_name: str = "Bridge") -> list[BridgeFinding]:
        """
        Run complete bridge security analysis.

        Args:
            source_code: Solidity source code
            contract_name: Name of the bridge contract

        Returns:
            List of bridge-specific findings
        """
        self.findings = []

        # 1. Pattern-based vulnerability detection
        self._check_vulnerability_patterns(source_code)

        # 2. L2-specific risk analysis
        if self.config.dest_chain in (ChainType.OPTIMISTIC_L2, ChainType.ZK_L2):
            self._check_l2_risks(source_code)

        # 3. Invariant analysis
        self._check_invariants(source_code)

        # 4. Escape hatch verification
        if self.config.check_escape_hatch:
            self._check_escape_hatch(source_code)

        # 5. Relayer trust analysis
        if self.config.check_relayer_trust:
            self._check_relayer_trust(source_code)

        return self.findings

    def _check_vulnerability_patterns(self, source: str) -> None:
        """Check for known vulnerability patterns."""
        for vuln_type, vuln_info in BRIDGE_VULNERABILITY_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source[:match.start()].count('\n') + 1
                    self.findings.append(BridgeFinding(
                        vulnerability=vuln_type,
                        severity=self._determine_severity(vuln_type),
                        title=f"Potential {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._generate_attack_scenario(vuln_type),
                        historical_exploit=vuln_info.get("historical"),
                        recommendation=self._get_recommendation(vuln_type),
                        poc_concept=self._generate_poc_concept(vuln_type),
                    ))

    def _check_l2_risks(self, source: str) -> None:
        """Check for L2-specific risks."""
        chain_type = "optimistic_l2" if self.config.dest_chain == ChainType.OPTIMISTIC_L2 else "zk_l2"
        risks = L2_RISK_PATTERNS.get(chain_type, {})

        for risk_name, risk_info in risks.items():
            match = re.search(risk_info["pattern"], source)
            if not match:
                # Pattern should exist but doesn't
                self.findings.append(BridgeFinding(
                    vulnerability=BridgeVulnerability.SEQUENCER_CENTRALIZATION,
                    severity="High",
                    title=f"Missing {risk_name.replace('_', ' ').title()}",
                    description=risk_info["risk"],
                    affected_code="Pattern not found in contract",
                    line_number=0,
                    attack_scenario=f"L2 {risk_name} vulnerability",
                    historical_exploit=None,
                    recommendation=f"Implement {risk_name} mechanism",
                    poc_concept="N/A - missing feature",
                ))

    def _check_invariants(self, source: str) -> None:
        """Verify bridge invariants are enforced."""
        for inv_name, inv_info in BRIDGE_INVARIANTS.items():
            # Check if invariant enforcement exists
            check_pattern = inv_info["check"].replace("(", r"\(").replace(")", r"\)")
            if not re.search(check_pattern, source, re.IGNORECASE):
                # Look for alternative implementations
                if not self._invariant_implemented(inv_name, source):
                    self.findings.append(BridgeFinding(
                        vulnerability=BridgeVulnerability.MESSAGE_VALIDATION,
                        severity="Critical" if inv_info["critical"] else "High",
                        title=f"Missing Invariant: {inv_info['description']}",
                        description=f"Bridge does not enforce: {inv_info['description']}",
                        affected_code="Invariant not found",
                        line_number=0,
                        attack_scenario=f"Violate {inv_name} invariant to exploit bridge",
                        historical_exploit=None,
                        recommendation=f"Add check: {inv_info['check']}",
                        poc_concept=self._generate_invariant_poc(inv_name),
                    ))

    def _check_escape_hatch(self, source: str) -> None:
        """Verify emergency exit mechanisms exist."""
        escape_patterns = [
            r"function\s+emergencyWithdraw",
            r"function\s+rescue\w*",
            r"function\s+exodus",
            r"Pausable",
            r"function\s+pause\s*\(",
        ]

        has_escape = any(re.search(p, source) for p in escape_patterns)

        if not has_escape:
            self.findings.append(BridgeFinding(
                vulnerability=BridgeVulnerability.ESCAPE_HATCH_MISSING,
                severity="High",
                title="No Emergency Exit Mechanism",
                description="Bridge has no way for users to exit if bridge is compromised",
                affected_code="No emergency withdrawal function found",
                line_number=0,
                attack_scenario="If bridge is compromised, user funds are permanently stuck",
                historical_exploit="Various bridges - funds stuck due to missing escape hatches",
                recommendation="Implement emergencyWithdraw with appropriate timelock",
                poc_concept="N/A - missing feature vulnerability",
            ))

    def _check_relayer_trust(self, source: str) -> None:
        """Analyze relayer trust assumptions."""
        # Check for single relayer
        single_relayer = re.search(r"address\s+(?:public\s+)?relayer\s*;", source)
        if single_relayer:
            self.findings.append(BridgeFinding(
                vulnerability=BridgeVulnerability.RELAYER_TRUST,
                severity="High",
                title="Single Relayer Trust Assumption",
                description="Bridge relies on a single relayer - single point of failure",
                affected_code=single_relayer.group(0),
                line_number=source[:single_relayer.start()].count('\n') + 1,
                attack_scenario="Compromise relayer to steal all bridged funds",
                historical_exploit="Ronin Bridge - 5/9 validators compromised ($625M)",
                recommendation="Use threshold signature scheme with multiple relayers",
                poc_concept="Compromise relayer private key, submit malicious messages",
            ))

        # Check for multisig threshold
        threshold_match = re.search(r"threshold\s*=\s*(\d+)", source)
        total_match = re.search(r"(?:totalValidators|validatorCount)\s*=\s*(\d+)", source)

        if threshold_match and total_match:
            threshold = int(threshold_match.group(1))
            total = int(total_match.group(1))
            if threshold < total * 2 // 3:
                self.findings.append(BridgeFinding(
                    vulnerability=BridgeVulnerability.RELAYER_TRUST,
                    severity="Medium",
                    title=f"Low Validator Threshold ({threshold}/{total})",
                    description=f"Only {threshold} of {total} validators needed - should be 2/3+",
                    affected_code=f"threshold = {threshold}",
                    line_number=source[:threshold_match.start()].count('\n') + 1,
                    attack_scenario=f"Compromise {threshold} validators to control bridge",
                    historical_exploit="Ronin - 5/9 threshold was too low",
                    recommendation=f"Increase threshold to at least {total * 2 // 3 + 1}",
                    poc_concept="Compromise threshold validators, sign malicious messages",
                ))

    def _determine_severity(self, vuln_type: BridgeVulnerability) -> str:
        """Determine severity based on vulnerability type."""
        critical = {
            BridgeVulnerability.MESSAGE_VALIDATION,
            BridgeVulnerability.SIGNATURE_VERIFICATION,
            BridgeVulnerability.REPLAY_ATTACK,
            BridgeVulnerability.MERKLE_PROOF_VALIDATION,
        }
        high = {
            BridgeVulnerability.FINALITY_ASSUMPTION,
            BridgeVulnerability.RELAYER_TRUST,
            BridgeVulnerability.ESCAPE_HATCH_MISSING,
        }

        if vuln_type in critical:
            return "Critical"
        elif vuln_type in high:
            return "High"
        else:
            return "Medium"

    def _generate_attack_scenario(self, vuln_type: BridgeVulnerability) -> str:
        """Generate attack scenario for vulnerability type."""
        scenarios = {
            BridgeVulnerability.MESSAGE_VALIDATION:
                "1. Craft malicious message with fake deposit\n"
                "2. Submit to bridge without proper validation\n"
                "3. Claim tokens on destination chain",
            BridgeVulnerability.SIGNATURE_VERIFICATION:
                "1. Find signature verification bypass\n"
                "2. Forge validator signatures\n"
                "3. Execute unauthorized withdrawals",
            BridgeVulnerability.REPLAY_ATTACK:
                "1. Capture valid bridge message\n"
                "2. Replay on same or different chain\n"
                "3. Double-claim tokens",
            BridgeVulnerability.FINALITY_ASSUMPTION:
                "1. Submit deposit on source chain\n"
                "2. Claim on destination before finality\n"
                "3. Reorg source chain to cancel deposit",
            BridgeVulnerability.MERKLE_PROOF_VALIDATION:
                "1. Craft fake Merkle proof\n"
                "2. Submit to bridge verifier\n"
                "3. Claim non-existent deposits",
        }
        return scenarios.get(vuln_type, "Attack scenario requires further analysis")

    def _get_recommendation(self, vuln_type: BridgeVulnerability) -> str:
        """Get remediation recommendation."""
        recommendations = {
            BridgeVulnerability.MESSAGE_VALIDATION:
                "Validate message origin, hash, and content. Use merkle proofs for inclusion.",
            BridgeVulnerability.SIGNATURE_VERIFICATION:
                "Check ecrecover != address(0), verify signature length, use threshold sigs.",
            BridgeVulnerability.REPLAY_ATTACK:
                "Include chain ID and nonce in message hash. Track processed messages.",
            BridgeVulnerability.FINALITY_ASSUMPTION:
                "Wait for sufficient confirmations before processing. Use finality gadgets.",
            BridgeVulnerability.RELAYER_TRUST:
                "Use decentralized relayer set with 2/3+ threshold.",
            BridgeVulnerability.ESCAPE_HATCH_MISSING:
                "Implement emergency withdrawal with appropriate delay.",
            BridgeVulnerability.MERKLE_PROOF_VALIDATION:
                "Validate proof length, leaf format, and root freshness.",
        }
        return recommendations.get(vuln_type, "Consult bridge security best practices")

    def _generate_poc_concept(self, vuln_type: BridgeVulnerability) -> str:
        """Generate PoC concept code."""
        pocs = {
            BridgeVulnerability.MESSAGE_VALIDATION: '''
// Forge malicious message
bytes memory fakeMessage = abi.encode(
    attacker,      // recipient
    1000000e18,    // amount (fake)
    bytes32(0)     // fake deposit hash
);
bridge.processMessage(fakeMessage);
''',
            BridgeVulnerability.SIGNATURE_VERIFICATION: '''
// Bypass signature check
bytes memory emptySig = "";
// or craft sig that recovers to address(0)
bytes memory badSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
bridge.executeWithSignature(message, badSig);
''',
            BridgeVulnerability.REPLAY_ATTACK: '''
// Capture valid message on chain A
bytes memory validMessage = getValidMessage();
// Replay on chain B (or same chain)
bridge.processMessage(validMessage); // First claim
bridge.processMessage(validMessage); // Replay!
''',
        }
        return pocs.get(vuln_type, "// PoC requires custom implementation")

    def _invariant_implemented(self, inv_name: str, source: str) -> bool:
        """Check if invariant is implemented via alternative patterns."""
        alternatives = {
            "conservation": [r"totalLocked", r"totalMinted", r"balanceOf.*bridge"],
            "no_double_spend": [r"processed\[", r"claimed\[", r"usedNonces"],
            "finality_respected": [r"confirmations", r"finalized", r"block\.number"],
            "authorized_relayers": [r"isRelayer", r"validators\[", r"onlyRelayer"],
            "chain_id_correct": [r"chainId", r"block\.chainid", r"destChain"],
        }

        patterns = alternatives.get(inv_name, [])
        return any(re.search(p, source) for p in patterns)

    def _generate_invariant_poc(self, inv_name: str) -> str:
        """Generate PoC for invariant violation."""
        pocs = {
            "conservation": '''
// Mint tokens without corresponding lock
bridge.mint(attacker, 1000000e18);
// No lock on source chain - conservation violated
''',
            "no_double_spend": '''
// Claim same deposit twice
bridge.claim(depositId);
bridge.claim(depositId); // Double spend!
''',
            "finality_respected": '''
// Claim before finality
bridge.claim(depositId); // Block N
// Reorg source chain at block N-1
// Deposit no longer exists but tokens claimed
''',
        }
        return pocs.get(inv_name, "// Invariant violation PoC")

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_vulnerability": {
                v.value: len([f for f in self.findings if f.vulnerability == v])
                for v in BridgeVulnerability
            },
            "bridge_type": self.config.bridge_type.value,
            "source_chain": self.config.source_chain.value,
            "dest_chain": self.config.dest_chain.value,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_bridge(
    source_code: str,
    bridge_type: str = "lock_and_mint",
    source_chain: str = "l1",
    dest_chain: str = "optimistic_l2",
) -> list[BridgeFinding]:
    """
    Convenience function for bridge analysis.

    Args:
        source_code: Solidity source
        bridge_type: Type of bridge architecture
        source_chain: Source chain type
        dest_chain: Destination chain type

    Returns:
        List of findings
    """
    config = BridgeConfig(
        bridge_type=BridgeType(bridge_type),
        source_chain=ChainType(source_chain),
        dest_chain=ChainType(dest_chain),
    )
    analyzer = BridgeSecurityAnalyzer(config)
    return analyzer.analyze(source_code)
