"""
Upgrade Safety Analyzer

Analyzes proxy upgrade patterns for security vulnerabilities:
- Storage layout collisions
- Uninitialized implementation contracts
- Missing initializer protection
- Selfdestruct in implementation
- Function selector clashes
- Upgrade access control issues

Common proxy patterns analyzed:
- TransparentUpgradeableProxy (OpenZeppelin)
- UUPS (ERC-1822)
- Beacon Proxy
- Diamond (ERC-2535)
- Minimal Proxy (ERC-1167)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re
import hashlib


class ProxyPattern(Enum):
    """Common proxy upgrade patterns."""
    TRANSPARENT = "transparent"          # OpenZeppelin TransparentProxy
    UUPS = "uups"                        # Universal Upgradeable Proxy Standard
    BEACON = "beacon"                    # Beacon Proxy
    DIAMOND = "diamond"                  # ERC-2535 Diamond
    MINIMAL = "minimal"                  # ERC-1167 Minimal Proxy
    CUSTOM = "custom"                    # Non-standard pattern


class UpgradeVulnerability(Enum):
    """Upgrade-specific vulnerability types."""
    STORAGE_COLLISION = "storage_collision"
    UNINITIALIZED_IMPLEMENTATION = "uninitialized_implementation"
    MISSING_INITIALIZER_MODIFIER = "missing_initializer_modifier"
    SELFDESTRUCT_IN_IMPL = "selfdestruct_in_impl"
    FUNCTION_SELECTOR_CLASH = "function_selector_clash"
    UNPROTECTED_UPGRADE = "unprotected_upgrade"
    MISSING_STORAGE_GAP = "missing_storage_gap"
    INITIALIZER_REENTRANCY = "initializer_reentrancy"
    DELEGATECALL_TO_UNTRUSTED = "delegatecall_to_untrusted"
    IMPLEMENTATION_NOT_CONTRACT = "implementation_not_contract"


@dataclass
class StorageSlot:
    """Represents a storage slot in a contract."""
    name: str
    var_type: str
    slot: int
    offset: int = 0
    size: int = 32  # bytes


@dataclass
class StorageLayout:
    """Complete storage layout of a contract."""
    contract_name: str
    slots: list[StorageSlot] = field(default_factory=list)
    inheritance_chain: list[str] = field(default_factory=list)


@dataclass
class StorageCollision:
    """Detected storage collision between versions."""
    slot: int
    v1_var: StorageSlot
    v2_var: StorageSlot
    collision_type: str  # "type_change", "removed", "reordered"
    severity: str
    description: str


@dataclass
class UpgradeFinding:
    """An upgrade safety finding."""
    vulnerability: UpgradeVulnerability
    severity: str
    title: str
    description: str
    affected_code: str
    line_number: int
    recommendation: str
    poc_concept: str


@dataclass
class UpgradeConfig:
    """Configuration for upgrade analysis."""
    proxy_pattern: ProxyPattern = ProxyPattern.TRANSPARENT
    check_storage_layout: bool = True
    check_initializers: bool = True
    check_selfdestruct: bool = True
    check_access_control: bool = True
    storage_gap_size: int = 50  # Recommended gap size


# =============================================================================
# STORAGE LAYOUT ANALYSIS
# =============================================================================

class StorageLayoutAnalyzer:
    """
    Analyze and compare storage layouts between contract versions.

    Storage collision is one of the most common upgrade bugs:
    - Reordering variables
    - Changing types
    - Removing variables
    - Missing storage gaps in inheritance
    """

    # Size of types in bytes
    TYPE_SIZES = {
        "bool": 1,
        "uint8": 1, "int8": 1,
        "uint16": 2, "int16": 2,
        "uint32": 4, "int32": 4,
        "uint64": 8, "int64": 8,
        "uint128": 16, "int128": 16,
        "uint256": 32, "int256": 32, "uint": 32, "int": 32,
        "address": 20,
        "bytes32": 32,
        "bytes": 32,  # Dynamic, but slot is 32
        "string": 32,  # Dynamic, but slot is 32
    }

    def parse_storage_layout(self, source: str, contract_name: str) -> StorageLayout:
        """
        Parse storage layout from source code.

        Note: For production use, prefer Foundry's `forge inspect <contract> storage-layout`
        """
        layout = StorageLayout(contract_name=contract_name)

        # Extract inheritance
        inheritance_match = re.search(
            rf"contract\s+{contract_name}\s+is\s+([^{{]+)",
            source
        )
        if inheritance_match:
            parents = [p.strip() for p in inheritance_match.group(1).split(",")]
            layout.inheritance_chain = parents

        # Extract state variables (simplified - real implementation uses AST)
        var_pattern = re.compile(
            r"^\s*(mapping\s*\([^)]+\)|"
            r"uint\d*|int\d*|address|bool|bytes\d*|string|"
            r"\w+(?:\[\d*\])?)\s+"
            r"(?:public\s+|private\s+|internal\s+)?"
            r"(\w+)\s*(?:=|;)",
            re.MULTILINE
        )

        current_slot = 0
        current_offset = 0

        for match in var_pattern.finditer(source):
            var_type = match.group(1).strip()
            var_name = match.group(2)

            # Skip constants and immutables
            line = source[source.rfind('\n', 0, match.start())+1:match.end()]
            if 'constant' in line or 'immutable' in line:
                continue

            size = self._get_type_size(var_type)

            # Check if fits in current slot
            if current_offset + size > 32:
                current_slot += 1
                current_offset = 0

            layout.slots.append(StorageSlot(
                name=var_name,
                var_type=var_type,
                slot=current_slot,
                offset=current_offset,
                size=size,
            ))

            # Mappings and dynamic arrays take full slot
            if var_type.startswith("mapping") or "[]" in var_type:
                current_slot += 1
                current_offset = 0
            else:
                current_offset += size
                if current_offset >= 32:
                    current_slot += 1
                    current_offset = 0

        return layout

    def _get_type_size(self, var_type: str) -> int:
        """Get size of type in bytes."""
        # Handle mappings and arrays
        if var_type.startswith("mapping") or "[]" in var_type:
            return 32

        # Handle fixed arrays
        array_match = re.match(r"(\w+)\[(\d+)\]", var_type)
        if array_match:
            base_type = array_match.group(1)
            count = int(array_match.group(2))
            return self.TYPE_SIZES.get(base_type, 32) * count

        return self.TYPE_SIZES.get(var_type, 32)

    def compare_layouts(
        self,
        v1: StorageLayout,
        v2: StorageLayout,
    ) -> list[StorageCollision]:
        """
        Compare storage layouts between two versions.

        Returns list of collisions/incompatibilities.
        """
        collisions = []

        # Build slot maps
        v1_slots = {s.slot: s for s in v1.slots}
        v2_slots = {s.slot: s for s in v2.slots}

        # Check each v1 slot
        for slot, v1_var in v1_slots.items():
            if slot in v2_slots:
                v2_var = v2_slots[slot]

                # Type change
                if v1_var.var_type != v2_var.var_type:
                    collisions.append(StorageCollision(
                        slot=slot,
                        v1_var=v1_var,
                        v2_var=v2_var,
                        collision_type="type_change",
                        severity="Critical",
                        description=f"Type changed from {v1_var.var_type} to {v2_var.var_type}",
                    ))

                # Name change (potential reorder)
                elif v1_var.name != v2_var.name:
                    collisions.append(StorageCollision(
                        slot=slot,
                        v1_var=v1_var,
                        v2_var=v2_var,
                        collision_type="reordered",
                        severity="High",
                        description=f"Variable at slot {slot} changed from {v1_var.name} to {v2_var.name}",
                    ))

            else:
                # Variable removed (gap created)
                collisions.append(StorageCollision(
                    slot=slot,
                    v1_var=v1_var,
                    v2_var=StorageSlot("(removed)", "", slot),
                    collision_type="removed",
                    severity="High",
                    description=f"Variable {v1_var.name} at slot {slot} was removed",
                ))

        return collisions


# =============================================================================
# VULNERABILITY PATTERNS
# =============================================================================

UPGRADE_VULNERABILITY_PATTERNS = {
    UpgradeVulnerability.UNINITIALIZED_IMPLEMENTATION: {
        "patterns": [
            # Implementation without constructor protection
            r"contract\s+\w+(?:Impl|Implementation|V\d+)(?!.*constructor\s*\(\s*\)\s*\{[^}]*_disableInitializers)",
            # Missing _disableInitializers call
            r"constructor\s*\(\s*\)\s*\{(?!.*_disableInitializers)",
        ],
        "description": "Implementation contract can be initialized by attacker",
        "severity": "Critical",
        "recommendation": "Call _disableInitializers() in constructor",
    },
    UpgradeVulnerability.MISSING_INITIALIZER_MODIFIER: {
        "patterns": [
            # Initialize function without modifier
            r"function\s+initialize\s*\([^)]*\)\s*(?:external|public)(?!.*initializer)",
            # Setup without protection
            r"function\s+(?:setup|init|configure)\s*\([^)]*\)\s*(?:external|public)(?!.*initializer)(?!.*onlyOwner)",
        ],
        "description": "Initializer can be called multiple times",
        "severity": "Critical",
        "recommendation": "Add 'initializer' modifier from OpenZeppelin",
    },
    UpgradeVulnerability.SELFDESTRUCT_IN_IMPL: {
        "patterns": [
            r"selfdestruct\s*\(",
            r"suicide\s*\(",  # Deprecated but still valid
        ],
        "description": "selfdestruct in implementation destroys proxy storage",
        "severity": "Critical",
        "recommendation": "Remove selfdestruct from implementation",
    },
    UpgradeVulnerability.UNPROTECTED_UPGRADE: {
        "patterns": [
            # upgradeTo without access control
            r"function\s+upgradeTo\s*\([^)]*\)\s*(?:external|public)(?!.*onlyOwner)(?!.*onlyRole)(?!.*onlyAdmin)",
            # _authorizeUpgrade not protected (UUPS)
            r"function\s+_authorizeUpgrade\s*\([^)]*\)\s*(?:internal|public)(?!.*onlyOwner)",
        ],
        "description": "Upgrade function not protected by access control",
        "severity": "Critical",
        "recommendation": "Add onlyOwner or equivalent modifier",
    },
    UpgradeVulnerability.MISSING_STORAGE_GAP: {
        "patterns": [
            # Base contract without __gap
            r"contract\s+\w+(?:Base|Upgradeable|Storage)\s+is(?!.*uint256\[\d+\]\s+(?:private\s+)?__gap)",
        ],
        "description": "Missing storage gap for future upgrades",
        "severity": "Medium",
        "recommendation": "Add uint256[50] private __gap; at end of contract",
    },
    UpgradeVulnerability.INITIALIZER_REENTRANCY: {
        "patterns": [
            # External call in initializer
            r"function\s+initialize[^}]*\{[^}]*(?:\.call|\.transfer|\.send|IERC20\([^)]+\)\.\w+)\s*\(",
        ],
        "description": "Initializer makes external calls (reentrancy risk)",
        "severity": "High",
        "recommendation": "Set state before external calls, use ReentrancyGuard",
    },
    UpgradeVulnerability.DELEGATECALL_TO_UNTRUSTED: {
        "patterns": [
            # delegatecall to user-provided address
            r"delegatecall\s*\([^)]*\)(?!.*onlyOwner)(?!.*trusted)",
            r"\.delegatecall\s*\(\s*abi\.encode",
        ],
        "description": "delegatecall to potentially untrusted address",
        "severity": "Critical",
        "recommendation": "Validate target address is trusted implementation",
    },
}


class UpgradeSafetyAnalyzer:
    """
    Comprehensive upgrade safety analyzer.

    Checks:
    1. Storage layout compatibility between versions
    2. Initializer security
    3. Implementation contract safety
    4. Upgrade access control
    5. Proxy-specific vulnerabilities
    """

    def __init__(self, config: Optional[UpgradeConfig] = None):
        self.config = config or UpgradeConfig()
        self.findings: list[UpgradeFinding] = []
        self.storage_analyzer = StorageLayoutAnalyzer()

    def analyze(
        self,
        source_code: str,
        contract_name: str = "Implementation",
    ) -> list[UpgradeFinding]:
        """
        Analyze single contract for upgrade safety issues.
        """
        self.findings = []

        # Pattern-based detection
        self._check_vulnerability_patterns(source_code)

        # Storage gap check
        if self.config.check_storage_layout:
            self._check_storage_gaps(source_code)

        # Initializer checks
        if self.config.check_initializers:
            self._check_initializer_safety(source_code)

        # Access control checks
        if self.config.check_access_control:
            self._check_upgrade_access_control(source_code)

        return self.findings

    def analyze_upgrade(
        self,
        v1_source: str,
        v2_source: str,
        v1_name: str = "ContractV1",
        v2_name: str = "ContractV2",
    ) -> tuple[list[UpgradeFinding], list[StorageCollision]]:
        """
        Analyze upgrade from v1 to v2.

        Returns:
            Tuple of (findings, storage_collisions)
        """
        self.findings = []

        # Analyze both versions
        self.analyze(v1_source, v1_name)
        self.analyze(v2_source, v2_name)

        # Compare storage layouts
        v1_layout = self.storage_analyzer.parse_storage_layout(v1_source, v1_name)
        v2_layout = self.storage_analyzer.parse_storage_layout(v2_source, v2_name)
        collisions = self.storage_analyzer.compare_layouts(v1_layout, v2_layout)

        # Add collision findings
        for collision in collisions:
            self.findings.append(UpgradeFinding(
                vulnerability=UpgradeVulnerability.STORAGE_COLLISION,
                severity=collision.severity,
                title=f"Storage Collision at Slot {collision.slot}",
                description=collision.description,
                affected_code=f"V1: {collision.v1_var.name} ({collision.v1_var.var_type})\n"
                             f"V2: {collision.v2_var.name} ({collision.v2_var.var_type})",
                line_number=0,
                recommendation="Maintain storage layout compatibility. Add new variables at end.",
                poc_concept=self._generate_collision_poc(collision),
            ))

        return self.findings, collisions

    def _check_vulnerability_patterns(self, source: str) -> None:
        """Check for known vulnerability patterns."""
        for vuln_type, vuln_info in UPGRADE_VULNERABILITY_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source[:match.start()].count('\n') + 1
                    self.findings.append(UpgradeFinding(
                        vulnerability=vuln_type,
                        severity=vuln_info["severity"],
                        title=f"Potential {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        recommendation=vuln_info["recommendation"],
                        poc_concept=self._generate_poc(vuln_type),
                    ))

    def _check_storage_gaps(self, source: str) -> None:
        """Check for proper storage gaps."""
        # Check if contract inherits from upgradeable contracts
        if re.search(r"is\s+[\w,\s]*(?:Upgradeable|Base|Storage)", source):
            # Look for __gap
            gap_match = re.search(r"uint256\[(\d+)\]\s+(?:private\s+)?__gap", source)
            if not gap_match:
                self.findings.append(UpgradeFinding(
                    vulnerability=UpgradeVulnerability.MISSING_STORAGE_GAP,
                    severity="Medium",
                    title="Missing Storage Gap",
                    description="Upgradeable contract should reserve storage slots for future variables",
                    affected_code="No __gap array found",
                    line_number=0,
                    recommendation=f"Add: uint256[{self.config.storage_gap_size}] private __gap;",
                    poc_concept="Future upgrade adds variable, collides with child contract storage",
                ))
            else:
                gap_size = int(gap_match.group(1))
                if gap_size < 20:
                    self.findings.append(UpgradeFinding(
                        vulnerability=UpgradeVulnerability.MISSING_STORAGE_GAP,
                        severity="Low",
                        title=f"Small Storage Gap ({gap_size} slots)",
                        description=f"Storage gap of {gap_size} may be insufficient",
                        affected_code=gap_match.group(0),
                        line_number=source[:gap_match.start()].count('\n') + 1,
                        recommendation=f"Consider increasing to {self.config.storage_gap_size} slots",
                        poc_concept="Future upgrades may exhaust available gap slots",
                    ))

    def _check_initializer_safety(self, source: str) -> None:
        """Check initializer function safety."""
        # Find initialize functions
        init_pattern = re.compile(
            r"function\s+(initialize\w*)\s*\([^)]*\)\s*([^{]*)\{([^}]+)\}",
            re.MULTILINE | re.DOTALL
        )

        for match in init_pattern.finditer(source):
            func_name = match.group(1)
            modifiers = match.group(2)
            body = match.group(3)

            # Check for initializer modifier
            if "initializer" not in modifiers and "reinitializer" not in modifiers:
                line_num = source[:match.start()].count('\n') + 1
                self.findings.append(UpgradeFinding(
                    vulnerability=UpgradeVulnerability.MISSING_INITIALIZER_MODIFIER,
                    severity="Critical",
                    title=f"Unprotected Initializer: {func_name}",
                    description="Initialize function can be called multiple times",
                    affected_code=f"function {func_name}(...) {modifiers[:50]}",
                    line_number=line_num,
                    recommendation="Add 'initializer' or 'reinitializer(version)' modifier",
                    poc_concept="Call initialize() after deployment to take control",
                ))

            # Check for external calls in initializer
            if re.search(r"\.call\{|\.transfer\(|IERC20\(\w+\)\.", body):
                self.findings.append(UpgradeFinding(
                    vulnerability=UpgradeVulnerability.INITIALIZER_REENTRANCY,
                    severity="High",
                    title=f"External Call in Initializer: {func_name}",
                    description="Initializer makes external calls before state is set",
                    affected_code=body[:200],
                    line_number=source[:match.start()].count('\n') + 1,
                    recommendation="Set all state before external calls, use nonReentrant",
                    poc_concept="Reenter during initialization to corrupt state",
                ))

    def _check_upgrade_access_control(self, source: str) -> None:
        """Check upgrade function access control."""
        # UUPS pattern - check _authorizeUpgrade
        auth_match = re.search(
            r"function\s+_authorizeUpgrade\s*\([^)]*\)\s*(internal[^{]*)\{([^}]*)\}",
            source,
            re.DOTALL
        )

        if auth_match:
            modifiers = auth_match.group(1)
            body = auth_match.group(2)

            # Check for access control
            has_access_control = any([
                "onlyOwner" in modifiers,
                "onlyRole" in modifiers,
                "require" in body and "owner" in body.lower(),
                "require" in body and "admin" in body.lower(),
            ])

            if not has_access_control:
                self.findings.append(UpgradeFinding(
                    vulnerability=UpgradeVulnerability.UNPROTECTED_UPGRADE,
                    severity="Critical",
                    title="Unprotected _authorizeUpgrade",
                    description="Anyone can upgrade the implementation",
                    affected_code=auth_match.group(0)[:200],
                    line_number=source[:auth_match.start()].count('\n') + 1,
                    recommendation="Add onlyOwner modifier or require(msg.sender == owner)",
                    poc_concept="Call upgradeTo() with malicious implementation",
                ))

    def _generate_poc(self, vuln_type: UpgradeVulnerability) -> str:
        """Generate PoC concept for vulnerability."""
        pocs = {
            UpgradeVulnerability.UNINITIALIZED_IMPLEMENTATION: '''
// Implementation deployed without _disableInitializers
Implementation impl = new Implementation();
// Attacker initializes implementation directly
impl.initialize(attacker);
// Now attacker controls implementation (can selfdestruct, etc)
''',
            UpgradeVulnerability.MISSING_INITIALIZER_MODIFIER: '''
// Initialize can be called again
proxy.initialize(attacker);  // First init (legit)
// Later...
proxy.initialize(attacker);  // Reinitialize with attacker as owner!
''',
            UpgradeVulnerability.SELFDESTRUCT_IN_IMPL: '''
// If attacker can call selfdestruct on implementation
impl.destroy();  // Implementation destroyed
// Proxy now delegates to destroyed contract
// Proxy is bricked OR returns 0 for all calls
''',
            UpgradeVulnerability.UNPROTECTED_UPGRADE: '''
// Anyone can upgrade
MaliciousImpl malicious = new MaliciousImpl();
proxy.upgradeTo(address(malicious));
// Proxy now runs attacker code
proxy.stealFunds();
''',
        }
        return pocs.get(vuln_type, "// PoC requires custom implementation")

    def _generate_collision_poc(self, collision: StorageCollision) -> str:
        """Generate PoC for storage collision."""
        return f'''
// Storage collision at slot {collision.slot}
// V1: {collision.v1_var.name} ({collision.v1_var.var_type})
// V2: {collision.v2_var.name} ({collision.v2_var.var_type})

// After upgrade, reading {collision.v2_var.name} returns
// data that was stored as {collision.v1_var.name}
// This can cause:
// - Incorrect balances
// - Broken access control
// - Corrupted state
'''

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "proxy_pattern": self.config.proxy_pattern.value,
        }


# =============================================================================
# FUNCTION SELECTOR CLASH DETECTION
# =============================================================================

def compute_selector(signature: str) -> str:
    """Compute 4-byte function selector."""
    return hashlib.sha3_256(signature.encode()).hexdigest()[:8]


def find_selector_clashes(
    proxy_source: str,
    impl_source: str,
) -> list[tuple[str, str, str]]:
    """
    Find function selector clashes between proxy and implementation.

    Returns list of (selector, proxy_func, impl_func) tuples.
    """
    func_pattern = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)")

    def extract_selectors(source: str) -> dict[str, str]:
        selectors = {}
        for match in func_pattern.finditer(source):
            name = match.group(1)
            params = match.group(2)
            # Simplified - real implementation parses param types
            param_types = ",".join(
                p.strip().split()[0] for p in params.split(",") if p.strip()
            )
            sig = f"{name}({param_types})"
            selector = compute_selector(sig)
            selectors[selector] = sig
        return selectors

    proxy_sels = extract_selectors(proxy_source)
    impl_sels = extract_selectors(impl_source)

    clashes = []
    for sel, proxy_sig in proxy_sels.items():
        if sel in impl_sels and proxy_sig != impl_sels[sel]:
            clashes.append((sel, proxy_sig, impl_sels[sel]))

    return clashes


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_upgrade_safety(
    source: str,
    contract_name: str = "Implementation",
) -> list[UpgradeFinding]:
    """Quick upgrade safety analysis."""
    analyzer = UpgradeSafetyAnalyzer()
    return analyzer.analyze(source, contract_name)


def compare_versions(
    v1_source: str,
    v2_source: str,
) -> tuple[list[UpgradeFinding], list[StorageCollision]]:
    """Compare two contract versions for upgrade compatibility."""
    analyzer = UpgradeSafetyAnalyzer()
    return analyzer.analyze_upgrade(v1_source, v2_source)
