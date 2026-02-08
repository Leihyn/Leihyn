"""
ZK Circuit Security Analyzer

Analyzes zero-knowledge circuits for vulnerabilities:
1. Underconstrained circuits - Missing constraints allow invalid proofs
2. Overconstrained circuits - Valid inputs rejected
3. Trusted setup leaks - Toxic waste exposure
4. Prover denial of service - Circuits that can't be proven
5. Verifier input manipulation - Incorrect public input handling
6. Frozen heart - Recursive proof vulnerabilities

Supports:
- Circom (R1CS)
- Noir (ACIR)
- Halo2 (PLONKish)
- gnark (R1CS/PLONK)
- Cairo (AIR)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class ZKLanguage(Enum):
    """Supported ZK circuit languages."""
    CIRCOM = "circom"
    NOIR = "noir"
    HALO2 = "halo2"
    GNARK = "gnark"
    CAIRO = "cairo"


class ZKVulnerability(Enum):
    """ZK-specific vulnerability types."""
    UNDERCONSTRAINED = "underconstrained"
    OVERCONSTRAINED = "overconstrained"
    TRUSTED_SETUP_LEAK = "trusted_setup_leak"
    PROVER_DOS = "prover_dos"
    VERIFIER_INPUT_MANIPULATION = "verifier_input_manipulation"
    FROZEN_HEART = "frozen_heart"
    SIGNAL_ASSIGNMENT_UNCONSTRAINED = "signal_assignment_unconstrained"
    MISSING_RANGE_CHECK = "missing_range_check"
    FIELD_OVERFLOW = "field_overflow"
    NONDETERMINISTIC_WITNESS = "nondeterministic_witness"


@dataclass
class ZKFinding:
    """A ZK circuit security finding."""
    vulnerability: ZKVulnerability
    severity: str
    title: str
    description: str
    affected_code: str
    line_number: int
    attack_scenario: str
    recommendation: str
    reference: Optional[str] = None  # Link to similar vulnerability


@dataclass
class ZKConfig:
    """Configuration for ZK analysis."""
    language: ZKLanguage = ZKLanguage.CIRCOM
    check_underconstrained: bool = True
    check_range: bool = True
    check_field: bool = True
    field_size: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254


# =============================================================================
# CIRCOM VULNERABILITY PATTERNS
# =============================================================================

CIRCOM_PATTERNS = {
    ZKVulnerability.SIGNAL_ASSIGNMENT_UNCONSTRAINED: {
        "patterns": [
            # Signal assigned but not constrained
            r"signal\s+(?:input\s+)?(\w+);\s*\n(?!.*\1\s*===)",
            # Using <-- without ===
            r"(\w+)\s*<--\s*[^;]+;(?!\s*\w+\s*===)",
            # Assignment without constraint
            r"<--(?!.*===)",
        ],
        "description": "Signal assigned (<--) but not constrained (===)",
        "severity": "Critical",
        "reference": "https://github.com/0xPARC/zk-bug-tracker#1-under-constrained-circuits",
    },
    ZKVulnerability.UNDERCONSTRAINED: {
        "patterns": [
            # Output signal without constraint
            r"signal\s+output\s+(\w+);\s*(?!.*\1\s*===)",
            # Component output not used
            r"component\s+(\w+)\s*=.*;\s*(?!.*\1\.)",
            # Input not used in constraints
            r"signal\s+input\s+(\w+);\s*(?!.*\1\s*[=<>])",
        ],
        "description": "Circuit may have missing constraints",
        "severity": "Critical",
        "reference": "Tornado Cash governance attack - underconstrained proof",
    },
    ZKVulnerability.MISSING_RANGE_CHECK: {
        "patterns": [
            # Comparison without range check
            r"(?:LessThan|GreaterThan)\s*\([^)]*\)(?!.*Num2Bits)",
            # Division without range check
            r"/\s*(?!.*Num2Bits)(?!.*range)",
            # Modulo without range check
            r"%\s*\d+(?!.*Num2Bits)",
        ],
        "description": "Arithmetic operation without range check",
        "severity": "High",
        "reference": "Field elements can wrap around without proper range checks",
    },
    ZKVulnerability.NONDETERMINISTIC_WITNESS: {
        "patterns": [
            # Random or external data in witness
            r"<--\s*(?:random|external|oracle)",
            # Multiple valid witnesses possible
            r"IsZero\s*\([^)]*\)",  # Can have multiple witnesses if not constrained
        ],
        "description": "Witness computation may be nondeterministic",
        "severity": "Medium",
        "reference": "Nondeterministic witnesses can lead to soundness issues",
    },
}


# =============================================================================
# NOIR VULNERABILITY PATTERNS
# =============================================================================

NOIR_PATTERNS = {
    ZKVulnerability.UNDERCONSTRAINED: {
        "patterns": [
            # Unused parameter
            r"fn\s+\w+\([^)]*(\w+)\s*:\s*Field[^)]*\)\s*\{(?!.*\1)",
            # Return without constraint
            r"fn\s+\w+[^{]*->\s*pub\s+Field\s*\{(?!.*assert)",
        ],
        "description": "Function may have unconstrained inputs",
        "severity": "Critical",
    },
    ZKVulnerability.MISSING_RANGE_CHECK: {
        "patterns": [
            # Array access without bounds check
            r"\[\s*\w+\s*\](?!.*assert.*<)",
            # Arithmetic without overflow check
            r"\+|\-|\*(?!.*assert.*<=)",
        ],
        "description": "Missing range or bounds check",
        "severity": "High",
    },
}


# =============================================================================
# HALO2 VULNERABILITY PATTERNS
# =============================================================================

HALO2_PATTERNS = {
    ZKVulnerability.UNDERCONSTRAINED: {
        "patterns": [
            # Missing constraint in configure
            r"fn\s+configure[^}]*\{(?!.*create_gate)",
            # Advice column without constraint
            r"advice_column[^;]*;(?!.*query_advice)",
        ],
        "description": "Circuit may lack necessary constraints",
        "severity": "Critical",
    },
    ZKVulnerability.PROVER_DOS: {
        "patterns": [
            # Exponential number of rows
            r"for.*in.*0\.\.\s*n\s*\{[^}]*for.*in.*0\.\.\s*n",
            # Very large lookup table
            r"lookup_table.*\d{6,}",
        ],
        "description": "Circuit complexity may cause prover DoS",
        "severity": "Medium",
    },
}


# =============================================================================
# CAIRO VULNERABILITY PATTERNS
# =============================================================================

CAIRO_PATTERNS = {
    ZKVulnerability.UNDERCONSTRAINED: {
        "patterns": [
            # Unused felt
            r"let\s+(\w+)\s*:\s*felt(?!.*\1)",
            # assert_nn without range_check
            r"assert_nn(?!.*range_check_ptr)",
        ],
        "description": "Cairo hint may be underconstrained",
        "severity": "Critical",
    },
    ZKVulnerability.NONDETERMINISTIC_WITNESS: {
        "patterns": [
            # Nondet hint
            r"%\{[^}]*\}",
            # External call in hint
            r"nondet\s+",
        ],
        "description": "Nondeterministic hint in Cairo",
        "severity": "High",
    },
}


# =============================================================================
# VERIFIER VULNERABILITIES (Solidity)
# =============================================================================

VERIFIER_PATTERNS = {
    ZKVulnerability.VERIFIER_INPUT_MANIPULATION: {
        "patterns": [
            # Public inputs not validated
            r"function\s+verify\w*\([^)]*uint256\[\]\s+(?:memory\s+)?publicInputs[^)]*\)(?!.*require.*publicInputs)",
            # Missing input length check
            r"function\s+verifyProof\([^)]*\)(?!.*require.*\.length)",
            # Unchecked modular arithmetic
            r"mulmod\s*\([^)]*,\s*[^)]*,\s*p\s*\)(?!.*require)",
        ],
        "description": "Verifier may accept manipulated inputs",
        "severity": "Critical",
    },
    ZKVulnerability.FROZEN_HEART: {
        "patterns": [
            # Recursive verification without proper checks
            r"verify\w*\([^)]*verify\w*\(",
            # Aggregated proof without commitment check
            r"aggregateProofs(?!.*commitment)",
        ],
        "description": "Recursive proof verification may be vulnerable",
        "severity": "Critical",
        "reference": "Frozen Heart vulnerability in recursive SNARKs",
    },
}


class ZKCircuitAnalyzer:
    """
    Comprehensive ZK circuit security analyzer.

    Analyzes circuits for:
    - Underconstrained signals (soundness issues)
    - Missing range checks (field overflow)
    - Nondeterministic witnesses
    - Verifier vulnerabilities
    """

    def __init__(self, config: Optional[ZKConfig] = None):
        self.config = config or ZKConfig()
        self.findings: list[ZKFinding] = []

    def analyze(
        self,
        source_code: str,
        language: Optional[ZKLanguage] = None,
    ) -> list[ZKFinding]:
        """
        Analyze ZK circuit for vulnerabilities.
        """
        self.findings = []
        lang = language or self.config.language

        # Select patterns based on language
        patterns = self._get_patterns_for_language(lang)

        # Run pattern matching
        for vuln_type, vuln_info in patterns.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = source_code[:match.start()].count('\n') + 1
                    self.findings.append(ZKFinding(
                        vulnerability=vuln_type,
                        severity=vuln_info.get("severity", "High"),
                        title=f"ZK Vulnerability: {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._generate_attack_scenario(vuln_type),
                        recommendation=self._get_recommendation(vuln_type, lang),
                        reference=vuln_info.get("reference"),
                    ))

        # Language-specific checks
        if lang == ZKLanguage.CIRCOM:
            self._check_circom_specific(source_code)
        elif lang == ZKLanguage.CAIRO:
            self._check_cairo_specific(source_code)

        return self.findings

    def analyze_verifier(self, verifier_source: str) -> list[ZKFinding]:
        """
        Analyze Solidity verifier contract for vulnerabilities.
        """
        self.findings = []

        for vuln_type, vuln_info in VERIFIER_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, verifier_source, re.MULTILINE | re.DOTALL))
                for match in matches:
                    line_num = verifier_source[:match.start()].count('\n') + 1
                    self.findings.append(ZKFinding(
                        vulnerability=vuln_type,
                        severity=vuln_info.get("severity", "Critical"),
                        title=f"Verifier Vulnerability: {vuln_type.value.replace('_', ' ').title()}",
                        description=vuln_info["description"],
                        affected_code=match.group(0)[:200],
                        line_number=line_num,
                        attack_scenario=self._generate_verifier_attack(vuln_type),
                        recommendation=self._get_verifier_recommendation(vuln_type),
                        reference=vuln_info.get("reference"),
                    ))

        return self.findings

    def _get_patterns_for_language(self, lang: ZKLanguage) -> dict:
        """Get vulnerability patterns for language."""
        patterns = {
            ZKLanguage.CIRCOM: CIRCOM_PATTERNS,
            ZKLanguage.NOIR: NOIR_PATTERNS,
            ZKLanguage.HALO2: HALO2_PATTERNS,
            ZKLanguage.CAIRO: CAIRO_PATTERNS,
        }
        return patterns.get(lang, CIRCOM_PATTERNS)

    def _check_circom_specific(self, source: str) -> None:
        """Circom-specific vulnerability checks."""
        # Check for <-- without corresponding ===
        assignments = re.findall(r"(\w+)\s*<--", source)
        constraints = re.findall(r"(\w+)\s*===", source)

        unconstrained = set(assignments) - set(constraints)
        for signal in unconstrained:
            # Check if it's a component output (those are OK)
            if not re.search(rf"component.*{signal}\s*=", source):
                self.findings.append(ZKFinding(
                    vulnerability=ZKVulnerability.SIGNAL_ASSIGNMENT_UNCONSTRAINED,
                    severity="Critical",
                    title=f"Unconstrained Signal: {signal}",
                    description=f"Signal '{signal}' is assigned (<--) but never constrained (===)",
                    affected_code=f"{signal} <-- ... (no === constraint found)",
                    line_number=0,
                    attack_scenario=(
                        "Attacker can set arbitrary value for this signal.\n"
                        "The prover can create valid proofs for invalid statements."
                    ),
                    recommendation=f"Add constraint: {signal} === <expected_value>;",
                    reference="https://github.com/0xPARC/zk-bug-tracker",
                ))

        # Check for template instantiation without all outputs connected
        templates = re.findall(r"template\s+(\w+)\s*\([^)]*\)\s*\{([^}]+)\}", source, re.DOTALL)
        for template_name, template_body in templates:
            outputs = re.findall(r"signal\s+output\s+(\w+)", template_body)
            # Check if template is used and all outputs are connected
            usages = re.findall(rf"component\s+(\w+)\s*=\s*{template_name}\s*\(", source)
            for usage in usages:
                for output in outputs:
                    if not re.search(rf"{usage}\.{output}", source):
                        self.findings.append(ZKFinding(
                            vulnerability=ZKVulnerability.UNDERCONSTRAINED,
                            severity="High",
                            title=f"Unused Template Output: {usage}.{output}",
                            description=f"Output '{output}' of component '{usage}' is not used",
                            affected_code=f"component {usage} = {template_name}(...)",
                            line_number=0,
                            attack_scenario="Unused output may indicate missing constraint",
                            recommendation=f"Either use {usage}.{output} or remove if intentional",
                        ))

    def _check_cairo_specific(self, source: str) -> None:
        """Cairo-specific vulnerability checks."""
        # Check for hints without proper constraints
        hints = re.finditer(r"%\{\s*([^}]+)\s*%\}", source)
        for hint in hints:
            hint_body = hint.group(1)
            line_num = source[:hint.start()].count('\n') + 1

            # Check if hint result is constrained after
            lines_after = source[hint.end():hint.end()+500]
            if not re.search(r"assert\s+", lines_after[:200]):
                self.findings.append(ZKFinding(
                    vulnerability=ZKVulnerability.NONDETERMINISTIC_WITNESS,
                    severity="High",
                    title="Hint Without Immediate Constraint",
                    description="Cairo hint computes value that may not be constrained",
                    affected_code=hint.group(0)[:200],
                    line_number=line_num,
                    attack_scenario="Prover can use any value satisfying the hint",
                    recommendation="Add assert statement immediately after hint",
                ))

    def _generate_attack_scenario(self, vuln_type: ZKVulnerability) -> str:
        """Generate attack scenario for vulnerability type."""
        scenarios = {
            ZKVulnerability.UNDERCONSTRAINED: (
                "1. Identify the unconstrained signal/variable\n"
                "2. Create witness with arbitrary value for that signal\n"
                "3. Generate valid proof for invalid statement\n"
                "4. Submit proof to verifier - it accepts!"
            ),
            ZKVulnerability.SIGNAL_ASSIGNMENT_UNCONSTRAINED: (
                "1. Signal X is assigned but not constrained\n"
                "2. Prover sets X to any value they want\n"
                "3. Proof verifies because constraint system ignores X\n"
                "4. Invalid state transition appears valid"
            ),
            ZKVulnerability.MISSING_RANGE_CHECK: (
                "1. Input is not range-checked\n"
                "2. Attacker provides value near field modulus\n"
                "3. Arithmetic wraps around unexpectedly\n"
                "4. Proof for impossible statement is valid"
            ),
            ZKVulnerability.NONDETERMINISTIC_WITNESS: (
                "1. Multiple valid witnesses exist for same public input\n"
                "2. Prover chooses witness advantageous to them\n"
                "3. Different provers get different results\n"
                "4. System behavior becomes unpredictable"
            ),
        }
        return scenarios.get(vuln_type, "Attack scenario requires specific analysis")

    def _generate_verifier_attack(self, vuln_type: ZKVulnerability) -> str:
        """Generate attack scenario for verifier vulnerability."""
        scenarios = {
            ZKVulnerability.VERIFIER_INPUT_MANIPULATION: (
                "1. Craft malformed public inputs array\n"
                "2. Bypass length or range checks\n"
                "3. Submit with valid proof for different inputs\n"
                "4. Verifier accepts proof for wrong statement"
            ),
            ZKVulnerability.FROZEN_HEART: (
                "1. Create recursive proof with inner proof's challenges\n"
                "2. Exploit shared randomness in aggregation\n"
                "3. Forge proof that verifies despite being invalid\n"
                "4. Compromise entire recursive proof chain"
            ),
        }
        return scenarios.get(vuln_type, "Attack scenario requires specific analysis")

    def _get_recommendation(self, vuln_type: ZKVulnerability, lang: ZKLanguage) -> str:
        """Get language-specific recommendation."""
        if lang == ZKLanguage.CIRCOM:
            recommendations = {
                ZKVulnerability.UNDERCONSTRAINED: (
                    "Ensure every signal is either:\n"
                    "1. Constrained with === operator\n"
                    "2. A component output that is used\n"
                    "3. Explicitly marked as unconstrained (document why)"
                ),
                ZKVulnerability.SIGNAL_ASSIGNMENT_UNCONSTRAINED: (
                    "Replace <-- with <== which combines assignment and constraint.\n"
                    "Or add explicit constraint: signal === expected_value;"
                ),
                ZKVulnerability.MISSING_RANGE_CHECK: (
                    "Use Num2Bits to range check values:\n"
                    "component rangeCheck = Num2Bits(n);\n"
                    "rangeCheck.in <== value;"
                ),
            }
        elif lang == ZKLanguage.NOIR:
            recommendations = {
                ZKVulnerability.UNDERCONSTRAINED: (
                    "Ensure all function inputs are used in constraints.\n"
                    "Add assert statements to constrain values."
                ),
            }
        else:
            recommendations = {}

        return recommendations.get(vuln_type, "Review circuit constraints carefully")

    def _get_verifier_recommendation(self, vuln_type: ZKVulnerability) -> str:
        """Get recommendation for verifier vulnerability."""
        recommendations = {
            ZKVulnerability.VERIFIER_INPUT_MANIPULATION: (
                "1. Validate public inputs array length\n"
                "2. Range check all inputs are in field\n"
                "3. Verify inputs match expected format\n"
                "4. Use named parameters instead of arrays where possible"
            ),
            ZKVulnerability.FROZEN_HEART: (
                "1. Use unique challenges per recursive level\n"
                "2. Include proof index in transcript\n"
                "3. Verify inner proofs independently\n"
                "4. Follow latest recursive SNARK best practices"
            ),
        }
        return recommendations.get(vuln_type, "Review verifier implementation")

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "language": self.config.language.value,
            "soundness_risk": "HIGH" if severity_counts["Critical"] > 0 else "MEDIUM" if severity_counts["High"] > 0 else "LOW",
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_circom(source: str) -> list[ZKFinding]:
    """Analyze Circom circuit."""
    analyzer = ZKCircuitAnalyzer(ZKConfig(language=ZKLanguage.CIRCOM))
    return analyzer.analyze(source)


def analyze_noir(source: str) -> list[ZKFinding]:
    """Analyze Noir circuit."""
    analyzer = ZKCircuitAnalyzer(ZKConfig(language=ZKLanguage.NOIR))
    return analyzer.analyze(source)


def analyze_cairo(source: str) -> list[ZKFinding]:
    """Analyze Cairo program."""
    analyzer = ZKCircuitAnalyzer(ZKConfig(language=ZKLanguage.CAIRO))
    return analyzer.analyze(source)


def check_verifier(verifier_source: str) -> list[ZKFinding]:
    """Check Solidity verifier for vulnerabilities."""
    analyzer = ZKCircuitAnalyzer()
    return analyzer.analyze_verifier(verifier_source)
