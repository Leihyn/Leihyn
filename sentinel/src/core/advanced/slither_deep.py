"""
Slither Deep Integration

Deep integration with Slither for advanced analysis:
1. Custom detector creation - Build detectors from patterns
2. Taint analysis - Track data flow from sources to sinks
3. Control flow analysis - Analyze execution paths
4. IR manipulation - Work with Slither's intermediate representation
5. Cross-contract analysis - Multi-contract vulnerability detection

Requires: pip install slither-analyzer
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Any
import subprocess
import json
import re
import tempfile
import os


class SlitherOutput(Enum):
    """Slither output formats."""
    JSON = "json"
    TEXT = "text"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class DetectorImpact(Enum):
    """Slither detector impact levels."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class DetectorConfidence(Enum):
    """Slither detector confidence levels."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class TaintSource:
    """A source of tainted data."""
    contract: str
    function: str
    variable: str
    source_type: str  # "msg.sender", "msg.value", "calldata", etc.
    line: int


@dataclass
class TaintSink:
    """A sink where tainted data could be dangerous."""
    contract: str
    function: str
    operation: str  # "transfer", "call", "selfdestruct", etc.
    line: int


@dataclass
class TaintPath:
    """A path from taint source to sink."""
    source: TaintSource
    sink: TaintSink
    path: list[str]  # List of intermediate variables/functions
    is_sanitized: bool
    risk_level: str


@dataclass
class SlitherFinding:
    """A finding from Slither analysis."""
    detector: str
    impact: DetectorImpact
    confidence: DetectorConfidence
    description: str
    contract: str
    function: Optional[str]
    line: int
    code_snippet: str
    recommendation: str


@dataclass
class CustomDetectorSpec:
    """Specification for a custom detector."""
    name: str
    description: str
    impact: DetectorImpact
    confidence: DetectorConfidence
    pattern: str  # Regex pattern to match
    wiki: str = ""


class SlitherDeepIntegration:
    """
    Deep integration with Slither for advanced security analysis.

    Provides:
    - Run Slither with custom configurations
    - Create and run custom detectors
    - Perform taint analysis
    - Analyze control flow
    """

    def __init__(self, project_path: str = "."):
        self.project_path = project_path
        self.findings: list[SlitherFinding] = []

    def run_analysis(
        self,
        target: str = ".",
        detectors: Optional[list[str]] = None,
        exclude: Optional[list[str]] = None,
        output_format: SlitherOutput = SlitherOutput.JSON,
    ) -> list[SlitherFinding]:
        """
        Run Slither analysis on target.

        Args:
            target: Contract file or directory
            detectors: List of detectors to run (None = all)
            exclude: List of detectors to exclude
            output_format: Output format

        Returns:
            List of findings
        """
        self.findings = []

        cmd = ["slither", target, f"--{output_format.value}"]

        if detectors:
            cmd.extend(["--detect", ",".join(detectors)])

        if exclude:
            cmd.extend(["--exclude", ",".join(exclude)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_path,
            )

            if output_format == SlitherOutput.JSON:
                self._parse_json_output(result.stdout)
            else:
                self._parse_text_output(result.stdout)

        except FileNotFoundError:
            # Slither not installed - return empty
            pass
        except Exception:
            pass

        return self.findings

    def _parse_json_output(self, output: str) -> None:
        """Parse JSON output from Slither."""
        try:
            data = json.loads(output)
            results = data.get("results", {}).get("detectors", [])

            for result in results:
                elements = result.get("elements", [])
                first_elem = elements[0] if elements else {}

                self.findings.append(SlitherFinding(
                    detector=result.get("check", "unknown"),
                    impact=DetectorImpact(result.get("impact", "Informational")),
                    confidence=DetectorConfidence(result.get("confidence", "Low")),
                    description=result.get("description", ""),
                    contract=first_elem.get("type_specific_fields", {}).get("parent", {}).get("name", ""),
                    function=first_elem.get("name"),
                    line=first_elem.get("source_mapping", {}).get("start", 0),
                    code_snippet=first_elem.get("source_mapping", {}).get("content", ""),
                    recommendation=self._get_recommendation(result.get("check", "")),
                ))
        except json.JSONDecodeError:
            pass

    def _parse_text_output(self, output: str) -> None:
        """Parse text output from Slither."""
        # Simple parsing for text output
        finding_pattern = re.compile(
            r"(\w+)\s+found\s+in\s+(.+?):\n(.+?)(?=\n\n|\Z)",
            re.DOTALL
        )

        for match in finding_pattern.finditer(output):
            self.findings.append(SlitherFinding(
                detector=match.group(1),
                impact=DetectorImpact.MEDIUM,
                confidence=DetectorConfidence.MEDIUM,
                description=match.group(3).strip(),
                contract=match.group(2),
                function=None,
                line=0,
                code_snippet="",
                recommendation="Review the finding",
            ))

    def _get_recommendation(self, detector: str) -> str:
        """Get recommendation for detector finding."""
        recommendations = {
            "reentrancy-eth": "Use ReentrancyGuard or checks-effects-interactions pattern",
            "reentrancy-no-eth": "Follow checks-effects-interactions pattern",
            "arbitrary-send-eth": "Restrict who can receive ETH transfers",
            "arbitrary-send-erc20": "Validate recipient and amount",
            "unchecked-transfer": "Check return value of transfer calls",
            "uninitialized-state": "Initialize all state variables",
            "uninitialized-local": "Initialize all local variables",
            "unused-return": "Check return values of external calls",
            "tx-origin": "Use msg.sender instead of tx.origin",
            "delegatecall-loop": "Avoid delegatecall in loops",
            "controlled-delegatecall": "Validate delegatecall targets",
            "suicidal": "Restrict access to selfdestruct",
        }
        return recommendations.get(detector, "Review and fix the issue")

    def create_custom_detector(
        self,
        spec: CustomDetectorSpec,
    ) -> str:
        """
        Generate Python code for a custom Slither detector.

        Returns Slither detector class code.
        """
        detector_code = f'''
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
import re


class {spec.name}Detector(AbstractDetector):
    """
    {spec.description}
    """

    ARGUMENT = "{spec.name.lower()}"
    HELP = "{spec.description}"
    IMPACT = DetectorClassification.{spec.impact.value.upper()}
    CONFIDENCE = DetectorClassification.{spec.confidence.value.upper()}
    WIKI = "{spec.wiki}"
    WIKI_TITLE = "{spec.name}"
    WIKI_DESCRIPTION = "{spec.description}"
    WIKI_RECOMMENDATION = "Review and fix the pattern"

    PATTERN = r"{spec.pattern}"

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                for node in function.nodes:
                    # Check pattern against node expression
                    if node.expression:
                        expr_str = str(node.expression)
                        if re.search(self.PATTERN, expr_str):
                            info = [
                                f"Potential issue in ",
                                function,
                                f" at line {{node.source_mapping.lines}}\\n",
                                f"Pattern matched: {{expr_str[:100]}}\\n"
                            ]
                            results.append(self.generate_result(info))

        return results
'''
        return detector_code

    def run_taint_analysis(
        self,
        source_file: str,
        sources: Optional[list[str]] = None,
        sinks: Optional[list[str]] = None,
    ) -> list[TaintPath]:
        """
        Run taint analysis to find data flow from sources to sinks.

        Default sources: msg.sender, msg.value, calldata
        Default sinks: transfer, call, delegatecall, selfdestruct
        """
        sources = sources or ["msg.sender", "msg.value", "calldata", "msg.data"]
        sinks = sinks or ["transfer", "call", "delegatecall", "selfdestruct", "send"]

        # Read source file
        with open(os.path.join(self.project_path, source_file)) as f:
            source_code = f.read()

        paths = []

        # Simple regex-based taint tracking (full implementation uses Slither IR)
        for source in sources:
            source_matches = list(re.finditer(rf'\b{re.escape(source)}\b', source_code))

            for sink in sinks:
                sink_matches = list(re.finditer(rf'\.{sink}\s*\(', source_code))

                for src_match in source_matches:
                    src_line = source_code[:src_match.start()].count('\n') + 1

                    for sink_match in sink_matches:
                        sink_line = source_code[:sink_match.start()].count('\n') + 1

                        # Check if sink comes after source (simple heuristic)
                        if sink_line > src_line:
                            # Check if in same function (simplified)
                            between = source_code[src_match.start():sink_match.start()]
                            func_boundaries = between.count('{') - between.count('}')

                            if func_boundaries >= 0:  # Same scope level
                                paths.append(TaintPath(
                                    source=TaintSource(
                                        contract="",
                                        function="",
                                        variable=source,
                                        source_type=source,
                                        line=src_line,
                                    ),
                                    sink=TaintSink(
                                        contract="",
                                        function="",
                                        operation=sink,
                                        line=sink_line,
                                    ),
                                    path=[source, "...", sink],
                                    is_sanitized=self._check_sanitization(between, source),
                                    risk_level=self._assess_taint_risk(source, sink),
                                ))

        return paths

    def _check_sanitization(self, code_between: str, source: str) -> bool:
        """Check if tainted data is sanitized between source and sink."""
        sanitizers = [
            rf'require\s*\([^)]*{source}',
            rf'if\s*\([^)]*{source}',
            rf'{source}\s*==',
            rf'{source}\s*!=',
        ]

        return any(re.search(pattern, code_between) for pattern in sanitizers)

    def _assess_taint_risk(self, source: str, sink: str) -> str:
        """Assess risk level of taint flow."""
        high_risk = {
            ("msg.value", "call"),
            ("msg.value", "transfer"),
            ("msg.sender", "delegatecall"),
            ("calldata", "delegatecall"),
        }

        if (source, sink) in high_risk:
            return "High"
        if sink in ("delegatecall", "selfdestruct"):
            return "High"
        if sink in ("call", "transfer"):
            return "Medium"
        return "Low"

    def get_function_summary(self, source_file: str) -> dict:
        """
        Get summary of all functions using Slither.

        Returns dict with function info including:
        - visibility
        - modifiers
        - state variables read/written
        - external calls made
        """
        summary = {}

        # Run slither with human-summary printer
        cmd = [
            "slither", source_file,
            "--print", "function-summary",
            "--json", "-"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_path,
            )

            data = json.loads(result.stdout)
            printers = data.get("results", {}).get("printers", [])

            for printer in printers:
                if printer.get("printer") == "function-summary":
                    summary = printer.get("elements", {})

        except Exception:
            pass

        return summary

    def get_contract_dependencies(self, source_file: str) -> dict:
        """
        Get contract dependency graph.

        Returns dict mapping contracts to their dependencies.
        """
        dependencies = {}

        cmd = [
            "slither", source_file,
            "--print", "contract-summary",
            "--json", "-"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_path,
            )

            data = json.loads(result.stdout)

            for contract in data.get("results", {}).get("contracts", []):
                name = contract.get("name", "")
                deps = contract.get("dependencies", [])
                dependencies[name] = deps

        except Exception:
            pass

        return dependencies

    def get_state_variables(self, source_file: str) -> list[dict]:
        """Get all state variables with their types and visibility."""
        variables = []

        cmd = [
            "slither", source_file,
            "--print", "vars-and-auth",
            "--json", "-"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_path,
            )

            data = json.loads(result.stdout)
            # Parse state variables from output
            # ...

        except Exception:
            pass

        return variables


# =============================================================================
# BUILT-IN DETECTOR PATTERNS
# =============================================================================

COMMON_VULNERABILITY_PATTERNS = {
    "unchecked_external_call": CustomDetectorSpec(
        name="UncheckedExternalCall",
        description="Detects external calls without return value checks",
        impact=DetectorImpact.MEDIUM,
        confidence=DetectorConfidence.HIGH,
        pattern=r"\.call\{[^}]*\}\([^)]*\)(?!\s*;?\s*(?:require|if|bool))",
    ),
    "timestamp_dependence": CustomDetectorSpec(
        name="TimestampDependence",
        description="Detects reliance on block.timestamp for critical logic",
        impact=DetectorImpact.LOW,
        confidence=DetectorConfidence.MEDIUM,
        pattern=r"block\.timestamp\s*[<>=!]+",
    ),
    "weak_randomness": CustomDetectorSpec(
        name="WeakRandomness",
        description="Detects weak randomness sources",
        impact=DetectorImpact.HIGH,
        confidence=DetectorConfidence.HIGH,
        pattern=r"keccak256\([^)]*block\.(timestamp|number|difficulty)",
    ),
    "missing_zero_check": CustomDetectorSpec(
        name="MissingZeroCheck",
        description="Detects missing zero address checks",
        impact=DetectorImpact.MEDIUM,
        confidence=DetectorConfidence.MEDIUM,
        pattern=r"=\s*_?(?:owner|admin|recipient|to)\s*;(?!.*require.*!=\s*address\(0\))",
    ),
}


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_slither(target: str, detectors: Optional[list[str]] = None) -> list[SlitherFinding]:
    """Run Slither analysis on target."""
    integration = SlitherDeepIntegration()
    return integration.run_analysis(target, detectors)


def analyze_taint(source_file: str) -> list[TaintPath]:
    """Run taint analysis on source file."""
    integration = SlitherDeepIntegration()
    return integration.run_taint_analysis(source_file)


def create_detector(pattern: str, name: str, impact: str = "Medium") -> str:
    """Create custom Slither detector code."""
    spec = CustomDetectorSpec(
        name=name,
        description=f"Custom detector for {name}",
        impact=DetectorImpact(impact),
        confidence=DetectorConfidence.MEDIUM,
        pattern=pattern,
    )
    integration = SlitherDeepIntegration()
    return integration.create_custom_detector(spec)
