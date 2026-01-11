"""
Slither static analysis tool integration.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from ..core.types import SlitherResult, Severity


def severity_from_slither(slither_severity: str) -> Severity:
    """Convert Slither severity to our severity enum."""
    mapping = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFORMATIONAL,
        "Optimization": Severity.GAS,
    }
    return mapping.get(slither_severity, Severity.INFORMATIONAL)


def run_slither(
    target_path: Path,
    exclude_detectors: Optional[list[str]] = None,
    include_detectors: Optional[list[str]] = None,
    solc_version: Optional[str] = None,
) -> tuple[list[SlitherResult], str]:
    """
    Run Slither analysis on a target.

    Args:
        target_path: Path to contract file or directory
        exclude_detectors: Detectors to exclude
        include_detectors: Only run these detectors
        solc_version: Specific solc version to use

    Returns:
        Tuple of (parsed results, raw output)
    """
    cmd = ["slither", str(target_path), "--json", "-"]

    if exclude_detectors:
        cmd.extend(["--exclude", ",".join(exclude_detectors)])

    if include_detectors:
        cmd.extend(["--detect", ",".join(include_detectors)])

    if solc_version:
        cmd.extend(["--solc-solcs-select", solc_version])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
    except subprocess.TimeoutExpired:
        return [], "Slither timed out after 5 minutes"
    except FileNotFoundError:
        return [], "Slither not found. Install with: pip install slither-analyzer"

    # Parse JSON output
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], f"Failed to parse Slither output: {result.stderr}"

    # Check for errors
    if not output.get("success", True):
        error_msg = output.get("error", result.stderr)
        return [], f"Slither error: {error_msg}"

    # Parse results
    results = []
    for detector_result in output.get("results", {}).get("detectors", []):
        # Extract relevant info
        elements = detector_result.get("elements", [])

        contract = ""
        function = None
        lines = []

        for element in elements:
            if element.get("type") == "contract":
                contract = element.get("name", "")
            elif element.get("type") == "function":
                function = element.get("name", "")

            source_mapping = element.get("source_mapping", {})
            if source_mapping:
                start_line = source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0
                if start_line:
                    lines.append(start_line)

        results.append(
            SlitherResult(
                detector=detector_result.get("check", "unknown"),
                severity=detector_result.get("impact", "Informational"),
                confidence=detector_result.get("confidence", "Low"),
                description=detector_result.get("description", ""),
                contract=contract,
                function=function,
                lines=sorted(set(lines)),
                raw=detector_result,
            )
        )

    # Sort by severity
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}
    results.sort(key=lambda x: severity_order.get(x.severity, 5))

    return results, ""


def filter_false_positives(
    results: list[SlitherResult],
    filters: Optional[dict] = None,
) -> list[SlitherResult]:
    """
    Filter out known false positives from Slither results.

    Args:
        results: Raw Slither results
        filters: Custom filter rules

    Returns:
        Filtered results
    """
    # Default filters for common false positives
    default_filters = {
        # Detectors that often produce false positives
        "exclude_detectors": [
            "solc-version",
            "low-level-calls",
            "naming-convention",
            "pragma",
            "dead-code",
        ],
        # Confidence thresholds
        "min_confidence": "Medium",
    }

    filters = {**default_filters, **(filters or {})}

    confidence_levels = {"High": 3, "Medium": 2, "Low": 1}
    min_confidence = confidence_levels.get(filters["min_confidence"], 1)

    filtered = []
    for result in results:
        # Skip excluded detectors
        if result.detector in filters["exclude_detectors"]:
            continue

        # Skip low confidence
        result_confidence = confidence_levels.get(result.confidence, 0)
        if result_confidence < min_confidence:
            continue

        filtered.append(result)

    return filtered


def get_detector_info() -> dict:
    """
    Get information about available Slither detectors.

    Returns:
        Dict mapping detector name to description
    """
    try:
        result = subprocess.run(
            ["slither", "--list-detectors-json"],
            capture_output=True,
            text=True,
        )
        detectors = json.loads(result.stdout)
        return {d["check"]: d for d in detectors}
    except Exception:
        return {}


# Detector categories for targeted analysis
REENTRANCY_DETECTORS = [
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-events",
    "reentrancy-unlimited-gas",
]

ACCESS_CONTROL_DETECTORS = [
    "unprotected-upgrade",
    "arbitrary-send-eth",
    "arbitrary-send-erc20",
    "arbitrary-send-erc20-permit",
    "suicidal",
    "protected-vars",
]

ORACLE_DETECTORS = [
    "oracle-price-update",
    "unchecked-price-feed",
]

ARITHMETIC_DETECTORS = [
    "divide-before-multiply",
    "unchecked-transfer",
]


def run_targeted_analysis(
    target_path: Path,
    category: str,
) -> tuple[list[SlitherResult], str]:
    """
    Run Slither with detectors targeted at a specific vulnerability category.
    """
    detector_map = {
        "reentrancy": REENTRANCY_DETECTORS,
        "access_control": ACCESS_CONTROL_DETECTORS,
        "oracle": ORACLE_DETECTORS,
        "arithmetic": ARITHMETIC_DETECTORS,
    }

    detectors = detector_map.get(category)
    if not detectors:
        return run_slither(target_path)

    return run_slither(target_path, include_detectors=detectors)
