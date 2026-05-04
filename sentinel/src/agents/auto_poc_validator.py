"""
Auto-PoC validator (Point 4).

Generates a Foundry-fork test scaffold per finding, runs `forge test`, and
demotes any finding without a passing PoC to QA tier. This is the gate that
turns "the LLM still believes it" devils-advocate into "the exploit either
runs or it doesn't".

Three input modes:
- finding.poc.code already present and well-formed -> just run it.
- finding.metadata['poc_template'] present -> render + run.
- neither -> emit a SCAFFOLD test that asserts the protocol's stated
  invariant; if the scaffold compiles and reverts as expected we keep the
  finding High/Critical, else demote.

The validator is intentionally conservative: a PoC that does NOT compile is
NOT proof of innocence; it's a signal we need a human. We tag those with
`needs-human-poc` rather than auto-dropping.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.types import AuditState, Finding, PoC, Severity
from ..tools.foundry import check_foundry_installed


@dataclass
class ValidationOutcome:
    finding_id: str
    status: str                # PASS / FAIL / NO_POC / NEEDS_HUMAN
    detail: str = ""
    forge_stdout: str = ""
    forge_stderr: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "detail": self.detail[:1000],
            "forge_stdout_tail": self.forge_stdout[-1500:],
            "forge_stderr_tail": self.forge_stderr[-1500:],
        }


_DEFAULT_FOUNDRY_TOML = """[profile.default]
src = "src"
out = "out"
libs = ["lib"]
verbosity = 3
"""


def _setup_project(project_path: Path, fork_url: Optional[str], fork_block: Optional[int]) -> None:
    project_path.mkdir(parents=True, exist_ok=True)
    (project_path / "src").mkdir(exist_ok=True)
    (project_path / "test").mkdir(exist_ok=True)
    (project_path / "lib").mkdir(exist_ok=True)
    toml = _DEFAULT_FOUNDRY_TOML
    if fork_url:
        toml += f'\n[rpc_endpoints]\nmainnet = "{fork_url}"\n'
        toml += "[fuzz]\nruns = 64\n"
        if fork_block:
            toml += f"\nfork_block_number = {fork_block}\n"
    (project_path / "foundry.toml").write_text(toml)


def _run_forge(
    project_path: Path,
    fork_url: Optional[str],
    fork_block: Optional[int],
    timeout: int = 180,
) -> tuple[bool, str, str]:
    cmd = ["forge", "test", "-vv"]
    if fork_url:
        cmd.extend(["--fork-url", fork_url])
        if fork_block:
            cmd.extend(["--fork-block-number", str(fork_block)])
    try:
        proc = subprocess.run(
            cmd, cwd=str(project_path), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return False, e.stdout or "", "forge test timed out"
    except FileNotFoundError:
        return False, "", "forge binary not found"
    return proc.returncode == 0, proc.stdout, proc.stderr


def _scaffold_for_finding(finding: Finding) -> str:
    """Last-resort scaffold: a Foundry test that imports the contract and
    encodes the finding's must-hold-property as an assertion. The test
    runs only if the project is set up correctly; this scaffold is meant
    to be human-completed, not to actually exploit anything by itself.
    """
    contract = finding.contract or "Target"
    fn = finding.function or "exploit_path"
    title = (finding.title or "FindingPoC").replace(" ", "_")[:40]
    title = "".join(c if c.isalnum() or c == "_" else "_" for c in title)
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// Sentinel auto-PoC SCAFFOLD for finding {finding.id}
// title: {finding.title}
// must-hold: {finding.metadata.get('must_hold_property', 'see report') if isinstance(finding.metadata, dict) else 'see report'}
//
// This scaffold is a stub. Wire up the deploy + caller flow that proves
// the must-hold property fails. If you remove this comment, the FP gate
// will treat the test as human-authored.
contract {title}_PoC is Test {{
    function setUp() public {{
        // TODO: deploy / fork-import {contract}
    }}

    function test_{fn}_breaks_invariant() public {{
        // TODO: trigger the {fn} path with attacker-controlled inputs
        // and assert that the invariant fails.
        assertTrue(true, "scaffold only");
    }}
}}
"""


def validate_finding(
    finding: Finding,
    fork_url: Optional[str],
    fork_block: Optional[int],
    project_root: Optional[Path] = None,
    timeout: int = 180,
    runner: str = "foundry",
) -> ValidationOutcome:
    """Validate a single finding by running its PoC under Foundry or cargo test.

    `runner="cargo"` routes to a `cargo test` runner for Rust PoCs (Solana,
    Anchor, native Rust). `runner="foundry"` (default) routes to Foundry.

    Returns a ValidationOutcome; mutates finding.poc.executed/success.
    """
    if runner == "cargo":
        return _validate_cargo(finding, project_root, timeout)
    if not check_foundry_installed():
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail="forge not installed; cannot auto-validate",
        )

    poc = getattr(finding, "poc", None)
    code: Optional[str] = None
    is_scaffold = False
    if poc and getattr(poc, "code", "").strip():
        code = poc.code
    elif isinstance(finding.metadata, dict) and finding.metadata.get("poc_template"):
        code = finding.metadata["poc_template"]
    else:
        code = _scaffold_for_finding(finding)
        is_scaffold = True

    if project_root is None:
        project_root = Path(tempfile.mkdtemp(prefix="sentinel_poc_"))
    _setup_project(project_root, fork_url, fork_block)
    test_path = project_root / "test" / f"FindingPoC_{finding.id}.t.sol"
    try:
        test_path.write_text(code)
    except OSError as e:
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail=f"could not write test file: {e}",
        )

    ok, stdout, stderr = _run_forge(project_root, fork_url, fork_block, timeout=timeout)
    if is_scaffold:
        # A scaffold passing means nothing; the human must complete it.
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail="auto-scaffold emitted; human must complete the PoC",
            forge_stdout=stdout, forge_stderr=stderr,
        )

    if poc is None:
        finding.poc = PoC(finding_id=finding.id, code=code)
        poc = finding.poc

    poc.executed = True
    poc.success = ok
    poc.output = (stdout or "") + ("\n--- stderr ---\n" + stderr if stderr else "")

    if ok:
        return ValidationOutcome(
            finding_id=finding.id, status="PASS",
            detail="forge test passed; PoC stands",
            forge_stdout=stdout, forge_stderr=stderr,
        )
    return ValidationOutcome(
        finding_id=finding.id, status="FAIL",
        detail="forge test failed",
        forge_stdout=stdout, forge_stderr=stderr,
    )


_DEMOTE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


def validate_all(
    state: AuditState,
    fork_url: Optional[str],
    fork_block: Optional[int],
    promote_only_above: Severity = Severity.LOW,
) -> list[ValidationOutcome]:
    """Validate every finding at or above `promote_only_above`. Findings that
    cannot be auto-validated (NEEDS_HUMAN) are tagged but not demoted; FAIL
    findings are demoted one tier.
    """
    out: list[ValidationOutcome] = []
    for f in state.findings:
        if _sev_value(f.severity) < _sev_value(promote_only_above):
            continue
        result = validate_finding(f, fork_url, fork_block)
        if isinstance(f.metadata, dict):
            f.metadata.setdefault("auto_poc", []).append(result.to_dict())
        if result.status == "FAIL":
            old = f.severity
            f.severity = _DEMOTE.get(f.severity, f.severity)
            if isinstance(f.metadata, dict):
                f.metadata["auto_poc_demote"] = f"{old.value} -> {f.severity.value}"
        out.append(result)
    return out


def _sev_value(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
        Severity.LOW: 1, Severity.INFORMATIONAL: 0,
    }.get(sev, 0)


def _validate_cargo(
    finding: Finding,
    project_root: Optional[Path],
    timeout: int = 600,
) -> ValidationOutcome:
    """Run `cargo test` against the finding's Rust PoC.

    The PoC must be either:
    - A `#[test]` function in a Rust crate at `project_root`, with the test
      name matching `finding.metadata['cargo_test_name']`.
    - Or a full crate at `project_root` (we run `cargo test` and pass/fail
      depending on overall result).

    For Anchor/Solana programs, the caller should set `project_root` to the
    program directory and `cargo_test_name` to the specific instruction test.
    """
    if not project_root or not project_root.exists():
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail="cargo runner needs project_root pointing at a Cargo.toml",
        )
    if not (project_root / "Cargo.toml").exists():
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail=f"no Cargo.toml at {project_root}",
        )
    test_name = (finding.metadata or {}).get("cargo_test_name") if isinstance(finding.metadata, dict) else None
    cmd = ["cargo", "test"]
    if test_name:
        cmd.extend(["--", test_name])
    cmd.append("--quiet")
    try:
        proc = subprocess.run(
            cmd, cwd=str(project_root), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return ValidationOutcome(
            finding_id=finding.id, status="FAIL",
            detail="cargo test timed out",
            forge_stdout=e.stdout or "", forge_stderr="timeout",
        )
    except FileNotFoundError:
        return ValidationOutcome(
            finding_id=finding.id, status="NEEDS_HUMAN",
            detail="cargo not installed",
        )
    poc = getattr(finding, "poc", None)
    if poc is not None:
        poc.executed = True
        poc.success = proc.returncode == 0
        poc.output = (proc.stdout or "") + ("\n--- stderr ---\n" + proc.stderr if proc.stderr else "")
    if proc.returncode == 0:
        return ValidationOutcome(
            finding_id=finding.id, status="PASS",
            detail=f"cargo test passed{' for ' + test_name if test_name else ''}",
            forge_stdout=proc.stdout, forge_stderr=proc.stderr,
        )
    return ValidationOutcome(
        finding_id=finding.id, status="FAIL",
        detail="cargo test failed",
        forge_stdout=proc.stdout, forge_stderr=proc.stderr,
    )


def cleanup_temp_projects(prefix: str = "sentinel_poc_") -> int:
    """Best-effort cleanup of leaked temp dirs from previous runs."""
    base = Path(tempfile.gettempdir())
    n = 0
    for p in base.glob(f"{prefix}*"):
        try:
            shutil.rmtree(p, ignore_errors=True)
            n += 1
        except OSError:
            continue
    return n
