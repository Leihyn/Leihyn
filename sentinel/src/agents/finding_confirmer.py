"""
Finding Confirmer — Semgrep-based deterministic confirmation of LLM findings.

LLM-generated findings are probabilistic. This agent adds a deterministic
signal: generate a Semgrep pattern that would match the specific code claim,
then run it. If the pattern matches at the claimed location, confidence goes
up. If it doesn't, confidence goes down. Tool failure is neutral.

Three phases:
1. Static rules (free, instant) — pre-built patterns for 20+ vuln types
2. LLM-generated patterns (one Haiku call per batch of ~5 findings) — for
   findings not covered by static rules
3. Run Semgrep deterministically (free, ~2-5 seconds)

Not all findings are Semgrep-confirmable. Logic bugs, cross-function issues,
and economic exploits can't be pattern-matched. Only arithmetic patterns,
missing checks, unsafe calls, and similar structural issues are attempted.

Static rules sourced from:
  https://github.com/kadenzipfel/smart-contract-vulnerabilities/tree/master/references

Budget: ~$0.01 for 10 findings (less if static rules cover most).
"""

import json
import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from ..core.llm import LLMClient, get_llm_client, HAIKU_MODEL
from ..core.types import AuditState, Finding, VulnerabilityType

console = Console()

# Vulnerability types where Semgrep can plausibly confirm/deny the claim
CONFIRMABLE_TYPES = {
    VulnerabilityType.ARITHMETIC,
    VulnerabilityType.PRECISION_LOSS,
    VulnerabilityType.ROUNDING_ERROR,
    VulnerabilityType.REENTRANCY,
    VulnerabilityType.REENTRANCY_CROSS_FUNCTION,
    VulnerabilityType.REENTRANCY_CROSS_CONTRACT,
    VulnerabilityType.REENTRANCY_READ_ONLY,
    VulnerabilityType.ACCESS_CONTROL,
    VulnerabilityType.MISSING_SLIPPAGE,
    VulnerabilityType.ERC20_RETURN_VALUE,
    VulnerabilityType.UNSAFE_CASTING,
    VulnerabilityType.INTEGER_OVERFLOW,
    VulnerabilityType.INTEGER_UNDERFLOW,
    VulnerabilityType.TX_ORIGIN,
    VulnerabilityType.ECRECOVER_ZERO,
    VulnerabilityType.DELEGATECALL,
    VulnerabilityType.UNPROTECTED_INITIALIZER,
    VulnerabilityType.MISSING_DEADLINE,
    VulnerabilityType.SELFDESTRUCT_DOS,
}

# Types that are logic/economic — Semgrep can't pattern-match these
SKIP_TYPES = {
    VulnerabilityType.BUSINESS_LOGIC,
    VulnerabilityType.INVARIANT_VIOLATION,
    VulnerabilityType.INCORRECT_ACCOUNTING,
    VulnerabilityType.FIRST_DEPOSITOR,
    VulnerabilityType.DONATION_ATTACK,
    VulnerabilityType.FLASH_LOAN,
    VulnerabilityType.FLASH_LOAN_GOVERNANCE,
    VulnerabilityType.FLASH_LOAN_REWARD,
    VulnerabilityType.ORACLE_MANIPULATION,
    VulnerabilityType.LP_PRICE_MANIPULATION,
    VulnerabilityType.SANDWICH_ATTACK,
    VulnerabilityType.FRONTRUNNING,
    VulnerabilityType.GOVERNANCE_MANIPULATION,
    VulnerabilityType.RACE_CONDITION,
    VulnerabilityType.TIME_MANIPULATION,
}

PATTERN_GEN_SYSTEM = """You are a Semgrep pattern generator for Solidity smart contract findings.

Given a list of security findings, generate Semgrep patterns that would CONFIRM the specific
code claim each finding makes. The pattern is NOT "find a vulnerability" -- it's "confirm
this specific claim about the code."

Example: Finding says "deposit() doesn't check totalSupply == 0 before dividing"
Pattern: A pattern matching division without a preceding zero check.

Rules:
- Use Semgrep's Solidity pattern syntax (metavariables like $X, $FUNC, ellipsis ...)
- Keep patterns simple and focused on the specific claim
- Use "solidity" as the language
- If a finding can't be expressed as a pattern, set semgrep_pattern to null

IMPORTANT — avoid generating patterns that would match these FALSE POSITIVE cases:
- Reentrancy: state updated BEFORE external call, or nonReentrant modifier present
- Access control: tx.origin used only for logging, not authorization
- Precision loss: multiplication done before division, or WAD/RAY scaling used
- Unsafe casting: SafeCast library or bounds check before cast
- ERC20: SafeERC20 wrappers used (safeTransfer, safeApprove)
- Signatures: OpenZeppelin ECDSA library used, or EIP-712 domain separator present
- Slippage: minAmountOut validated via oracle price, not just parameter presence

Each finding may include false_positive_hints — factor these into your pattern design.

Output ONLY a JSON array (no markdown fences):
[{"finding_id": "...", "semgrep_pattern": "...", "description": "..."}]
"""


class FindingConfirmer:
    """Deterministic finding confirmation via Semgrep pattern matching.

    Follows the same `apply(findings, state) -> list[Finding]` interface
    as C4SeverityGate.
    """

    def __init__(
        self,
        state: AuditState,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        self.state = state
        self.llm = llm_client or get_llm_client()
        self.verbose = verbose
        self.results: list[tuple[str, str, str]] = []  # (finding_id, result, source)

    def log(self, message: str, style: str = "white") -> None:
        if self.verbose:
            console.print(f"[{style}][FindingConfirmer][/{style}] {message}")
        self.state.add_log(f"[FindingConfirmer] {message}")

    def _is_confirmable(self, finding: Finding) -> bool:
        """Check if a finding's type is amenable to Semgrep pattern confirmation."""
        if finding.vulnerability_type in SKIP_TYPES:
            return False
        if finding.vulnerability_type in CONFIRMABLE_TYPES:
            return True
        # Default: skip unknown types rather than waste a pattern attempt
        return False

    def _try_static_rules(
        self, finding: Finding, state: AuditState,
    ) -> Optional[str]:
        """Try pre-built static rules for this finding's vuln type.

        Returns 'confirmed'/'unconfirmed'/'error' if static rules exist,
        None if no static rules are available (caller should fall back to LLM).
        """
        from ..core.skills.semgrep_rules import get_rules_for_type

        rule_set = get_rules_for_type(finding.vulnerability_type)
        if not rule_set or not rule_set.rules:
            return None  # No static rules — need LLM fallback

        try:
            from ..core.skills.semgrep_integration import SemgrepIntegration
        except ImportError:
            return "error"

        try:
            integration = SemgrepIntegration()
        except Exception:
            return "error"

        # Run all rules for this vuln type in a single scan
        try:
            report = integration.scan(
                project_path=str(state.target_path),
                rulesets=[],
                custom_rules=rule_set.rules,
                include_patterns=["*.sol"],
            )
        except Exception as e:
            self.log(f"Static rule scan failed for {finding.id}: {e}", style="yellow")
            return "error"

        if report.errors and not report.results:
            return "error"

        # Check if any result matches the claimed contract
        contract_name = finding.contract.split(",")[0].strip()
        for result in report.results:
            if contract_name.lower() in result.path.lower():
                return "confirmed"

        # Matched elsewhere in the project
        if report.results:
            return "confirmed"

        return "unconfirmed"

    async def _generate_patterns_batch(
        self, findings: list[Finding],
    ) -> list[dict]:
        """Ask Haiku to generate Semgrep patterns for a batch of findings.

        Enriches the prompt with false positive hints from the static rule
        library so Haiku generates more precise patterns.
        """
        from ..core.skills.semgrep_rules import get_false_positive_hints

        batch_desc = []
        for f in findings:
            entry = {
                "finding_id": f.id,
                "title": f.title,
                "vulnerability_type": f.vulnerability_type.value,
                "contract": f.contract,
                "function": f.function or "N/A",
                "description_excerpt": f.description[:400],
            }
            # Enrich with false positive hints from the reference library
            fp_hints = get_false_positive_hints(f.vulnerability_type)
            if fp_hints:
                entry["false_positive_hints"] = fp_hints
            batch_desc.append(entry)

        prompt = (
            "Generate Semgrep patterns for these Solidity findings:\n\n"
            + json.dumps(batch_desc, indent=2)
        )

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=PATTERN_GEN_SYSTEM,
                max_tokens=2048,
                model_override=HAIKU_MODEL,
            )
        except Exception as e:
            self.log(f"Pattern generation failed: {e}", style="red")
            return []

        # Parse JSON response
        text = response.content.strip()
        # Strip markdown fences if present
        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        try:
            patterns = json.loads(text)
            if isinstance(patterns, list):
                return patterns
        except (json.JSONDecodeError, ValueError):
            self.log("Failed to parse pattern generation response", style="yellow")

        return []

    def _run_semgrep_confirmation(
        self, finding: Finding, pattern_info: dict, state: AuditState,
    ) -> str:
        """Run Semgrep with a generated pattern against the project. Returns 'confirmed'/'unconfirmed'/'error'."""
        pattern = pattern_info.get("semgrep_pattern")
        if not pattern:
            return "skipped"

        try:
            from ..core.skills.semgrep_integration import (
                SemgrepIntegration,
                SemgrepSeverity,
            )
        except ImportError:
            self.log("Semgrep integration not available", style="yellow")
            return "error"

        try:
            integration = SemgrepIntegration()
        except Exception:
            return "error"

        rule_id = f"confirm-{finding.id.lower()}"
        description = pattern_info.get("description", f"Confirmation for {finding.id}")

        rule = integration.create_pattern_rule(
            rule_id=rule_id,
            languages=["solidity"],
            message=description,
            pattern=pattern,
            severity=SemgrepSeverity.WARNING,
        )

        try:
            report = integration.scan(
                project_path=str(state.target_path),
                rulesets=[],
                custom_rules=[rule],
                include_patterns=["*.sol"],
            )
        except Exception as e:
            self.log(f"Semgrep scan failed for {finding.id}: {e}", style="yellow")
            return "error"

        if report.errors and not report.results:
            return "error"

        # Check if any result matches the claimed contract
        contract_name = finding.contract.split(",")[0].strip()
        for result in report.results:
            # Match by contract file name or path
            if contract_name.lower() in result.path.lower():
                return "confirmed"

        # Pattern ran but didn't match at the claimed location
        if report.results:
            # Matched elsewhere — partial confirmation
            return "confirmed"

        return "unconfirmed"

    def _apply_result(self, finding: Finding, result: str, source: str = "llm") -> None:
        """Adjust finding confidence based on Semgrep confirmation result."""
        self.results.append((finding.id, result, source))

        if result == "confirmed":
            old_conf = finding.confidence
            finding.confidence = min(1.0, finding.confidence + 0.2)
            if "[SEMGREP-CONFIRMED]" not in finding.description:
                finding.description += "\n\n[SEMGREP-CONFIRMED] Pattern matched by deterministic Semgrep scan."
            self.log(
                f"  [{finding.id}] CONFIRMED (confidence {old_conf:.2f} -> {finding.confidence:.2f})",
                style="green",
            )
        elif result == "unconfirmed":
            old_conf = finding.confidence
            finding.confidence = max(0.0, finding.confidence - 0.3)
            if "[SEMGREP-UNCONFIRMED]" not in finding.description:
                finding.description += "\n\n[SEMGREP-UNCONFIRMED] Pattern did not match. Manual review recommended."
            self.log(
                f"  [{finding.id}] UNCONFIRMED (confidence {old_conf:.2f} -> {finding.confidence:.2f})",
                style="yellow",
            )
        # "error" and "skipped" — no change

    def _generate_codeql_queries(
        self, findings: list[Finding], state: AuditState,
    ) -> list[Path]:
        """Generate CodeQL queries for non-Solidity findings. Saved for manual use.

        Most Sentinel targets are pure Solidity, which CodeQL doesn't support.
        This generates .ql files for any non-Solidity code in the project
        (JS deployment scripts, Python tooling, etc.) and saves them for
        manual use or future integration.
        """
        # Only generate if project has non-Solidity code worth scanning
        non_sol_findings = [
            f for f in findings
            if not f.contract.endswith(".sol") and f.vulnerability_type in CONFIRMABLE_TYPES
        ]
        if not non_sol_findings:
            return []

        output_dir = state.target_path / ".sentinel" / "codeql_queries"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return []

        generated = []
        batch_desc = []
        for f in non_sol_findings[:5]:
            batch_desc.append({
                "finding_id": f.id,
                "title": f.title,
                "description_excerpt": f.description[:300],
            })

        if not batch_desc:
            return generated

        prompt = (
            "Generate CodeQL queries (.ql format) for these findings. "
            "Output a JSON array of {finding_id, ql_code}:\n\n"
            + json.dumps(batch_desc, indent=2)
        )

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system="You generate CodeQL queries for security findings. Output only valid JSON.",
                max_tokens=2048,
                model_override=HAIKU_MODEL,
            )

            text = response.content.strip()
            if "```" in text:
                match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
                if match:
                    text = match.group(1).strip()

            queries = json.loads(text)
            for q in queries:
                if not isinstance(q, dict) or "ql_code" not in q:
                    continue
                finding_id = q.get("finding_id", "unknown")
                ql_path = output_dir / f"{finding_id}.ql"
                ql_path.write_text(q["ql_code"])
                generated.append(ql_path)

        except Exception as e:
            self.log(f"CodeQL query generation failed: {e}", style="yellow")

        if generated:
            self.log(f"Generated {len(generated)} CodeQL queries in {output_dir}", style="dim")

        return generated

    async def apply(
        self, findings: list[Finding], state: AuditState,
    ) -> list[Finding]:
        """Apply Semgrep confirmation to findings. Returns the same list with adjusted confidence.

        Strategy:
        1. Try pre-built static rules first (free, instant, deterministic)
        2. Fall back to LLM-generated patterns for findings without static rules
        3. Run Semgrep scans and adjust confidence based on results
        """
        if not findings:
            return findings

        # Split into confirmable and non-confirmable
        confirmable = [f for f in findings if self._is_confirmable(f) and not f.false_positive]
        skipped_count = len(findings) - len(confirmable)

        self.log(
            f"Confirming {len(confirmable)} findings via Semgrep "
            f"({skipped_count} skipped — logic/economic type)",
            style="bold magenta",
        )

        if not confirmable:
            return findings

        # Phase 1: Try static rules first (free, no LLM cost)
        need_llm: list[Finding] = []
        static_tried = 0

        for finding in confirmable:
            result = self._try_static_rules(finding, state)
            if result is not None:
                # Static rules exist for this type
                static_tried += 1
                if result != "error":
                    self._apply_result(finding, result, source="static")
                # On error, fall through to LLM as backup
                elif result == "error":
                    need_llm.append(finding)
            else:
                # No static rules — needs LLM-generated pattern
                need_llm.append(finding)

        if static_tried > 0:
            self.log(
                f"Static rules: {static_tried} findings tested, "
                f"{len(need_llm)} need LLM fallback",
                style="cyan",
            )

        # Phase 2: LLM-generated patterns for remaining findings
        if need_llm:
            batch_size = 5
            all_patterns: dict[str, dict] = {}

            for i in range(0, len(need_llm), batch_size):
                batch = need_llm[i : i + batch_size]
                self.log(f"Generating LLM patterns for batch {i // batch_size + 1}...", style="cyan")
                patterns = await self._generate_patterns_batch(batch)
                for p in patterns:
                    fid = p.get("finding_id")
                    if fid:
                        all_patterns[fid] = p

            self.log(f"Generated {len(all_patterns)} LLM patterns", style="cyan")

            # Phase 3: Run Semgrep confirmation for LLM-generated patterns
            for finding in need_llm:
                pattern_info = all_patterns.get(finding.id)
                if not pattern_info or not pattern_info.get("semgrep_pattern"):
                    continue

                result = self._run_semgrep_confirmation(finding, pattern_info, state)
                self._apply_result(finding, result)

        # Optional: Generate CodeQL queries for non-Solidity findings
        self._generate_codeql_queries(findings, state)

        self._print_summary()
        return findings

    def _print_summary(self) -> None:
        """Print confirmation summary table."""
        if not self.results:
            self.log("No patterns were testable", style="dim")
            return

        console.print("\n[bold magenta]=== FINDING CONFIRMATION RESULTS ===[/bold magenta]\n")

        table = Table(title="Semgrep Confirmation")
        table.add_column("Finding", style="cyan", max_width=20)
        table.add_column("Result")
        table.add_column("Source", style="dim")

        for finding_id, result, source in self.results:
            style = {
                "confirmed": "green",
                "unconfirmed": "yellow",
                "error": "red",
                "skipped": "dim",
            }.get(result, "white")
            table.add_row(
                finding_id[:20],
                f"[{style}]{result.upper()}[/{style}]",
                source,
            )

        console.print(table)

        confirmed = sum(1 for _, r, _ in self.results if r == "confirmed")
        unconfirmed = sum(1 for _, r, _ in self.results if r == "unconfirmed")
        static_count = sum(1 for _, _, s in self.results if s == "static")
        llm_count = sum(1 for _, _, s in self.results if s == "llm")
        console.print(
            f"\n{confirmed} confirmed, {unconfirmed} unconfirmed "
            f"({static_count} static rules, {llm_count} LLM-generated)"
        )
