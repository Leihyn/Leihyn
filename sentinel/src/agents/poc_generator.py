"""
PoC Generator Agent - Automated Proof of Concept generation.

World-class auditors prove exploitability:
- No PoC = no bug (often)
- Working PoCs get higher payouts
- Helps devs understand severity

This agent:
1. Selects appropriate template based on vulnerability type
2. Uses ultrathink to generate exploit logic
3. Compiles and runs the PoC
4. Iterates on failures
5. Returns verified working PoC
"""

import asyncio
import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from ..core.agent import HunterAgent, AgentRole
from ..core.llm import LLMClient, Tool, get_llm_client
from ..core.types import Finding, Severity, VulnerabilityType

console = Console()


class PoCStatus(Enum):
    """Status of PoC generation."""
    PENDING = "pending"
    GENERATED = "generated"
    COMPILING = "compiling"
    COMPILE_ERROR = "compile_error"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class PoC:
    """Proof of concept for a vulnerability."""
    finding_id: str
    vulnerability_type: VulnerabilityType
    code: str
    template_used: str
    status: PoCStatus = PoCStatus.PENDING
    output: str = ""
    profit: float = 0.0
    gas_used: int = 0
    iterations: int = 0
    verified: bool = False


@dataclass
class PoCConfig:
    """Configuration for PoC generation."""
    ultrathink: bool = True
    thinking_budget: int = 20000
    fork_url: Optional[str] = None
    fork_block: Optional[int] = None
    max_iterations: int = 3
    output_dir: Optional[Path] = None
    run_tests: bool = True
    timeout: int = 120


class PoCGeneratorAgent(HunterAgent):
    """
    Automated PoC generation with verification.

    Features:
    - Template selection based on vulnerability type
    - Ultrathink for complex exploit logic
    - Automatic compilation and testing
    - Iterative fixing of failures
    - Profit tracking
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "PoCGenerator"
    description = "Generate verified Foundry PoCs for findings"

    # Template mapping
    TEMPLATES = {
        VulnerabilityType.REENTRANCY: "patterns/reentrancy_poc.sol",
        VulnerabilityType.REENTRANCY_CROSS_FUNCTION: "patterns/reentrancy_poc.sol",
        VulnerabilityType.REENTRANCY_READ_ONLY: "patterns/reentrancy_poc.sol",
        VulnerabilityType.FLASH_LOAN: "patterns/flash_loan_poc.sol",
        VulnerabilityType.FLASH_LOAN_ORACLE: "patterns/oracle_manipulation_poc.sol",
        VulnerabilityType.ORACLE_MANIPULATION: "patterns/oracle_manipulation_poc.sol",
        VulnerabilityType.ORACLE_STALE_PRICE: "patterns/oracle_manipulation_poc.sol",
        VulnerabilityType.ACCESS_CONTROL: "patterns/access_control_poc.sol",
        VulnerabilityType.ACCESS_UNPROTECTED_INIT: "patterns/access_control_poc.sol",
        VulnerabilityType.SIGNATURE_REPLAY: "patterns/access_control_poc.sol",
    }

    def __init__(
        self,
        state,
        config: Optional[PoCConfig] = None,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        super().__init__(state, llm_client, verbose)
        self.config = config or PoCConfig()
        self.templates_dir = Path(__file__).parent.parent.parent / "templates" / "poc"
        self.generated_pocs: list[PoC] = []

    @property
    def system_prompt(self) -> str:
        return """You are an expert at writing Foundry exploit PoCs.

Your PoCs must:
1. Actually compile (valid Solidity 0.8.20+)
2. Actually run (proper setup, valid addresses)
3. Actually exploit (demonstrate the vulnerability)
4. Show profit (log the extracted value)

Structure:
1. setUp(): Fork mainnet, deploy contracts, fund attacker
2. test_exploit(): Execute the attack step by step
3. Callbacks: Implement any needed callbacks (receive, flashloan, etc.)

Best practices:
- Use console.log liberally to show attack progress
- Use vm.prank/startPrank for impersonation
- Use deal() to give tokens/ETH
- Use vm.roll/warp for block/time manipulation
- Use vm.createSelectFork for mainnet forking
- Assert that profit was made at the end

Common imports:
```solidity
import "forge-std/Test.sol";
import "forge-std/console.sol";
```

Error handling:
- If compilation fails, fix the Solidity errors
- If test fails, analyze the revert reason and fix
- If no profit, verify the attack logic"""

    def get_tools(self) -> list[Tool]:
        return []

    async def run(self, **kwargs) -> list[PoC]:
        """Generate PoCs for all findings."""
        findings = kwargs.get("findings", [])
        if not findings:
            self.log("No findings to generate PoCs for", style="yellow")
            return []

        self.log(f"Generating PoCs for {len(findings)} findings...", style="bold magenta")

        for finding in findings:
            self.log(f"Generating PoC for: {finding.title}", style="cyan")

            poc = await self.generate_poc(finding)
            if poc:
                self.generated_pocs.append(poc)

                if poc.verified:
                    self.log(f"  [SUCCESS] PoC verified for {finding.id}", style="bold green")
                else:
                    self.log(f"  [FAILED] Could not verify PoC for {finding.id}", style="red")

        # Summary
        verified = sum(1 for p in self.generated_pocs if p.verified)
        self.log(f"Generated {len(self.generated_pocs)} PoCs, {verified} verified", style="bold")

        return self.generated_pocs

    async def generate_poc(self, finding: Finding) -> Optional[PoC]:
        """Generate and verify a PoC for a finding."""
        # Select template
        template = self._select_template(finding.vulnerability_type)
        template_content = self._load_template(template)

        # Create initial PoC
        poc = PoC(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            code="",
            template_used=template,
        )

        # Generate with ultrathink
        poc.code = await self._generate_poc_code(finding, template_content)
        poc.status = PoCStatus.GENERATED
        poc.iterations = 1

        # Verify loop
        while poc.iterations <= self.config.max_iterations:
            # Compile
            compile_result = await self._compile_poc(poc)
            if not compile_result["success"]:
                poc.status = PoCStatus.COMPILE_ERROR
                poc.output = compile_result["error"]

                # Try to fix
                if poc.iterations < self.config.max_iterations:
                    self.log(f"  Compile error, fixing (attempt {poc.iterations + 1})...", style="yellow")
                    poc.code = await self._fix_poc(poc, compile_result["error"])
                    poc.iterations += 1
                    continue
                else:
                    return poc

            # Run test
            if self.config.run_tests:
                run_result = await self._run_poc(poc)
                if run_result["success"]:
                    poc.status = PoCStatus.SUCCESS
                    poc.verified = True
                    poc.output = run_result["output"]
                    poc.profit = run_result.get("profit", 0)
                    poc.gas_used = run_result.get("gas", 0)
                    return poc
                else:
                    poc.status = PoCStatus.FAILED
                    poc.output = run_result["output"]

                    # Try to fix
                    if poc.iterations < self.config.max_iterations:
                        self.log(f"  Test failed, fixing (attempt {poc.iterations + 1})...", style="yellow")
                        poc.code = await self._fix_poc(poc, run_result["output"])
                        poc.iterations += 1
                        continue

            break

        return poc

    def _select_template(self, vuln_type: VulnerabilityType) -> str:
        """Select the appropriate template for the vulnerability type."""
        return self.TEMPLATES.get(vuln_type, "foundry/base_test.sol")

    def _load_template(self, template_path: str) -> str:
        """Load a template file."""
        full_path = self.templates_dir / template_path
        if full_path.exists():
            return full_path.read_text()
        return ""

    async def _generate_poc_code(self, finding: Finding, template: str) -> str:
        """Generate PoC code using ultrathink."""
        prompt = f"""Generate a working Foundry PoC for this vulnerability.

**Vulnerability:**
- ID: {finding.id}
- Title: {finding.title}
- Type: {finding.vulnerability_type.value}
- Severity: {finding.severity.value}
- Contract: {finding.contract}

**Description:**
{finding.description}

**Root Cause:**
{finding.root_cause or "See description"}

**Impact:**
{finding.impact or "See description"}

**Template to build on:**
```solidity
{template[:3000] if template else "// No template - write from scratch"}
```

**Requirements:**
1. Use Solidity 0.8.20+
2. Import forge-std/Test.sol and console.sol
3. Fork mainnet if needed: vm.createSelectFork("mainnet", blockNumber);
4. Name the test function: test_exploit_{finding.id.replace("-", "_")}
5. Use console.log to show attack progress
6. Assert profit at the end

**Fork Configuration:**
{f"Fork URL: {self.config.fork_url}" if self.config.fork_url else "Use hardcoded mainnet addresses"}
{f"Fork Block: {self.config.fork_block}" if self.config.fork_block else "Latest or specific block for reproducibility"}

Generate complete, compilable, runnable PoC code.
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=self.config.thinking_budget,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        # Extract code from response
        return self._extract_code(response.content)

    def _extract_code(self, response: str) -> str:
        """Extract Solidity code from LLM response."""
        # Try to find code block
        code_match = re.search(r'```solidity\s*\n(.*?)```', response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()

        code_match = re.search(r'```\s*\n(.*?)```', response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()

        # If no code block, assume entire response is code
        return response.strip()

    async def _fix_poc(self, poc: PoC, error: str) -> str:
        """Fix a failing PoC."""
        prompt = f"""Fix this Foundry PoC that has an error.

**Current Code:**
```solidity
{poc.code}
```

**Error:**
```
{error[:2000]}
```

**Instructions:**
1. Analyze the error carefully
2. Fix the specific issue
3. Return the complete fixed code

Common fixes:
- Import missing dependencies
- Fix interface definitions
- Correct function signatures
- Fix memory/calldata issues
- Add missing returns

Return the complete fixed Solidity code.
"""

        if self.config.ultrathink:
            response = self.llm.ultrathink(
                prompt=prompt,
                system=self.system_prompt,
                thinking_budget=12000,
                stream=False,
            )
        else:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=self.system_prompt,
            )

        return self._extract_code(response.content)

    async def _compile_poc(self, poc: PoC) -> dict:
        """Compile the PoC to check for errors."""
        if not self.config.output_dir:
            # Dry run - assume success
            return {"success": True}

        # Write the file
        poc_path = self.config.output_dir / f"{poc.finding_id}.t.sol"
        poc_path.parent.mkdir(parents=True, exist_ok=True)
        poc_path.write_text(poc.code)

        # Compile
        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=self.config.output_dir.parent,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return {"success": True}
            else:
                return {"success": False, "error": result.stderr or result.stdout}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Compilation timed out"}
        except FileNotFoundError:
            return {"success": False, "error": "Foundry not installed"}

    async def _run_poc(self, poc: PoC) -> dict:
        """Run the PoC test."""
        if not self.config.output_dir:
            return {"success": True, "output": "Dry run - not executed"}

        # Build command
        cmd = ["forge", "test", "-vvvv"]

        if self.config.fork_url:
            cmd.extend(["--fork-url", self.config.fork_url])
        if self.config.fork_block:
            cmd.extend(["--fork-block-number", str(self.config.fork_block)])

        # Match specific test
        cmd.extend(["--match-path", f"*{poc.finding_id}*"])

        try:
            result = subprocess.run(
                cmd,
                cwd=self.config.output_dir.parent,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )

            output = result.stdout + result.stderr

            # Check for success
            if "[PASS]" in output:
                profit = self._extract_profit(output)
                gas = self._extract_gas(output)
                return {
                    "success": True,
                    "output": output,
                    "profit": profit,
                    "gas": gas,
                }
            else:
                return {"success": False, "output": output}

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Test timed out"}
        except FileNotFoundError:
            return {"success": False, "output": "Foundry not installed"}

    def _extract_profit(self, output: str) -> float:
        """Extract profit amount from test output."""
        # Look for common profit logging patterns
        patterns = [
            r'Profit[:\s]+(\d+\.?\d*)',
            r'profit[:\s]+(\d+\.?\d*)',
            r'PROFIT[:\s]+(\d+\.?\d*)',
            r'Extracted[:\s]+(\d+\.?\d*)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return float(match.group(1))

        return 0.0

    def _extract_gas(self, output: str) -> int:
        """Extract gas used from test output."""
        match = re.search(r'gas[:\s]+(\d+)', output, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    def write_all_pocs(self, output_dir: Path) -> None:
        """Write all generated PoCs to files."""
        output_dir.mkdir(parents=True, exist_ok=True)

        for poc in self.generated_pocs:
            poc_path = output_dir / f"{poc.finding_id}.t.sol"
            poc_path.write_text(poc.code)
            self.log(f"Wrote PoC: {poc_path}")

    def print_summary(self) -> None:
        """Print summary of generated PoCs."""
        from rich.table import Table

        table = Table(title="Generated PoCs")
        table.add_column("Finding", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Status")
        table.add_column("Verified")
        table.add_column("Iterations")

        for poc in self.generated_pocs:
            status_style = "green" if poc.verified else "red"
            table.add_row(
                poc.finding_id,
                poc.vulnerability_type.value[:20],
                poc.status.value,
                "Yes" if poc.verified else "No",
                str(poc.iterations),
                style=status_style if poc.verified else None,
            )

        console.print(table)


# Convenience function
async def generate_pocs(
    findings: list[Finding],
    fork_url: Optional[str] = None,
    output_dir: Optional[Path] = None,
) -> list[PoC]:
    """Generate PoCs for findings."""
    config = PoCConfig(
        fork_url=fork_url,
        output_dir=output_dir,
    )
    # Create minimal state
    from ..core.types import AuditState
    state = AuditState(project_path=str(output_dir) if output_dir else "")

    agent = PoCGeneratorAgent(state=state, config=config)
    return await agent.run(findings=findings)
