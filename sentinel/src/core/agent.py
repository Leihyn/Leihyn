"""
Base agent class that all specialized agents inherit from.
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

from .llm import LLMClient, Tool, get_llm_client
from .types import AgentRole, AuditState, Finding

console = Console()


class BaseAgent(ABC):
    """
    Base class for all agents in the Sentinel system.

    Each agent has:
    - A specific role and system prompt
    - Access to tools relevant to its task
    - Ability to update the shared audit state
    """

    role: AgentRole
    name: str
    description: str

    def __init__(
        self,
        state: AuditState,
        llm_client: Optional[LLMClient] = None,
        verbose: bool = True,
    ):
        self.state = state
        self.llm = llm_client or get_llm_client()
        self.verbose = verbose
        self._tools: list[Tool] = []

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """The system prompt that defines this agent's behavior."""
        pass

    @abstractmethod
    def get_tools(self) -> list[Tool]:
        """Return the tools this agent can use."""
        pass

    @abstractmethod
    async def run(self, **kwargs) -> Any:
        """Execute the agent's main task."""
        pass

    def log(self, message: str, style: str = "white") -> None:
        """Log a message with the agent's name."""
        if self.verbose:
            console.print(f"[{style}][{self.name}][/{style}] {message}")
        self.state.add_log(f"[{self.name}] {message}")

    def log_finding(self, finding: Finding) -> None:
        """Log and add a finding."""
        severity_colors = {
            "Critical": "red bold",
            "High": "red",
            "Medium": "yellow",
            "Low": "blue",
            "Informational": "dim",
            "Gas": "dim",
        }
        color = severity_colors.get(finding.severity.value, "white")

        if self.verbose:
            console.print(
                Panel(
                    f"[bold]{finding.title}[/bold]\n\n"
                    f"Contract: {finding.contract}\n"
                    f"Type: {finding.vulnerability_type.value}\n\n"
                    f"{finding.description[:200]}...",
                    title=f"[{color}]{finding.severity.value}[/{color}]",
                    border_style=color,
                )
            )
        self.state.add_finding(finding)

    def execute_tool(self, tool_name: str, tool_input: dict) -> Any:
        """Execute a tool by name."""
        for tool in self._tools:
            if tool.name == tool_name:
                return tool.handler(tool_input)
        raise ValueError(f"Unknown tool: {tool_name}")

    def run_with_tools(
        self,
        prompt: str,
        additional_context: str = "",
        max_iterations: int = 10,
    ) -> str:
        """
        Run the agent with its tools until it produces a final response.
        """
        self._tools = self.get_tools()

        full_system = self.system_prompt
        if additional_context:
            full_system += f"\n\n## Additional Context\n{additional_context}"

        def on_tool_call(name: str, input_data: dict) -> None:
            self.log(f"Calling tool: {name}", style="cyan")

        response, tool_results = self.llm.run_agent_loop(
            initial_message=prompt,
            system=full_system,
            tools=self._tools,
            max_iterations=max_iterations,
            on_tool_call=on_tool_call,
        )

        return response

    def ask_llm(self, prompt: str, context: str = "") -> str:
        """Simple LLM query without tools."""
        full_system = self.system_prompt
        if context:
            full_system += f"\n\n## Context\n{context}"

        response = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system=full_system,
        )
        return response.content


class HunterAgent(BaseAgent):
    """
    Base class for vulnerability hunter agents.

    Hunters focus on finding specific types of vulnerabilities.
    """

    vulnerability_types: list[str] = []

    def get_hunt_prompt(self, contract_source: str, contract_name: str) -> str:
        """Generate the hunting prompt for this vulnerability type."""
        return f"""
Analyze the following smart contract for {', '.join(self.vulnerability_types)} vulnerabilities.

## Contract: {contract_name}

```solidity
{contract_source}
```

## Instructions

1. Carefully analyze the code for any {', '.join(self.vulnerability_types)} vulnerabilities
2. Consider both obvious and subtle attack vectors
3. Think about how an attacker would exploit any issues found
4. For each potential vulnerability:
   - Explain the root cause
   - Describe the attack scenario
   - Assess the impact
   - Suggest a fix

Be thorough but avoid false positives. Only report issues you are confident about.
"""

    def parse_findings_from_response(self, response: str, contract_name: str) -> list[Finding]:
        """Parse findings from the LLM response."""
        # This is a simple implementation - could be enhanced with structured output
        findings = []
        # The LLM should return structured findings that we can parse
        # For now, we'll rely on the agent to call a report_finding tool
        return findings


class AnalysisAgent(BaseAgent):
    """
    Base class for analysis agents that process data rather than hunt bugs.

    Examples: Recon, Static Analysis, Invariant agents
    """

    pass


class SynthesisAgent(BaseAgent):
    """
    Base class for agents that synthesize information.

    Examples: Attack, PoC Generator, Reporter agents
    """

    pass
