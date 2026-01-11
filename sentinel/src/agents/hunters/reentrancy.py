"""
Reentrancy Hunter Agent - Specialized in finding reentrancy vulnerabilities.

Supports: Solidity (EVM), Cairo (StarkNet)
"""

import re
import uuid
from typing import Any

from ...core.agent import HunterAgent
from ...core.llm import Tool
from ...core.types import (
    AgentRole,
    AuditState,
    Finding,
    Severity,
    VulnerabilityType,
)
from ...core.languages import Language
from ...tools.code_reader import get_function_source, summarize_contract


class ReentrancyHunter(HunterAgent):
    """
    Specialized agent for finding reentrancy vulnerabilities.

    Hunts for:
    - Classic reentrancy (external call before state update)
    - Cross-function reentrancy (reenter through different function)
    - Cross-contract reentrancy (reenter through callback to another contract)
    - Read-only reentrancy (view function returns stale data)

    Language support:
    - Solidity: Full support
    - Cairo: Basic support (external calls before storage writes)
    """

    role = AgentRole.VULNERABILITY_HUNTER
    name = "ReentrancyHunter"
    description = "Hunts for reentrancy vulnerabilities"
    vulnerability_types = ["reentrancy"]

    def __init__(self, state: AuditState, **kwargs):
        super().__init__(state=state, **kwargs)
        self.language = kwargs.get("language", Language.SOLIDITY)

    @property
    def system_prompt(self) -> str:
        return """You are an expert smart contract security auditor specializing in reentrancy vulnerabilities.

## Reentrancy Variants You Hunt For

### 1. Classic Reentrancy
External call (especially ETH transfers) before state update.
```solidity
// VULNERABLE
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    require(success);
    balances[msg.sender] -= amount;  // State update AFTER call
}
```

### 2. Cross-Function Reentrancy
Reenter through a different function that shares state.
```solidity
// VULNERABLE - attacker calls withdraw(), which calls back, then calls transfer()
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0;
}

function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount);  // Still has old balance!
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### 3. Cross-Contract Reentrancy
Reenter through a callback to a different contract that reads stale state.
```solidity
// Contract A
function withdraw() external {
    contractB.doSomething(msg.sender);  // Callback to B
    balances[msg.sender] = 0;
}

// Contract B
function doSomething(address user) external {
    uint256 balance = contractA.balances(user);  // Reads stale balance!
}
```

### 4. Read-Only Reentrancy
View functions return stale data during a reentrancy attack.
```solidity
// VULNERABLE - getPrice() returns stale data during reentrancy
function getPrice() public view returns (uint256) {
    return reserve1 / reserve0;  // Can be manipulated mid-transaction
}
```

## Analysis Approach

1. **Identify External Calls**: Find all `.call`, `.transfer`, `.send`, and calls to external contracts
2. **Check State Updates**: For each external call, verify state is updated BEFORE the call
3. **Analyze Cross-Function**: Check if other functions read state that could be stale
4. **Check Modifiers**: Look for `nonReentrant` or similar guards
5. **Consider Callbacks**: ERC777 tokens, flash loans, and other callback patterns

## When Reporting

- Clearly explain the attack path
- Identify what state can be manipulated
- Estimate the impact (fund loss, state corruption)
- Note any mitigating factors (access control, value limits)

Only report HIGH confidence findings. Avoid false positives."""

    def get_tools(self) -> list[Tool]:
        """Tools for reentrancy hunting."""
        return [
            Tool(
                name="get_contract_source",
                description="Get the full source code of a contract",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {"type": "string"},
                    },
                    "required": ["contract_name"],
                },
                handler=self._get_contract_source,
            ),
            Tool(
                name="get_function_code",
                description="Get the source code of a specific function",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {"type": "string"},
                        "function_name": {"type": "string"},
                    },
                    "required": ["contract_name", "function_name"],
                },
                handler=self._get_function_code,
            ),
            Tool(
                name="find_external_calls",
                description="Find all external calls in a contract",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {"type": "string"},
                    },
                    "required": ["contract_name"],
                },
                handler=self._find_external_calls,
            ),
            Tool(
                name="check_reentrancy_guard",
                description="Check if a function has reentrancy protection",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_name": {"type": "string"},
                        "function_name": {"type": "string"},
                    },
                    "required": ["contract_name", "function_name"],
                },
                handler=self._check_reentrancy_guard,
            ),
            Tool(
                name="report_finding",
                description="Report a reentrancy vulnerability finding",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "contract": {"type": "string"},
                        "function": {"type": "string"},
                        "description": {"type": "string"},
                        "impact": {"type": "string"},
                        "root_cause": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["title", "severity", "contract", "description", "impact"],
                },
                handler=self._report_finding,
            ),
        ]

    def _get_contract_source(self, params: dict) -> str:
        """Get full contract source."""
        name = params["contract_name"]
        for contract in self.state.contracts:
            if contract.name == name:
                return contract.source
        return f"Contract not found: {name}"

    def _get_function_code(self, params: dict) -> str:
        """Get specific function code."""
        contract_name = params["contract_name"]
        function_name = params["function_name"]

        for contract in self.state.contracts:
            if contract.name == contract_name:
                source = get_function_source(contract, function_name)
                if source:
                    return source
                return f"Function not found: {function_name}"

        return f"Contract not found: {contract_name}"

    def _find_external_calls(self, params: dict) -> str:
        """Find all external calls in a contract."""
        name = params["contract_name"]

        for contract in self.state.contracts:
            if contract.name == name:
                calls = []
                for func in contract.functions:
                    for call in func.external_calls:
                        value_note = " (sends ETH)" if call.value_sent else ""
                        calls.append(
                            f"  {func.name}() -> {call.target}.{call.function}(){value_note}"
                        )

                if calls:
                    return "External calls found:\n" + "\n".join(calls)
                return "No external calls found in this contract."

        return f"Contract not found: {name}"

    def _check_reentrancy_guard(self, params: dict) -> str:
        """Check if a function has reentrancy protection."""
        contract_name = params["contract_name"]
        function_name = params["function_name"]

        for contract in self.state.contracts:
            if contract.name == contract_name:
                for func in contract.functions:
                    if func.name == function_name:
                        # Check for common reentrancy guards
                        guards = [
                            "nonReentrant",
                            "noReentrancy",
                            "reentrancyGuard",
                            "lock",
                            "mutex",
                        ]

                        for guard in guards:
                            if guard.lower() in [m.lower() for m in func.modifiers]:
                                return f"PROTECTED: Function has '{guard}' modifier"

                        # Check inheritance for ReentrancyGuard
                        if any("ReentrancyGuard" in inh for inh in contract.inheritance):
                            return "Contract inherits ReentrancyGuard, but function may not use it"

                        return "NO PROTECTION: No reentrancy guard found on this function"

        return f"Function not found: {contract_name}.{function_name}"

    def _report_finding(self, params: dict) -> str:
        """Report a finding."""
        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        finding = Finding(
            id=f"REENTRANCY-{uuid.uuid4().hex[:8]}",
            title=params["title"],
            severity=severity_map.get(params["severity"], Severity.MEDIUM),
            vulnerability_type=VulnerabilityType.REENTRANCY,
            description=params["description"],
            contract=params["contract"],
            function=params.get("function"),
            impact=params.get("impact", ""),
            root_cause=params.get("root_cause", ""),
            recommendation=params.get("recommendation", ""),
            found_by=self.role,
            confidence=params.get("confidence", 0.7),
        )

        self.log_finding(finding)
        return f"Finding reported: {finding.id}"

    def _quick_scan(self) -> list[dict]:
        """
        Quick regex-based scan for potential reentrancy patterns.

        Returns list of suspicious patterns for deeper analysis.
        """
        suspicious = []

        for contract in self.state.contracts:
            # Pattern 1: .call{value: before state assignment
            call_pattern = r"\.call\s*\{[^}]*value"
            state_pattern = r"\[\s*msg\.sender\s*\]\s*[-+]?="

            for func in contract.functions:
                func_source = get_function_source(contract, func.name)
                if not func_source:
                    continue

                call_matches = list(re.finditer(call_pattern, func_source))
                state_matches = list(re.finditer(state_pattern, func_source))

                if call_matches and state_matches:
                    # Check if call comes before state update
                    first_call = call_matches[0].start()
                    last_state = state_matches[-1].start()

                    if first_call < last_state:
                        suspicious.append({
                            "contract": contract.name,
                            "function": func.name,
                            "pattern": "call_before_state_update",
                            "priority": "high",
                        })

                # Pattern 2: External call without nonReentrant
                if func.external_calls:
                    has_guard = any(
                        "reentran" in m.lower()
                        for m in func.modifiers
                    )
                    if not has_guard and any(c.value_sent for c in func.external_calls):
                        suspicious.append({
                            "contract": contract.name,
                            "function": func.name,
                            "pattern": "unguarded_external_call_with_value",
                            "priority": "high",
                        })

        return suspicious

    async def run(self, **kwargs) -> list[Finding]:
        """
        Hunt for reentrancy vulnerabilities.

        Returns:
            List of findings
        """
        self.log("Starting reentrancy hunt...", style="bold yellow")

        # Step 1: Quick scan for suspicious patterns
        self.log("Running quick pattern scan...")
        suspicious = self._quick_scan()

        if suspicious:
            self.log(f"Found {len(suspicious)} suspicious patterns for analysis")
        else:
            self.log("No obvious reentrancy patterns found")

        # Step 2: Deep analysis with LLM
        self.log("Running deep analysis with LLM...")

        # Prepare context
        contract_summaries = []
        for contract in self.state.contracts:
            contract_summaries.append(summarize_contract(contract))

        suspicious_text = ""
        if suspicious:
            suspicious_text = "\n## Suspicious Patterns Detected\n"
            for s in suspicious:
                suspicious_text += f"- {s['contract']}.{s['function']}(): {s['pattern']}\n"

        prompt = f"""Analyze the following smart contracts for reentrancy vulnerabilities.

## Contracts
{chr(10).join(contract_summaries)}

{suspicious_text}

## Instructions

1. For each contract, analyze functions that make external calls
2. Check if state updates happen BEFORE external calls (CEI pattern)
3. Look for cross-function reentrancy opportunities
4. Check for reentrancy guards
5. Consider callback vectors (ERC777, flash loans, etc.)

Use the available tools to get function source code and analyze deeply.
Report any findings using the report_finding tool.

Be thorough but avoid false positives. Only report issues you are confident about."""

        response = self.run_with_tools(prompt, max_iterations=15)

        # Return findings
        reentrancy_findings = [
            f for f in self.state.findings
            if f.vulnerability_type == VulnerabilityType.REENTRANCY
        ]

        self.log(
            f"Reentrancy hunt complete. Found {len(reentrancy_findings)} issues.",
            style="bold green"
        )

        return reentrancy_findings
