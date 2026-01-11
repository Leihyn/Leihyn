"""
Access Control Hunter Agent - Multi-language privilege escalation detection.

Detects:
- Missing access control on privileged functions
- Broken authorization patterns
- Privilege escalation vulnerabilities
- Role management issues
- Owner/Admin manipulation

Supports: Solidity, Rust/Solana, Move, Cairo
"""

from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AuditState, Finding, Severity
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite smart contract security researcher specializing in
access control vulnerabilities. You have won multiple competitive audits on Sherlock,
Code4rena, and Cantina by finding critical authorization bugs.

Your expertise spans multiple languages:
- **Solidity/EVM**: onlyOwner, OpenZeppelin AccessControl, role-based patterns
- **Rust/Solana**: Signer checks, owner validation, PDA authority
- **Move (Aptos/Sui)**: Capability patterns, signer authorization, object ownership
- **Cairo/StarkNet**: get_caller_address, access control modifiers, L1 handlers

## Access Control Vulnerability Categories

### 1. Missing Access Control
- Privileged functions callable by anyone
- Missing modifiers/checks on sensitive operations
- Unprotected initialization

### 2. Broken Access Control
- Incorrect check logic (OR instead of AND)
- Bypassable through delegatecall/CPI
- Race conditions in role changes

### 3. Privilege Escalation
- Users can grant themselves elevated permissions
- Role hierarchy violations
- Circular role dependencies

### 4. Centralization Risks
- Single admin key controls everything
- No timelock on critical operations
- Unrevokable permissions

## Language-Specific Patterns

### Solidity
- Check for onlyOwner, onlyRole, require(msg.sender == ...)
- Look for missing modifiers on external/public functions
- AccessControl role management issues

### Rust/Solana
- Missing Signer constraint in Anchor
- owner.key != expected without constraint
- PDA authority validation

### Move
- Missing signer parameter on entry functions
- Capability not required for privileged operations
- Object ownership bypass

### Cairo
- Missing get_caller_address() check
- L1 handler without source validation
- Unprotected external functions

When you find an issue, assess:
1. What privileged operation is exposed?
2. Who can exploit this (anyone, specific roles, etc.)?
3. What's the maximum damage?
4. Is there any mitigating factor?

Rate severity:
- CRITICAL: Direct fund theft, protocol takeover
- HIGH: Significant damage but limited scope
- MEDIUM: Privilege escalation with preconditions
- LOW: Minor permission issues
"""


class AccessControlHunter(AnalysisAgent):
    """
    Hunts for access control and authorization vulnerabilities.
    """

    name = "access_control_hunter"
    description = "Specialized agent for finding access control vulnerabilities"

    def __init__(self, state: AuditState, **kwargs):
        super().__init__(state=state, **kwargs)
        self.language = kwargs.get("language", Language.SOLIDITY)
        self.tools = self._build_tools()

    def _build_tools(self) -> list[Tool]:
        """Build tools available to this hunter."""
        return [
            Tool(
                name="read_file",
                description="Read a source code file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to read",
                        }
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="search_pattern",
                description="Search for code patterns in the codebase",
                input_schema={
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to search for",
                        }
                    },
                    "required": ["pattern"],
                },
                handler=self._search_pattern,
            ),
            Tool(
                name="find_privileged_functions",
                description="Find functions that perform privileged operations",
                input_schema={
                    "type": "object",
                    "properties": {},
                },
                handler=self._find_privileged_functions,
            ),
            Tool(
                name="analyze_access_control",
                description="Analyze access control patterns in a specific contract/module",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        }
                    },
                    "required": ["file_path"],
                },
                handler=self._analyze_access_control,
            ),
            Tool(
                name="check_role_management",
                description="Check for role management vulnerabilities",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        }
                    },
                    "required": ["file_path"],
                },
                handler=self._check_role_management,
            ),
            Tool(
                name="report_finding",
                description="Report an access control vulnerability",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low"],
                        },
                        "description": {"type": "string"},
                        "location": {"type": "string"},
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                    },
                    "required": ["title", "severity", "description", "location"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run access control analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        # Build initial prompt based on language
        language_context = self._get_language_context()

        # Get contract info from state
        contracts_info = self._format_contracts_info()

        initial_prompt = f"""Analyze this {self.language.value} codebase for access control vulnerabilities.

## Language Context
{language_context}

## Codebase Overview
Target: {self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture Notes
{self._format_architecture_notes()}

Your task:
1. Use find_privileged_functions to identify sensitive operations
2. For each privileged function, use analyze_access_control to check protections
3. Look for missing modifiers, broken checks, and privilege escalation
4. Use check_role_management to find role-related issues
5. Report all findings with report_finding

Focus on functions that:
- Modify state (storage writes, transfers)
- Change ownership or roles
- Pause/unpause functionality
- Update critical parameters
- Perform withdrawals or minting
"""

        # Run the agent loop
        response, tool_calls = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(f"  Access Control Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _get_language_context(self) -> str:
        """Get language-specific context for the hunter."""
        contexts = {
            Language.SOLIDITY: """
## Solidity Access Control Patterns

### Standard Modifiers
```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

// OpenZeppelin AccessControl
modifier onlyRole(bytes32 role) {
    require(hasRole(role, msg.sender), "Missing role");
    _;
}
```

### Common Vulnerabilities
1. Missing modifier on external/public functions
2. Using tx.origin instead of msg.sender
3. Incorrect role check logic
4. Unprotected initialize()
5. Single-step ownership transfer
""",
            Language.RUST: """
## Rust/Solana Access Control Patterns

### Anchor Constraints
```rust
#[account(
    constraint = authority.key() == pool.authority @ ErrorCode::Unauthorized
)]
pub authority: Signer<'info>,

// PDA authority
#[account(
    seeds = [b"authority"],
    bump,
)]
pub pda_authority: AccountInfo<'info>,
```

### Common Vulnerabilities
1. Missing Signer<'info> for privileged accounts
2. Missing owner/authority validation
3. CPI privilege escalation
4. PDA authority bypass
5. Account substitution attacks
""",
            Language.MOVE: """
## Move Access Control Patterns

### Capability Pattern
```move
struct AdminCapability has key, store {}

public entry fun admin_action(
    admin_cap: &AdminCapability,
    // ...
) {
    // Only holders of AdminCapability can call
}
```

### Signer Authorization
```move
public entry fun transfer(
    sender: &signer,  // Must be signer
    recipient: address,
    amount: u64
) {
    let sender_addr = signer::address_of(sender);
    // ...
}
```

### Common Vulnerabilities
1. Missing signer parameter
2. Capability not required
3. Object ownership not verified (Sui)
4. Acquires not checked
""",
            Language.CAIRO: """
## Cairo/StarkNet Access Control Patterns

### Caller Verification
```cairo
fn only_owner(self: @ContractState) {
    let caller = get_caller_address();
    let owner = self.owner.read();
    assert(caller == owner, 'Caller is not owner');
}

#[external(v0)]
fn admin_action(ref self: ContractState) {
    self.only_owner();
    // ...
}
```

### L1 Handler Security
```cairo
#[l1_handler]
fn handle_l1_message(
    ref self: ContractState,
    from_address: felt252,  // L1 contract address
    // Must validate from_address
) {
    assert(from_address == EXPECTED_L1_CONTRACT, 'Invalid L1 source');
}
```

### Common Vulnerabilities
1. Missing get_caller_address() check
2. L1 handler without source validation
3. Unprotected initializer
4. External function without access check
""",
        }
        return contexts.get(self.language, contexts[Language.SOLIDITY])

    def _format_contracts_info(self) -> str:
        """Format contract information for the prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet. Use find_privileged_functions first."

        lines = []
        for contract in self.state.contracts[:10]:  # Limit to 10
            lines.append(f"- {contract.name} ({contract.path})")
            if contract.functions:
                for func in contract.functions[:5]:
                    lines.append(f"  - {func}")
        return "\n".join(lines)

    def _format_architecture_notes(self) -> str:
        """Format architecture notes."""
        if not self.state.architecture:
            return "No architecture analysis available."

        notes = []
        if self.state.architecture.is_upgradeable:
            notes.append("- Upgradeable proxy pattern detected")
        if self.state.architecture.has_access_control:
            notes.append("- Access control system present")
        if self.state.architecture.notes:
            notes.extend([f"- {note}" for note in self.state.architecture.notes[:5]])

        return "\n".join(notes) if notes else "No specific notes."

    # Tool handlers

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            return file_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

    async def _search_pattern(self, pattern: str) -> str:
        """Search for patterns in the codebase."""
        import re

        results = []
        extensions = self._get_file_extensions()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    matches = list(re.finditer(pattern, content, re.MULTILINE))
                    if matches:
                        for match in matches[:3]:  # Limit matches per file
                            line_num = content[:match.start()].count('\n') + 1
                            results.append(f"{file_path}:{line_num}: {match.group()[:100]}")
                except Exception:
                    continue

        return "\n".join(results[:20]) if results else "No matches found"

    async def _find_privileged_functions(self) -> str:
        """Find functions that perform privileged operations."""
        results = []
        extensions = self._get_file_extensions()

        privileged_patterns = self._get_privileged_patterns()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    for pattern_name, pattern in privileged_patterns.items():
                        import re
                        matches = list(re.finditer(pattern, content, re.MULTILINE))
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            results.append({
                                "file": str(file_path.relative_to(self.state.target_path)),
                                "line": line_num,
                                "type": pattern_name,
                                "match": match.group()[:80],
                            })
                except Exception:
                    continue

        if not results:
            return "No privileged functions found"

        output = "Found privileged functions:\n\n"
        for r in results[:30]:
            output += f"[{r['type']}] {r['file']}:{r['line']}\n  {r['match']}\n\n"

        return output

    async def _analyze_access_control(self, file_path: str) -> str:
        """Analyze access control in a specific file."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path

            content = full_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

        analysis = []

        if self.language == Language.SOLIDITY:
            analysis = self._analyze_solidity_access(content, file_path)
        elif self.language == Language.RUST:
            analysis = self._analyze_rust_access(content, file_path)
        elif self.language == Language.MOVE:
            analysis = self._analyze_move_access(content, file_path)
        elif self.language == Language.CAIRO:
            analysis = self._analyze_cairo_access(content, file_path)

        if not analysis:
            return "No access control issues detected in this file."

        output = f"Access Control Analysis for {file_path}:\n\n"
        for item in analysis:
            output += f"- [{item['severity']}] {item['issue']}\n"
            output += f"  Location: Line {item['line']}\n"
            output += f"  Details: {item['details']}\n\n"

        return output

    def _analyze_solidity_access(self, content: str, file_path: str) -> list[dict]:
        """Analyze Solidity access control patterns."""
        import re
        issues = []

        # Find external/public functions
        func_pattern = r"function\s+(\w+)\s*\([^)]*\)\s*(external|public)[^{]*\{"
        modifiers_to_check = ["onlyOwner", "onlyRole", "onlyAdmin", "auth", "authorized"]

        for match in re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL):
            func_name = match.group(1)
            func_start = match.start()
            line_num = content[:func_start].count('\n') + 1

            # Get the full function signature line
            func_line = content[func_start:content.find('{', func_start)]

            # Check if any modifier is present
            has_modifier = any(mod in func_line for mod in modifiers_to_check)
            has_require_sender = "msg.sender" in content[func_start:func_start + 500]

            # Check for privileged operations in function body
            func_end = self._find_matching_brace(content, content.find('{', func_start))
            func_body = content[func_start:func_end] if func_end > 0 else ""

            is_privileged = any(op in func_body.lower() for op in [
                "transfer", "mint", "burn", "pause", "unpause",
                "setowner", "setadmin", "upgrade", "selfdestruct",
                "withdrawfees", "setfee", "setoracl"
            ])

            if is_privileged and not has_modifier and not has_require_sender:
                issues.append({
                    "severity": "HIGH",
                    "issue": f"Function `{func_name}` performs privileged operation without access control",
                    "line": line_num,
                    "details": f"External function may be callable by anyone",
                })

        # Check for tx.origin usage
        if "tx.origin" in content:
            for match in re.finditer(r"tx\.origin", content):
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Usage of tx.origin for authorization",
                    "line": line_num,
                    "details": "tx.origin can be manipulated via phishing attacks",
                })

        # Check for single-step ownership transfer
        if "transferOwnership" in content and "_transferOwnership" in content:
            if "pendingOwner" not in content and "acceptOwnership" not in content:
                issues.append({
                    "severity": "LOW",
                    "issue": "Single-step ownership transfer",
                    "line": 0,
                    "details": "Consider two-step ownership transfer to prevent accidental loss",
                })

        return issues

    def _analyze_rust_access(self, content: str, file_path: str) -> list[dict]:
        """Analyze Rust/Solana access control patterns."""
        import re
        issues = []

        # Find instruction handlers
        handler_pattern = r"pub\s+fn\s+(\w+)\s*\([^)]*ctx:\s*Context<['\w]+>"

        for match in re.finditer(handler_pattern, content):
            func_name = match.group(1)
            func_start = match.start()
            line_num = content[:func_start].count('\n') + 1

            # Look for the Context struct
            context_match = re.search(r"Context<(\w+)>", match.group())
            if context_match:
                context_name = context_match.group(1)

                # Find the accounts struct
                accounts_pattern = rf"pub\s+struct\s+{context_name}\s*<[^>]+>\s*\{{\s*([^}}]+)\}}"
                accounts_match = re.search(accounts_pattern, content, re.DOTALL)

                if accounts_match:
                    accounts_body = accounts_match.group(1)

                    # Check if there's a Signer type for authority
                    if "authority" in accounts_body.lower() or "admin" in accounts_body.lower():
                        if "Signer<" not in accounts_body:
                            issues.append({
                                "severity": "CRITICAL",
                                "issue": f"Function `{func_name}` may be missing signer validation",
                                "line": line_num,
                                "details": "Authority account should be Signer<'info> type",
                            })

        # Check for manual is_signer checks
        if "is_signer" in content:
            for match in re.finditer(r"if\s+!\s*\w+\.is_signer", content):
                # This is actually good - they're checking
                pass

        # Look for CPI without proper validation
        if "invoke_signed" in content or "invoke(" in content:
            issues.append({
                "severity": "MEDIUM",
                "issue": "CPI detected - verify authority validation",
                "line": 0,
                "details": "Cross-program invocations should validate all signers",
            })

        return issues

    def _analyze_move_access(self, content: str, file_path: str) -> list[dict]:
        """Analyze Move access control patterns."""
        import re
        issues = []

        # Find public entry functions
        entry_pattern = r"public\s+entry\s+fun\s+(\w+)\s*(<[^>]*>)?\s*\(([^)]*)\)"

        for match in re.finditer(entry_pattern, content):
            func_name = match.group(1)
            params = match.group(3)
            func_start = match.start()
            line_num = content[:func_start].count('\n') + 1

            # Check if signer is in parameters
            has_signer = "&signer" in params or ": signer" in params or ": &signer" in params

            # Check for privileged operations
            func_end = self._find_function_end_move(content, func_start)
            func_body = content[func_start:func_end] if func_end > 0 else ""

            is_privileged = any(op in func_body.lower() for op in [
                "move_to", "move_from", "borrow_global_mut",
                "transfer", "mint", "burn", "withdraw"
            ])

            if is_privileged and not has_signer:
                issues.append({
                    "severity": "HIGH",
                    "issue": f"Entry function `{func_name}` may be missing signer authorization",
                    "line": line_num,
                    "details": "Privileged operation without signer parameter",
                })

        # Check for capability pattern usage
        if "Capability" in content or "Cap" in content:
            # Good - they're using capability pattern
            cap_required = "AdminCap" in content or "OwnerCap" in content
            if cap_required:
                # Check if capabilities are properly checked in entry functions
                pass

        return issues

    def _analyze_cairo_access(self, content: str, file_path: str) -> list[dict]:
        """Analyze Cairo/StarkNet access control patterns."""
        import re
        issues = []

        # Find external functions
        external_pattern = r"#\[external[^\]]*\]\s*fn\s+(\w+)"

        for match in re.finditer(external_pattern, content):
            func_name = match.group(1)
            func_start = match.start()
            line_num = content[:func_start].count('\n') + 1

            # Find the function body
            func_end = content.find("fn ", func_start + 10)
            if func_end == -1:
                func_end = len(content)

            func_body = content[func_start:func_end]

            # Check for access control
            has_access_check = (
                "get_caller_address" in func_body or
                "assert_only_owner" in func_body or
                "only_owner" in func_body or
                "assert!" in func_body and "caller" in func_body
            )

            # Check for privileged operations
            is_privileged = any(op in func_body.lower() for op in [
                "write(", "transfer", "mint", "burn",
                "upgrade", "set_owner", "pause"
            ])

            if is_privileged and not has_access_check:
                issues.append({
                    "severity": "HIGH",
                    "issue": f"External function `{func_name}` may lack access control",
                    "line": line_num,
                    "details": "Privileged operation without caller verification",
                })

        # Check L1 handlers
        l1_handler_pattern = r"#\[l1_handler\]\s*fn\s+(\w+)"
        for match in re.finditer(l1_handler_pattern, content):
            func_name = match.group(1)
            func_start = match.start()
            line_num = content[:func_start].count('\n') + 1

            # Find function body
            func_end = content.find("fn ", func_start + 10)
            if func_end == -1:
                func_end = len(content)
            func_body = content[func_start:func_end]

            # Check for L1 address validation
            if "from_address" in func_body:
                if "assert" not in func_body or "from_address" not in func_body.split("assert")[1][:100]:
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"L1 handler `{func_name}` may not validate source",
                        "line": line_num,
                        "details": "L1 handlers should validate from_address",
                    })

        return issues

    async def _check_role_management(self, file_path: str) -> str:
        """Check for role management vulnerabilities."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

        issues = []

        if self.language == Language.SOLIDITY:
            import re

            # Check for self-role assignment
            if "grantRole" in content:
                grant_pattern = r"grantRole\s*\([^,]+,\s*msg\.sender\s*\)"
                if re.search(grant_pattern, content):
                    issues.append("MEDIUM: Contract can grant roles to msg.sender directly")

            # Check for missing role revocation
            if "grantRole" in content and "revokeRole" not in content:
                issues.append("LOW: Role granting without revocation capability")

            # Check for admin role that can change other admins
            if "DEFAULT_ADMIN_ROLE" in content:
                issues.append("INFO: Uses DEFAULT_ADMIN_ROLE - verify admin role management")

            # Check for renounceOwnership
            if "renounceOwnership" in content:
                issues.append("INFO: renounceOwnership is available - could lock contract")

        elif self.language == Language.RUST:
            if "admin" in content.lower() and "set_admin" in content.lower():
                issues.append("MEDIUM: Admin change functionality - verify access control")

        elif self.language == Language.MOVE:
            if "Capability" in content:
                if "drop" in content and "store" in content:
                    issues.append("MEDIUM: Capability can be dropped and stored - verify lifecycle")

        elif self.language == Language.CAIRO:
            if "owner" in content.lower() and "set_owner" in content.lower():
                issues.append("MEDIUM: Owner change functionality - verify access control")

        if not issues:
            return "No role management issues detected."

        return "Role Management Analysis:\n" + "\n".join(f"- {issue}" for issue in issues)

    async def _report_finding(
        self,
        title: str,
        severity: str,
        description: str,
        location: str,
        impact: str = "",
        recommendation: str = "",
    ) -> str:
        """Report an access control finding."""
        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        finding = Finding(
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            description=description,
            location=location,
            impact=impact,
            recommendation=recommendation,
            category="access_control",
            confidence="high",
        )

        self.findings.append(finding)
        self.state.findings.append(finding)

        return f"Finding reported: [{severity}] {title}"

    # Utility methods

    def _get_file_extensions(self) -> list[str]:
        """Get file extensions for current language."""
        extensions = {
            Language.SOLIDITY: [".sol"],
            Language.RUST: [".rs"],
            Language.MOVE: [".move"],
            Language.CAIRO: [".cairo"],
        }
        return extensions.get(self.language, [".sol"])

    def _get_privileged_patterns(self) -> dict[str, str]:
        """Get patterns for privileged operations by language."""
        if self.language == Language.SOLIDITY:
            return {
                "ownership_transfer": r"transferOwnership\s*\(",
                "role_grant": r"grantRole\s*\(",
                "mint": r"function\s+mint\s*\(",
                "burn": r"function\s+burn\s*\(",
                "pause": r"function\s+pause\s*\(",
                "withdraw": r"function\s+withdraw\s*\(",
                "upgrade": r"function\s+upgrade\s*\(",
                "set_admin": r"function\s+set\w*[Aa]dmin\s*\(",
            }
        elif self.language == Language.RUST:
            return {
                "authority_set": r"pub\s+fn\s+set_authority",
                "owner_set": r"pub\s+fn\s+set_owner",
                "mint": r"pub\s+fn\s+mint",
                "burn": r"pub\s+fn\s+burn",
                "withdraw": r"pub\s+fn\s+withdraw",
                "close": r"pub\s+fn\s+close",
            }
        elif self.language == Language.MOVE:
            return {
                "capability_grant": r"move_to.*Capability",
                "admin_set": r"public\s+entry\s+fun\s+set_admin",
                "mint": r"public\s+entry\s+fun\s+mint",
                "burn": r"public\s+entry\s+fun\s+burn",
                "withdraw": r"public\s+entry\s+fun\s+withdraw",
            }
        elif self.language == Language.CAIRO:
            return {
                "owner_set": r"fn\s+set_owner",
                "admin_set": r"fn\s+set_admin",
                "mint": r"fn\s+mint",
                "burn": r"fn\s+burn",
                "upgrade": r"fn\s+upgrade",
                "pause": r"fn\s+pause",
            }
        return {}

    def _find_matching_brace(self, content: str, start: int) -> int:
        """Find the matching closing brace."""
        if start < 0 or start >= len(content) or content[start] != '{':
            return -1

        count = 1
        i = start + 1
        while i < len(content) and count > 0:
            if content[i] == '{':
                count += 1
            elif content[i] == '}':
                count -= 1
            i += 1

        return i if count == 0 else -1

    def _find_function_end_move(self, content: str, start: int) -> int:
        """Find the end of a Move function."""
        brace_start = content.find('{', start)
        if brace_start == -1:
            return len(content)
        return self._find_matching_brace(content, brace_start)
