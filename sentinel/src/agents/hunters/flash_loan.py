"""
Flash Loan Attack Hunter Agent - Cross-protocol attack vector detection.

Detects:
- Flash loan vulnerability patterns
- Price manipulation via flash loans
- Collateral manipulation
- Governance attacks
- LP token inflation attacks

Supports: Solidity (EVM), Rust (Solana - flash swaps), Move, Cairo
"""

from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AuditState, Finding, Severity
from ...core.languages import Language


SYSTEM_PROMPT = """You are an expert DeFi security researcher specializing in flash loan attacks
and cross-protocol exploit vectors. You have extensive experience analyzing real-world exploits
like bZx, Harvest Finance, Cream, and others.

## Flash Loan Attack Classes

### 1. Price Manipulation Attacks
Flash loan -> manipulate AMM spot price -> exploit price-dependent logic -> repay loan

### 2. Collateral Manipulation
Flash loan -> inflate collateral value -> borrow excess funds -> repay loan

### 3. Governance Attacks
Flash loan -> acquire voting power -> pass malicious proposal -> profit

### 4. LP Token Inflation
Flash loan -> donate to pool -> inflate share price -> profit from discrepancy

### 5. Reentrancy + Flash Loan
Combine flash loan with reentrancy for amplified damage

## Key Detection Patterns

### Price Dependencies
- Using spot prices from AMMs
- Balance ratios for valuations
- Reserve-based calculations

### State Changes
- Deposits, withdrawals, swaps in same tx
- Minting LP tokens based on spot price
- Collateral evaluations without TWAP

### Missing Protections
- No flash loan guards (same-tx check)
- No TWAP for pricing
- No minimum deposit periods
- No withdrawal cooldowns

## Blockchain Specifics

### EVM (Solidity)
- Aave V2/V3 flash loans
- dYdX flash loans (via callback)
- Uniswap V2/V3 flash swaps
- Balancer flash loans
- Single-block execution

### Solana
- Flash "swaps" via CPI loops
- Same-tx reentrancy via CPI
- SPL lending protocols
- Transaction bundling

### Move (Aptos/Sui)
- Flash loans in Move are harder (no callbacks like EVM)
- Package-to-package calls
- Object borrowing patterns

### Cairo/StarkNet
- L2 flash loans (emerging)
- Cross-contract calls
- Transaction atomicity

When analyzing, consider:
1. Can an attacker acquire large amounts of tokens temporarily?
2. Are there price-dependent operations vulnerable to manipulation?
3. Is there any same-block or same-tx protection?
4. What's the maximum exploitable value?
"""


class FlashLoanHunter(AnalysisAgent):
    """
    Hunts for flash loan attack vulnerabilities.
    """

    name = "flash_loan_hunter"
    description = "Specialized agent for finding flash loan attack vectors"

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
                        "path": {"type": "string", "description": "File path to read"}
                    },
                    "required": ["path"],
                },
                handler=self._read_file,
            ),
            Tool(
                name="find_flash_loan_vectors",
                description="Find potential flash loan attack vectors",
                input_schema={"type": "object", "properties": {}},
                handler=self._find_flash_vectors,
            ),
            Tool(
                name="analyze_price_dependencies",
                description="Analyze price-dependent operations that could be manipulated",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"}
                    },
                    "required": ["file_path"],
                },
                handler=self._analyze_price_deps,
            ),
            Tool(
                name="check_flash_loan_guards",
                description="Check for flash loan protection mechanisms",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"}
                    },
                    "required": ["file_path"],
                },
                handler=self._check_guards,
            ),
            Tool(
                name="analyze_deposit_withdraw",
                description="Analyze deposit/withdraw patterns for manipulation",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"}
                    },
                    "required": ["file_path"],
                },
                handler=self._analyze_deposit_withdraw,
            ),
            Tool(
                name="trace_value_flow",
                description="Trace how value flows through a function to find manipulation points",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "function_name": {"type": "string"}
                    },
                    "required": ["file_path", "function_name"],
                },
                handler=self._trace_value_flow,
            ),
            Tool(
                name="report_finding",
                description="Report a flash loan vulnerability",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                        "description": {"type": "string"},
                        "location": {"type": "string"},
                        "attack_flow": {"type": "string"},
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                    },
                    "required": ["title", "severity", "description", "location", "attack_flow"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run flash loan vulnerability analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        contracts_info = self._format_contracts_info()
        flash_context = self._get_flash_loan_context()

        initial_prompt = f"""Analyze this {self.language.value} DeFi codebase for flash loan attack vulnerabilities.

## Flash Loan Context
{flash_context}

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture Notes
{self._format_architecture()}

Your analysis should:
1. Use find_flash_loan_vectors to identify potential attack surfaces
2. For each vector, use analyze_price_dependencies to check for manipulation
3. Use check_flash_loan_guards to verify protections exist
4. Analyze deposit/withdraw patterns for inflation attacks
5. Trace value flows in critical functions
6. Report all findings with detailed attack flows

Focus on:
- Functions that read prices/balances and make decisions
- Deposit/mint functions using spot calculations
- Withdrawal functions with share-based accounting
- Collateral evaluation without TWAP
- Single-tx operation patterns
- Missing cooldown or delay mechanisms
"""

        response, tool_calls = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(f"  Flash Loan Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _get_flash_loan_context(self) -> str:
        """Get language-specific flash loan context."""
        contexts = {
            Language.SOLIDITY: """
## EVM Flash Loan Patterns

### Aave Flash Loan
```solidity
interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}
```

### Uniswap V2 Flash Swap
```solidity
function uniswapV2Call(
    address sender,
    uint amount0,
    uint amount1,
    bytes calldata data
) external {
    // Receive tokens, do stuff, repay
}
```

### Common Vulnerable Patterns
```solidity
// VULNERABLE: Uses spot price
function deposit(uint amount) external {
    uint shares = amount * totalShares / totalAssets();  // Manipulable!
    _mint(msg.sender, shares);
}

// VULNERABLE: No same-block protection
function borrow(uint amount) external {
    uint collateralValue = getSpotPrice() * collateralBalance;  // Flash-manipulable
    require(amount <= collateralValue * LTV);
    _transfer(msg.sender, amount);
}
```

### Flash Loan Protection
```solidity
// Protection: Track deposits per block
mapping(address => uint) public lastDepositBlock;

modifier noFlashLoan() {
    require(lastDepositBlock[msg.sender] < block.number, "Flash loan guard");
    _;
}

function withdraw(uint shares) external noFlashLoan {
    // Safe from same-block manipulation
}
```
""",
            Language.RUST: """
## Solana Flash Loan Patterns

### Flash Loan Simulation via CPI
On Solana, flash loans work differently - typically through CPI loops or bundled transactions.

```rust
// Attacker can bundle transactions to achieve flash-loan-like effects
// tx1: Borrow from lending protocol
// tx2: Manipulate pool
// tx3: Exploit vulnerable protocol
// tx4: Repay lending protocol

// VULNERABLE: Uses spot pool ratio
pub fn calculate_value(pool: &Pool) -> u64 {
    // Manipulable via concentrated liquidity/swaps
    pool.token_a_amount * price / pool.token_b_amount
}
```

### Protection Patterns
```rust
// Track actions per slot
pub last_action_slot: u64,

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let clock = Clock::get()?;
    require!(
        ctx.accounts.user_state.last_action_slot < clock.slot,
        ErrorCode::SameSlotOperation
    );
    // ... withdraw logic
}
```
""",
            Language.MOVE: """
## Move Flash Loan Considerations

Move's resource model makes traditional flash loans harder, but similar effects
are possible through package-to-package calls.

### Potential Vulnerable Patterns
```move
// Uses spot pool reserves for valuation
public fun get_value(pool: &Pool): u64 {
    pool.reserve_a * pool.reserve_b  // Can be manipulated
}

// No check for same-transaction manipulation
public entry fun deposit_and_borrow(...) {
    deposit(amount);  // Increases collateral
    let borrow_limit = get_collateral_value();  // Uses spot
    borrow(borrow_limit);  // Borrow max
}
```

### Protection: Epoch-based restrictions
```move
// Require waiting period
assert!(current_epoch > user.deposit_epoch, E_SAME_EPOCH);
```
""",
            Language.CAIRO: """
## Cairo/StarkNet Flash Considerations

StarkNet's L2 architecture has different atomicity guarantees.

### Potential Patterns
```cairo
// Vulnerable to manipulation within same block
fn get_collateral_value(self: @ContractState) -> u256 {
    let balance = self.collateral_balance.read();
    let price = get_spot_price();  // Manipulable
    balance * price
}
```

### Protection
```cairo
// Block-based cooldown
fn withdraw(ref self: ContractState, amount: u256) {
    let current_block = get_block_number();
    let deposit_block = self.deposit_block.read(get_caller_address());
    assert(current_block > deposit_block, 'Same block');
    // ... withdraw
}
```
""",
        }
        return contexts.get(self.language, contexts[Language.SOLIDITY])

    def _format_contracts_info(self) -> str:
        """Format contract info."""
        if not self.state.contracts:
            return "No contracts analyzed."
        lines = [f"- {c.name}" for c in self.state.contracts[:10]]
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture notes."""
        if not self.state.architecture:
            return "No architecture analysis."
        notes = []
        if self.state.architecture.is_defi:
            notes.append("- DeFi protocol")
        if self.state.architecture.external_protocols:
            notes.append(f"- Integrates: {', '.join(self.state.architecture.external_protocols)}")
        return "\n".join(notes) if notes else "Standard"

    # Tool handlers

    async def _read_file(self, path: str) -> str:
        """Read source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            return file_path.read_text()
        except Exception as e:
            return f"Error: {e}"

    async def _find_flash_vectors(self) -> str:
        """Find potential flash loan attack vectors."""
        import re

        vectors = []
        extensions = self._get_file_extensions()
        patterns = self._get_vulnerability_patterns()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()

                    for pattern_name, pattern in patterns.items():
                        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
                        for match in matches[:3]:
                            line_num = content[:match.start()].count('\n') + 1
                            vectors.append({
                                "file": str(file_path.relative_to(self.state.target_path)),
                                "line": line_num,
                                "type": pattern_name,
                                "snippet": match.group()[:100],
                            })
                except Exception:
                    continue

        if not vectors:
            return "No obvious flash loan vectors found."

        output = "Potential Flash Loan Vectors:\n\n"
        for v in vectors[:25]:
            output += f"[{v['type']}] {v['file']}:{v['line']}\n"
            output += f"  {v['snippet']}\n\n"

        return output

    async def _analyze_price_deps(self, file_path: str) -> str:
        """Analyze price-dependent operations."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        import re
        deps = []

        if self.language == Language.SOLIDITY:
            # Balance-based calculations
            if re.search(r"balanceOf.*[*/]|[*/].*balanceOf", content):
                deps.append("CRITICAL: Balance used in price calculation - flash manipulable")

            # Reserve-based calculations
            if re.search(r"getReserves.*[*/]", content):
                deps.append("CRITICAL: AMM reserves used for pricing - flash manipulable")

            # Share calculations
            share_pattern = r"(\w+)\s*[*/]\s*total(Supply|Shares|Assets)"
            if re.search(share_pattern, content, re.IGNORECASE):
                deps.append("HIGH: Share/supply ratio calculation - check for first depositor attack")

            # Spot oracle usage
            if "latestAnswer" in content and "TWAP" not in content.upper():
                deps.append("MEDIUM: Using spot oracle without TWAP backup")

        elif self.language == Language.RUST:
            # Pool reserve ratio
            if re.search(r"reserve|pool.*amount", content, re.IGNORECASE):
                deps.append("HIGH: Pool reserves in calculation - potentially manipulable")

            # Token balance ratios
            if "get_account_amount" in content or "amount" in content and "/" in content:
                deps.append("MEDIUM: Token amount calculations - verify manipulation resistance")

        if not deps:
            return "No obvious price dependencies found."

        return "Price Dependency Analysis:\n" + "\n".join(f"- {d}" for d in deps)

    async def _check_guards(self, file_path: str) -> str:
        """Check for flash loan protection mechanisms."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        guards = []

        if self.language == Language.SOLIDITY:
            # Block number checks
            if "block.number" in content:
                if "lastActionBlock" in content or "depositBlock" in content:
                    guards.append("FOUND: Block-based flash loan guard")

            # Reentrancy guard (partial protection)
            if "nonReentrant" in content or "ReentrancyGuard" in content:
                guards.append("FOUND: Reentrancy guard (partial flash protection)")

            # TWAP usage
            if "TWAP" in content.upper() or "observe" in content:
                guards.append("FOUND: TWAP oracle (flash resistant)")

            # Cooldown mechanisms
            if "cooldown" in content.lower() or "delay" in content.lower():
                guards.append("FOUND: Cooldown/delay mechanism")

            # Minimum hold time
            if "lockTime" in content or "holdPeriod" in content:
                guards.append("FOUND: Lock/hold period requirement")

        elif self.language == Language.RUST:
            # Slot-based checks
            if "slot" in content.lower():
                if "last_action_slot" in content or "deposit_slot" in content:
                    guards.append("FOUND: Slot-based guard")

            # Epoch checks
            if "epoch" in content.lower():
                guards.append("FOUND: Epoch-based restriction")

        if not guards:
            return "WARNING: No flash loan guards detected!"

        return "Flash Loan Guards:\n" + "\n".join(f"- {g}" for g in guards)

    async def _analyze_deposit_withdraw(self, file_path: str) -> str:
        """Analyze deposit/withdraw patterns for manipulation."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        import re
        issues = []

        if self.language == Language.SOLIDITY:
            # First depositor attack
            if "totalSupply" in content:
                if re.search(r"if\s*\(\s*totalSupply\s*==\s*0", content):
                    issues.append("CHECK: First depositor case - verify no inflation attack")
                elif "totalSupply == 0" not in content and "mint" in content.lower():
                    issues.append("WARNING: May be missing first depositor check")

            # Share calculation without minimum
            if re.search(r"amount\s*\*\s*totalShares\s*/\s*totalAssets", content):
                issues.append("HIGH: Classic share calculation - check for donation attack")

            # Direct balance usage in share calc
            if re.search(r"address\(this\)\.balance|balanceOf\(address\(this\)\)", content):
                if "shares" in content.lower():
                    issues.append("CRITICAL: Contract balance in share calc - donation attack possible")

        elif self.language == Language.RUST:
            # LP token minting
            if "mint" in content.lower() and "pool" in content.lower():
                issues.append("CHECK: LP minting logic - verify first depositor handling")

        if not issues:
            return "No obvious deposit/withdraw vulnerabilities found."

        return "Deposit/Withdraw Analysis:\n" + "\n".join(f"- {i}" for i in issues)

    async def _trace_value_flow(self, file_path: str, function_name: str) -> str:
        """Trace value flow in a function."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        import re

        # Find the function
        if self.language == Language.SOLIDITY:
            func_pattern = rf"function\s+{function_name}\s*\([^)]*\)[^{{]*\{{([^}}]+)\}}"
        elif self.language == Language.RUST:
            func_pattern = rf"pub\s+fn\s+{function_name}\s*[<(][^{{]*\{{([^}}]+)\}}"
        else:
            func_pattern = rf"fn\s+{function_name}[^{{]*\{{([^}}]+)\}}"

        match = re.search(func_pattern, content, re.DOTALL)
        if not match:
            return f"Function {function_name} not found."

        func_body = match.group(1)

        # Analyze value sources
        analysis = [f"Value Flow in {function_name}:\n"]

        # External reads
        if "balanceOf" in func_body or "getReserves" in func_body:
            analysis.append("INPUT: Reads external balances/reserves (manipulable)")

        # Oracle reads
        if "latestRoundData" in func_body or "getPrice" in func_body:
            analysis.append("INPUT: Reads oracle price")

        # State modifications
        if "transfer" in func_body.lower() or "_mint" in func_body:
            analysis.append("OUTPUT: Transfers value or mints tokens")

        # Calculations
        calcs = re.findall(r"=\s*[^;]*[*/][^;]*;", func_body)
        for calc in calcs[:5]:
            analysis.append(f"CALC: {calc[:60]}...")

        return "\n".join(analysis)

    async def _report_finding(
        self,
        title: str,
        severity: str,
        description: str,
        location: str,
        attack_flow: str,
        impact: str = "",
        recommendation: str = "",
    ) -> str:
        """Report a flash loan finding."""
        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        full_description = f"{description}\n\n**Attack Flow:**\n{attack_flow}"

        finding = Finding(
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            description=full_description,
            location=location,
            impact=impact,
            recommendation=recommendation,
            category="flash_loan",
            confidence="high",
        )

        self.findings.append(finding)
        self.state.findings.append(finding)

        return f"Finding reported: [{severity}] {title}"

    def _get_vulnerability_patterns(self) -> dict[str, str]:
        """Get patterns indicating flash loan vulnerability."""
        if self.language == Language.SOLIDITY:
            return {
                "spot_price": r"getReserves\s*\(\s*\).*?[*/]",
                "balance_calc": r"balanceOf\s*\([^)]*\)\s*[*/]",
                "share_calc": r"amount\s*\*\s*total(?:Shares|Supply)\s*/\s*total(?:Assets|Balance)",
                "first_deposit": r"totalSupply\s*==\s*0",
                "flash_callback": r"(?:flashLoan|uniswapV2Call|executeOperation)\s*\(",
                "no_twap": r"latestAnswer|latestRoundData(?!.*[Tt][Ww][Aa][Pp])",
            }
        elif self.language == Language.RUST:
            return {
                "pool_calc": r"reserve_[ab]\s*[*/]",
                "spot_swap": r"get_amount_out|swap_base_in",
                "share_mint": r"mint.*total_supply\s*/",
            }
        elif self.language == Language.MOVE:
            return {
                "reserve_calc": r"pool\.reserve.*[*/]",
                "coin_value": r"coin::value.*[*/]",
            }
        elif self.language == Language.CAIRO:
            return {
                "balance_calc": r"balance.*[*/]",
                "spot_price": r"get_price|get_rate",
            }
        return {}

    def _get_file_extensions(self) -> list[str]:
        """Get file extensions for current language."""
        extensions = {
            Language.SOLIDITY: [".sol"],
            Language.RUST: [".rs"],
            Language.MOVE: [".move"],
            Language.CAIRO: [".cairo"],
        }
        return extensions.get(self.language, [".sol"])
