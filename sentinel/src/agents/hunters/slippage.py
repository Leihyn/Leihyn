"""
Slippage & MEV Hunter Agent - Swap protection and MEV vulnerability detection.

Detects:
- Missing slippage protection (amountOutMin = 0)
- Missing deadline parameters
- Sandwich attack vectors
- Hardcoded slippage values
- Missing minAmounts in liquidity operations
- Balancer limit = 0 swaps
- Unprotected swap operations

Supports: Solidity, Rust/Solana, Move, Cairo
"""

from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite MEV researcher and DeFi security auditor specializing in slippage
protection and sandwich attack vulnerabilities. You have deep experience with Uniswap, Curve,
Balancer, GMX, and every major DEX aggregator.

Your expertise includes:
- Sandwich attacks on unprotected swaps
- Missing deadline exploitation by validators
- Hardcoded slippage abuse in volatile markets
- JIT liquidity extraction from unprotected LPs
- Cross-DEX slippage vectors

## Common Vulnerability Patterns

### 1. amountOutMin = 0 in Uniswap Swaps
Setting minimum output to zero lets a sandwich attacker extract the entire swap value.
A $10,000 swap with amountOutMin = 0 can lose 100% of its value to MEV.

```solidity
// VULNERABLE
router.swapExactTokensForTokens(amountIn, 0, path, to, deadline);

// SECURE
uint256 minOut = oracle.getExpectedOutput(amountIn) * 99 / 100;  // 1% tolerance
router.swapExactTokensForTokens(amountIn, minOut, path, to, deadline);
```

### 2. Missing Deadline Allows Stale Transaction Execution
Without a deadline, validators can hold a transaction and execute it when the price moves
against the user. A swap submitted at price $100 could execute days later at $80.

```solidity
// VULNERABLE
router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, type(uint256).max);

// SECURE
router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, block.timestamp + 300);
```

### 3. limit = 0 in Balancer Swaps
Balancer uses `limit` instead of `amountOutMin`. Setting it to zero is equivalent to
no slippage protection.

```solidity
// VULNERABLE
IVault.SingleSwap memory swap = IVault.SingleSwap({
    poolId: poolId,
    kind: IVault.SwapKind.GIVEN_IN,
    assetIn: tokenIn,
    assetOut: tokenOut,
    amount: amountIn,
    userData: ""
});
vault.swap(swap, funds, 0, deadline);  // limit = 0!
```

### 4. Hardcoded Slippage (e.g., 5%) Instead of Oracle-Based
A hardcoded 5% slippage on a $1M swap means $50,000 extractable by MEV.
Slippage should be calculated from a reliable price oracle with a small tolerance.

### 5. Missing minAmounts in Liquidity Operations
`addLiquidity` and `removeLiquidity` without minimum amount checks let attackers
manipulate pool ratios before the LP operation.

```solidity
// VULNERABLE
router.addLiquidity(tokenA, tokenB, amountA, amountB, 0, 0, to, deadline);

// SECURE
router.addLiquidity(tokenA, tokenB, amountA, amountB, amountA * 99 / 100, amountB * 99 / 100, to, deadline);
```

### 6. Swaps Without Any Slippage Parameter
Custom swap functions that don't accept or enforce any slippage parameter are
unconditionally vulnerable.

## Language-Specific Patterns

### Solidity/EVM
- Uniswap V2/V3 Router: swapExact*, exactInput, exactOutput
- Curve: exchange, exchange_underlying, add_liquidity, remove_liquidity
- Balancer: swap, batchSwap with limit parameter
- 1inch/Aggregators: swap with minReturnAmount

### Rust/Solana
- SPL Token Swap: swap with minimum_amount_out
- Raydium: swap_base_in, swap_base_out
- Orca Whirlpool: swap with otherAmountThreshold
- Jupiter: route with slippageBps

### Move (Aptos/Sui)
- Liquidswap: swap with min_amount_out
- PancakeSwap on Aptos: swap with slippage checks
- Cetus on Sui: swap_a2b with amount_limit

### Cairo/StarkNet
- JediSwap: swap_exact_tokens_for_tokens with amountOutMin
- 10KSwap: similar to Uniswap V2 pattern
- Ekubo: swap with sqrt_ratio_limit

## Severity Rating

- CRITICAL: amountOutMin = 0 or no slippage at all on swap handling user funds
- HIGH: Hardcoded high slippage (>= 3%) or missing deadline on significant operations
- MEDIUM: Hardcoded low slippage (<3%) or missing minAmounts on LP operations
- LOW: Slippage protection exists but could be tighter, informational deadline issues

When analyzing, trace the full path of every swap and liquidity operation.
Check both the function signature AND the actual values passed to external calls.
A function might accept amountOutMin but then pass 0 to the router internally."""


class SlippageHunter(AnalysisAgent):
    """
    Hunts for slippage protection and MEV vulnerabilities.
    """

    role = "hunter"
    name = "slippage_hunter"
    description = "Specialized agent for finding slippage and MEV vulnerabilities"

    @property
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def get_tools(self) -> list[Tool]:
        return self.tools

    def __init__(self, state: AuditState, **kwargs):
        self.language = kwargs.pop("language", Language.SOLIDITY)
        super().__init__(state=state, **kwargs)
        self.findings = []
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
                name="find_swap_operations",
                description="Find all swap and exchange operations in the codebase",
                input_schema={"type": "object", "properties": {}},
                handler=self._find_swap_operations,
            ),
            Tool(
                name="analyze_slippage_protection",
                description="Analyze a specific file for slippage protection issues",
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
                handler=self._analyze_slippage_protection,
            ),
            Tool(
                name="run_mev_analysis",
                description="Run the MEV analyzer on a contract's source code",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the contract file to analyze",
                        }
                    },
                    "required": ["file_path"],
                },
                handler=self._run_mev_analysis,
            ),
            Tool(
                name="report_finding",
                description="Report a slippage or MEV vulnerability",
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
                        "recommendation": {"type": "string"},
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                    },
                    "required": ["title", "severity", "contract", "description"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run slippage and MEV vulnerability analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        # Build context
        contracts_info = self._format_contracts_info()
        slippage_context = self._get_slippage_context()

        initial_prompt = f"""Analyze this {self.language.value} DeFi codebase for slippage and MEV vulnerabilities.

## Slippage/MEV Context
{slippage_context}

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture
{self._format_architecture()}

Your analysis should:
1. Use find_swap_operations to identify all swaps, exchanges, and liquidity operations
2. For each file with swap operations, use analyze_slippage_protection to check protections
3. Use run_mev_analysis on key contracts for deeper MEV pattern detection
4. Read specific files for manual analysis when needed
5. Report all findings with report_finding

Focus on:
- amountOutMin = 0 or amountOutMinimum = 0 in any swap call
- Missing deadline parameters or deadline = type(uint256).max
- limit = 0 in Balancer vault.swap() calls
- Hardcoded slippage percentages instead of oracle-derived values
- Missing minAmounts in addLiquidity/removeLiquidity
- Custom swap wrappers that silently drop slippage params
- Functions that accept slippage but pass 0 to the underlying router
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(f"  Slippage Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _get_slippage_context(self) -> str:
        """Get language-specific slippage context."""
        contexts = {
            Language.SOLIDITY: """
## EVM Slippage Patterns

### Uniswap V2 Router
```solidity
// swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
// VULNERABLE: amountOutMin = 0
router.swapExactTokensForTokens(amount, 0, path, msg.sender, block.timestamp);

// VULNERABLE: deadline = type(uint256).max (never expires)
router.swapExactTokensForTokens(amount, minOut, path, msg.sender, type(uint256).max);
```

### Uniswap V3 Router
```solidity
// VULNERABLE: amountOutMinimum = 0
ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
    tokenIn: tokenA,
    tokenOut: tokenB,
    fee: 3000,
    recipient: msg.sender,
    deadline: block.timestamp,
    amountIn: amount,
    amountOutMinimum: 0,  // NO PROTECTION
    sqrtPriceLimitX96: 0
});
```

### Curve Finance
```solidity
// VULNERABLE: min_dy = 0
pool.exchange(i, j, dx, 0);

// VULNERABLE: min_amounts all zero
pool.add_liquidity([amount0, amount1], 0);

// VULNERABLE: min_amount = 0
pool.remove_liquidity_one_coin(lp_amount, i, 0);
```

### Balancer Vault
```solidity
// VULNERABLE: limit = 0
vault.swap(singleSwap, funds, 0, deadline);

// VULNERABLE: limits all zero in batchSwap
int256[] memory limits = new int256[](tokens.length);
// all zeros = no protection
vault.batchSwap(kind, swaps, assets, funds, limits, deadline);
```

### Hardcoded Slippage
```solidity
// VULNERABLE: hardcoded 5% slippage
uint256 minOut = expectedOut * 95 / 100;

// BETTER: oracle-based with tight tolerance
uint256 oraclePrice = oracle.getPrice(tokenIn, tokenOut);
uint256 expectedOut = amountIn * oraclePrice / 1e18;
uint256 minOut = expectedOut * 9950 / 10000;  // 0.5% tolerance
```
""",
            Language.RUST: """
## Solana Slippage Patterns

### SPL Token Swap
```rust
// VULNERABLE: minimum_amount_out = 0
let instruction = spl_token_swap::instruction::swap(
    &program_id,
    &token_swap,
    &authority,
    &user_transfer_authority,
    &source,
    &swap_source,
    &swap_dest,
    &destination,
    &pool_mint,
    &fee_account,
    None,
    amount_in,
    0,  // minimum_amount_out = 0!
)?;
```

### Raydium
```rust
// VULNERABLE: minimum_out = 0
let ix = raydium_amm::instruction::swap_base_in(
    &program_id,
    &amm_id,
    &amm_authority,
    &amm_open_orders,
    &amm_target_orders,
    &pool_coin,
    &pool_pc,
    &serum_program,
    &serum_market,
    &serum_bids,
    &serum_asks,
    &serum_event,
    &serum_coin,
    &serum_pc,
    &serum_vault_signer,
    &user_source,
    &user_dest,
    &user_owner,
    amount_in,
    0,  // minimum_out = 0!
)?;
```

### Orca Whirlpool
```rust
// VULNERABLE: other_amount_threshold = 0
let cpi_ctx = CpiContext::new(
    ctx.accounts.whirlpool_program.to_account_info(),
    whirlpool::cpi::accounts::Swap { ... }
);
whirlpool::cpi::swap(
    cpi_ctx,
    amount,
    0,     // other_amount_threshold = 0!
    sqrt_price_limit,
    amount_specified_is_input,
    a_to_b,
)?;
```

### Common Issues
- Missing slippage in CPI calls to DEX programs
- Hardcoded slip_tolerance in program constants
- Not checking output amount after swap completes
""",
            Language.MOVE: """
## Move Slippage Patterns

### Liquidswap (Aptos)
```move
// VULNERABLE: min_amount_out = 0
let coins_out = router::swap_exact_coin_for_coin<CoinIn, CoinOut, Curve>(
    account,
    coins_in,
    0,  // min_amount_out = 0!
);
```

### PancakeSwap (Aptos)
```move
// VULNERABLE: no minimum check
public entry fun swap_exact_input<X, Y>(
    sender: &signer,
    amount_in: u64,
    // Missing: amount_out_min parameter
) {
    let coins_out = swap::swap(coin::withdraw(sender, amount_in));
    coin::deposit(signer::address_of(sender), coins_out);
}
```

### Cetus (Sui)
```move
// VULNERABLE: amount_limit = 0
let (receive_a, receive_b) = pool::swap<CoinA, CoinB>(
    pool,
    coin_a,
    coin_b,
    a2b,
    by_amount_in,
    amount,
    0,     // amount_limit = 0!
    clock,
);
```

### Common Issues
- Missing min_amount_out in swap entry functions
- No slippage check after coin::value() call
- Hardcoded slippage in module constants
""",
            Language.CAIRO: """
## Cairo/StarkNet Slippage Patterns

### JediSwap
```cairo
// VULNERABLE: amountOutMin = 0
let amounts = IJediSwapRouter::swap_exact_tokens_for_tokens(
    router,
    amount_in,
    0,              // amountOutMin = 0!
    path,
    to,
    deadline,
);
```

### 10KSwap
```cairo
// VULNERABLE: same Uniswap V2 pattern
fn swap_exact_tokens_for_tokens(
    ref self: ContractState,
    amountIn: u256,
    amountOutMin: u256,  // Often passed as 0
    path: Array<ContractAddress>,
    to: ContractAddress,
    deadline: u64,
)
```

### Ekubo
```cairo
// VULNERABLE: no sqrt_ratio_limit
fn swap(
    ref self: ContractState,
    pool_key: PoolKey,
    params: SwapParameters,
) {
    // Check params.sqrt_ratio_limit is not 0
    // Check params.amount is bounded
}
```

### Common Issues
- amountOutMin passed as 0 in router calls
- Missing deadline validation (felt252 overflow)
- No slippage check in custom swap wrappers
""",
        }
        return contexts.get(self.language, contexts[Language.SOLIDITY])

    def _format_contracts_info(self) -> str:
        """Format contract info for prompt."""
        if not self.state.contracts:
            return "No contracts analyzed yet."

        lines = []
        for contract in self.state.contracts[:10]:
            lines.append(f"- {contract.name}")
            if hasattr(contract, "external_calls"):
                for call in contract.external_calls[:3]:
                    lines.append(f"  - Calls: {call}")
        return "\n".join(lines)

    def _format_architecture(self) -> str:
        """Format architecture info."""
        if not self.state.architecture:
            return "No architecture analysis."

        notes = []
        if self.state.architecture.is_defi:
            notes.append("- DeFi protocol detected")
        if self.state.architecture.external_protocols:
            notes.append(
                f"- External protocols: {', '.join(self.state.architecture.external_protocols)}"
            )
        if self.state.architecture.defi_type:
            notes.append(
                f"- DeFi type: {', '.join(self.state.architecture.defi_type)}"
            )
        return "\n".join(notes) if notes else "Standard architecture"

    # Tool handlers

    async def _read_file(self, path: str) -> str:
        """Read a source file."""
        try:
            file_path = Path(path)
            if not file_path.is_absolute():
                file_path = self.state.target_path / path
            return file_path.read_text()
        except Exception as e:
            return f"Error: {e}"

    async def _find_swap_operations(self) -> str:
        """Find all swap and exchange operations in the codebase."""
        import re

        patterns = self._get_swap_patterns()
        results = []
        extensions = self._get_file_extensions()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()

                    for pattern_name, pattern in patterns.items():
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches[:5]:
                            line_num = content[: match.start()].count("\n") + 1
                            results.append(
                                {
                                    "file": str(
                                        file_path.relative_to(self.state.target_path)
                                    ),
                                    "line": line_num,
                                    "type": pattern_name,
                                    "match": match.group()[:120],
                                }
                            )
                except Exception:
                    continue

        if not results:
            return "No swap or exchange operations found in codebase."

        output = "Swap/Exchange Operations Found:\n\n"
        for r in results[:40]:
            output += f"[{r['type']}] {r['file']}:{r['line']}\n  {r['match']}\n\n"

        return output

    async def _analyze_slippage_protection(self, file_path: str) -> str:
        """Analyze slippage protection in a specific file."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        issues = []

        if self.language == Language.SOLIDITY:
            issues = self._analyze_solidity_slippage(content)
        elif self.language == Language.RUST:
            issues = self._analyze_rust_slippage(content)
        elif self.language == Language.MOVE:
            issues = self._analyze_move_slippage(content)
        elif self.language == Language.CAIRO:
            issues = self._analyze_cairo_slippage(content)

        if not issues:
            return "No slippage protection issues detected in this file."

        output = f"Slippage Protection Analysis for {file_path}:\n\n"
        for issue in issues:
            output += f"- [{issue['severity']}] {issue['issue']}\n"
            output += f"  Line: {issue.get('line', 'N/A')}\n"
            output += f"  Details: {issue['details']}\n\n"

        return output

    def _analyze_solidity_slippage(self, content: str) -> list[dict]:
        """Analyze Solidity slippage patterns."""
        import re

        issues = []

        # amountOutMin = 0 or amountOutMinimum = 0
        zero_min_pattern = r"amountOut(?:Min|Minimum)\s*[:=]\s*0\b"
        for match in re.finditer(zero_min_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "amountOutMin set to 0",
                    "line": line_num,
                    "details": "Swap has zero slippage protection - 100% of value extractable via sandwich attack",
                }
            )

        # amountOutMin = 1 (effectively zero)
        one_min_pattern = r"amountOut(?:Min|Minimum)\s*[:=]\s*1\b"
        for match in re.finditer(one_min_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "amountOutMin set to 1",
                    "line": line_num,
                    "details": "Setting amountOutMin to 1 is effectively the same as 0 - no real protection",
                }
            )

        # Swap router calls with literal 0 as min output
        # Uniswap V2 pattern: swapExact...(..., 0, ...)
        swap_zero_patterns = [
            (r"\.swapExact\w+\([^)]*,\s*0\s*,", "Uniswap V2 swap with amountOutMin = 0"),
            (r"\.exactInput(?:Single)?\s*\([^)]*amountOutMinimum\s*:\s*0", "Uniswap V3 swap with amountOutMinimum = 0"),
            (r"\.exchange\s*\([^)]*,\s*0\s*\)", "Curve exchange with min_dy = 0"),
            (r"\.exchange_underlying\s*\([^)]*,\s*0\s*\)", "Curve exchange_underlying with min_dy = 0"),
        ]

        for pattern, desc in swap_zero_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "severity": "CRITICAL",
                        "issue": desc,
                        "line": line_num,
                        "details": "Swap call passes 0 as minimum output amount",
                    }
                )

        # Balancer vault.swap with limit = 0
        balancer_pattern = r"\.swap\s*\([^)]*,\s*0\s*,"
        for match in re.finditer(balancer_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            # Avoid false positives - check if this looks like a Balancer call
            context_start = max(0, match.start() - 200)
            context = content[context_start : match.start()]
            if any(kw in context.lower() for kw in ["vault", "balancer", "singleswap", "batchswap"]):
                issues.append(
                    {
                        "severity": "CRITICAL",
                        "issue": "Balancer swap with limit = 0",
                        "line": line_num,
                        "details": "Balancer vault.swap() called with limit = 0 provides no slippage protection",
                    }
                )

        # Missing deadline (type(uint256).max or very large constant)
        max_deadline_pattern = r"type\s*\(\s*uint256\s*\)\s*\.max"
        for match in re.finditer(max_deadline_pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            # Check if this is in a swap context
            context_start = max(0, match.start() - 300)
            context = content[context_start : match.end()]
            if any(kw in context.lower() for kw in ["swap", "exchange", "liquidity", "deadline"]):
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": "Deadline set to type(uint256).max",
                        "line": line_num,
                        "details": "Transaction never expires - validators can hold and execute at unfavorable time",
                    }
                )

        # Hardcoded slippage percentages
        hardcoded_patterns = [
            (r"(\d+)\s*/\s*100\b", "percentage"),
            (r"\*\s*(\d+)\s*/\s*100\b", "percentage"),
            (r"\*\s*(9[0-9])\s*/\s*100\b", "percentage"),
            (r"\*\s*(9[0-9]{2,3})\s*/\s*(?:1000|10000)\b", "basis_points"),
        ]

        for pattern, ptype in hardcoded_patterns:
            for match in re.finditer(pattern, content):
                # Check if this is in a slippage context
                context_start = max(0, match.start() - 200)
                context = content[context_start : match.end() + 50]
                if any(kw in context.lower() for kw in [
                    "slippage", "minout", "minamount", "amountout", "min_dy",
                    "amountoutmin", "expected",
                ]):
                    value = int(match.group(1))
                    if ptype == "percentage" and 90 <= value <= 97:
                        slip_pct = 100 - value
                        issues.append(
                            {
                                "severity": "MEDIUM" if slip_pct <= 3 else "HIGH",
                                "issue": f"Hardcoded slippage tolerance of {slip_pct}%",
                                "line": content[: match.start()].count("\n") + 1,
                                "details": f"Slippage hardcoded at {slip_pct}% instead of being calculated from oracle price",
                            }
                        )
                    elif ptype == "basis_points" and 9000 <= value <= 9700:
                        slip_bps = 10000 - value
                        slip_pct = slip_bps / 100
                        issues.append(
                            {
                                "severity": "MEDIUM" if slip_pct <= 3 else "HIGH",
                                "issue": f"Hardcoded slippage tolerance of {slip_pct}%",
                                "line": content[: match.start()].count("\n") + 1,
                                "details": f"Slippage hardcoded at {slip_bps} bps instead of oracle-derived value",
                            }
                        )

        # addLiquidity with minAmounts = 0
        liq_zero_pattern = r"\.addLiquidity\s*\([^)]*,\s*0\s*,\s*0\s*[,)]"
        for match in re.finditer(liq_zero_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "addLiquidity with minAmounts = 0",
                    "line": line_num,
                    "details": "Liquidity addition has no minimum amount protection - vulnerable to pool ratio manipulation",
                }
            )

        # removeLiquidity with minAmounts = 0
        remove_liq_pattern = r"\.removeLiquidity\s*\([^)]*,\s*0\s*,\s*0\s*[,)]"
        for match in re.finditer(remove_liq_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "removeLiquidity with minAmounts = 0",
                    "line": line_num,
                    "details": "Liquidity removal has no minimum amount protection",
                }
            )

        # Curve add_liquidity with min_mint_amount = 0
        curve_add_pattern = r"\.add_liquidity\s*\([^)]*,\s*0\s*\)"
        for match in re.finditer(curve_add_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Curve add_liquidity with min_mint_amount = 0",
                    "line": line_num,
                    "details": "Curve liquidity deposit has no minimum LP token check",
                }
            )

        # remove_liquidity_one_coin with min_amount = 0
        curve_remove_pattern = r"\.remove_liquidity_one_coin\s*\([^)]*,\s*0\s*\)"
        for match in re.finditer(curve_remove_pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "Curve remove_liquidity_one_coin with min_amount = 0",
                    "line": line_num,
                    "details": "Single-sided liquidity removal has no minimum output protection",
                }
            )

        return issues

    def _analyze_rust_slippage(self, content: str) -> list[dict]:
        """Analyze Rust/Solana slippage patterns."""
        import re

        issues = []

        # minimum_amount_out = 0
        min_out_zero = r"minimum_amount_out\s*[:=]\s*0\b"
        for match in re.finditer(min_out_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "minimum_amount_out set to 0",
                    "line": line_num,
                    "details": "Swap has zero slippage protection on Solana",
                }
            )

        # other_amount_threshold = 0 (Orca Whirlpool)
        threshold_zero = r"other_amount_threshold\s*[:=]\s*0\b"
        for match in re.finditer(threshold_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "other_amount_threshold set to 0 (Whirlpool)",
                    "line": line_num,
                    "details": "Orca Whirlpool swap has no slippage protection",
                }
            )

        # Hardcoded slippage_bps or slip_tolerance
        hardcoded_slip = r"(?:slippage_bps|slip_tolerance|slippage)\s*[:=]\s*(\d+)"
        for match in re.finditer(hardcoded_slip, content, re.IGNORECASE):
            value = int(match.group(1))
            line_num = content[: match.start()].count("\n") + 1
            if value == 0:
                issues.append(
                    {
                        "severity": "CRITICAL",
                        "issue": "Slippage tolerance set to 0",
                        "line": line_num,
                        "details": "Zero slippage tolerance provides no protection",
                    }
                )
            elif value >= 300:  # 3% in bps
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": f"Hardcoded high slippage tolerance: {value} bps ({value/100}%)",
                        "line": line_num,
                        "details": "High hardcoded slippage enables significant MEV extraction",
                    }
                )

        # Swap CPI without checking output
        if "invoke" in content or "invoke_signed" in content:
            if "swap" in content.lower():
                # Check if output amount is validated after the CPI
                if "minimum" not in content.lower() and "min_amount" not in content.lower():
                    issues.append(
                        {
                            "severity": "HIGH",
                            "issue": "Swap CPI without output validation",
                            "line": 0,
                            "details": "Cross-program swap invocation may lack output amount verification",
                        }
                    )

        return issues

    def _analyze_move_slippage(self, content: str) -> list[dict]:
        """Analyze Move slippage patterns."""
        import re

        issues = []

        # min_amount_out = 0
        min_out_zero = r"min_amount_out\s*[:=]\s*0\b"
        for match in re.finditer(min_out_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "min_amount_out set to 0",
                    "line": line_num,
                    "details": "Swap has zero slippage protection",
                }
            )

        # amount_limit = 0
        amount_limit_zero = r"amount_limit\s*[:=]\s*0\b"
        for match in re.finditer(amount_limit_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "amount_limit set to 0",
                    "line": line_num,
                    "details": "Swap amount limit of 0 provides no slippage protection",
                }
            )

        # Swap function without min output parameter
        swap_func_pattern = r"public\s+(?:entry\s+)?fun\s+swap\w*\s*(?:<[^>]*>)?\s*\(([^)]*)\)"
        for match in re.finditer(swap_func_pattern, content):
            params = match.group(1).lower()
            if "min" not in params and "limit" not in params and "threshold" not in params:
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": "Swap function without minimum output parameter",
                        "line": line_num,
                        "details": "Swap entry function has no slippage protection parameter",
                    }
                )

        return issues

    def _analyze_cairo_slippage(self, content: str) -> list[dict]:
        """Analyze Cairo/StarkNet slippage patterns."""
        import re

        issues = []

        # amountOutMin = 0 in Cairo
        min_out_zero = r"(?:amount_out_min|amountOutMin)\s*[:=]\s*0\b"
        for match in re.finditer(min_out_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "CRITICAL",
                    "issue": "amountOutMin set to 0",
                    "line": line_num,
                    "details": "Swap has zero slippage protection on StarkNet",
                }
            )

        # Missing deadline check
        if "swap" in content.lower():
            if "deadline" not in content.lower() and "block_timestamp" not in content.lower():
                issues.append(
                    {
                        "severity": "MEDIUM",
                        "issue": "Swap without deadline check",
                        "line": 0,
                        "details": "No deadline validation found near swap operations",
                    }
                )

        # sqrt_ratio_limit = 0 (Ekubo)
        sqrt_zero = r"sqrt_ratio_limit\s*[:=]\s*0\b"
        for match in re.finditer(sqrt_zero, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": "sqrt_ratio_limit set to 0 (Ekubo)",
                    "line": line_num,
                    "details": "Ekubo swap with no price limit provides no slippage protection",
                }
            )

        return issues

    async def _run_mev_analysis(self, file_path: str) -> str:
        """Run the MEV analyzer on a contract file."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error reading file: {e}"

        try:
            from ...core.advanced.mev_analyzer import MEVAnalyzer

            analyzer = MEVAnalyzer()
            findings = analyzer.analyze(content, contract_name=full_path.stem)
            summary = analyzer.get_summary()

            if not findings:
                return f"MEV Analyzer: No MEV vulnerabilities found in {file_path}."

            output = f"MEV Analysis for {file_path}:\n\n"
            output += f"Total findings: {summary['total_findings']}\n"
            output += f"Risk level: {summary['estimated_risk']}\n\n"

            for finding in findings:
                output += f"[{finding.severity.value.upper()}] {finding.title}\n"
                output += f"  Vector: {finding.vector.value}\n"
                output += f"  Line: {finding.line_number}\n"
                output += f"  Description: {finding.description}\n"
                output += f"  Extraction: {finding.extraction_potential}\n"
                output += f"  Attack: {finding.attack_scenario[:200]}\n"
                output += f"  Mitigation: {finding.mitigation}\n\n"

            return output

        except ImportError:
            return "MEV Analyzer module not available. Perform manual analysis."
        except Exception as e:
            return f"Error running MEV analysis: {e}"

    def _report_finding(self, params: dict) -> str:
        """Report a slippage or MEV finding."""
        title = params["title"]
        severity = params["severity"]
        contract = params["contract"]
        description = params["description"]
        function = params.get("function", "")
        impact = params.get("impact", "")
        recommendation = params.get("recommendation", "")
        confidence = params.get("confidence", 0.8)

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        # Determine vulnerability type based on the finding content
        vuln_type = self._classify_vulnerability(title, description)

        finding = Finding(
            id=f"SLIPPAGE-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            vulnerability_type=vuln_type,
            description=description,
            contract=contract,
            function=function if function else None,
            impact=impact,
            recommendation=recommendation,
            found_by=AgentRole.VULNERABILITY_HUNTER,
            confidence=confidence,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity}] {title}"

    def _classify_vulnerability(self, title: str, description: str) -> VulnerabilityType:
        """Classify the vulnerability type based on title and description content."""
        combined = (title + " " + description).lower()

        if "deadline" in combined:
            return VulnerabilityType.MISSING_DEADLINE
        if "sandwich" in combined:
            return VulnerabilityType.SANDWICH_ATTACK
        return VulnerabilityType.MISSING_SLIPPAGE

    def _get_swap_patterns(self) -> dict[str, str]:
        """Get swap-related patterns for each language."""
        if self.language == Language.SOLIDITY:
            return {
                "uniswap_v2_swap": r"\.swapExact\w+For\w+\s*\(",
                "uniswap_v3_swap": r"\.exactInput(?:Single)?\s*\(|\.exactOutput(?:Single)?\s*\(",
                "curve_exchange": r"\.exchange(?:_underlying)?\s*\(",
                "curve_liquidity": r"\.(?:add|remove)_liquidity\w*\s*\(",
                "balancer_swap": r"(?:vault|IVault)\s*\.\s*(?:swap|batchSwap)\s*\(",
                "generic_swap": r"function\s+\w*(?:[Ss]wap|[Ee]xchange)\w*\s*\(",
                "add_liquidity": r"\.addLiquidity\s*\(",
                "remove_liquidity": r"\.removeLiquidity\s*\(",
            }
        elif self.language == Language.RUST:
            return {
                "spl_swap": r"swap\s*\(|swap_base_in\s*\(|swap_base_out\s*\(",
                "raydium_swap": r"raydium.*swap|swap.*raydium",
                "orca_swap": r"whirlpool.*swap|swap.*whirlpool",
                "jupiter_route": r"route\s*\(|swap_exact\s*\(",
                "generic_swap": r"pub\s+fn\s+\w*swap\w*\s*[<(]",
                "add_liquidity": r"pub\s+fn\s+\w*(?:add_liquidity|deposit)\w*\s*[<(]",
                "remove_liquidity": r"pub\s+fn\s+\w*(?:remove_liquidity|withdraw)\w*\s*[<(]",
            }
        elif self.language == Language.MOVE:
            return {
                "swap": r"(?:public\s+)?(?:entry\s+)?fun\s+\w*swap\w*\s*(?:<[^>]*>)?\s*\(",
                "exchange": r"(?:public\s+)?fun\s+\w*exchange\w*\s*\(",
                "add_liquidity": r"(?:public\s+)?fun\s+\w*add_liquidity\w*\s*\(",
                "remove_liquidity": r"(?:public\s+)?fun\s+\w*remove_liquidity\w*\s*\(",
            }
        elif self.language == Language.CAIRO:
            return {
                "swap": r"fn\s+\w*swap\w*\s*\(",
                "exchange": r"fn\s+\w*exchange\w*\s*\(",
                "add_liquidity": r"fn\s+\w*add_liquidity\w*\s*\(",
                "remove_liquidity": r"fn\s+\w*remove_liquidity\w*\s*\(",
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
