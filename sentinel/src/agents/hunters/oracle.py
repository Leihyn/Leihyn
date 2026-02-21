"""
Oracle Manipulation Hunter Agent - Price oracle and data feed security.

Detects:
- Spot price manipulation vulnerabilities
- TWAP manipulation windows
- Oracle staleness issues
- Flash loan + oracle attacks
- Multi-block MEV oracle attacks

Supports: Solidity, Rust/Solana, Move, Cairo
"""

from pathlib import Path
from typing import Optional

from ...core.agent import AnalysisAgent, Tool
from ...core.types import AgentRole, AuditState, Finding, Severity, VulnerabilityType
from ...core.languages import Language


SYSTEM_PROMPT = """You are an elite DeFi security researcher specializing in oracle manipulation
and price feed vulnerabilities across Chainlink, Uniswap TWAPs, Pyth, Switchboard, Pragma,
and custom oracle implementations.

Consult the vulnerability cheatsheet below for known oracle patterns, and use the
`get_vulnerability_reference` tool with category="oracle_manipulation" for detailed
detection heuristics, per-ecosystem oracle types, code examples, and false-positive conditions.

## Analysis Approach
1. Find all oracle/price reads (latestRoundData, getReserves, consult, Pyth get_price)
2. Check for spot price usage vulnerable to flash loan manipulation
3. Verify freshness checks on all price data (updatedAt, answeredInRound, timestamp)
4. Check TWAP windows (< 10 min = HIGH risk, < 30 min = MEDIUM risk)
5. Look for missing circuit breakers and single oracle dependencies
6. Verify decimal normalization (Chainlink 8 decimals, tokens 6/8/18)

## Reporting
- Estimate manipulation cost vs potential profit
- Note whether TWAP, multi-oracle, or other mitigations exist
- Rate: CRITICAL (direct fund loss), HIGH (significant impact), MEDIUM (mitigated), LOW (minor)
"""


class OracleManipulationHunter(AnalysisAgent):
    """
    Hunts for oracle manipulation and price feed vulnerabilities.
    """

    role = "hunter"
    name = "oracle_hunter"
    description = "Specialized agent for finding oracle manipulation vulnerabilities"

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
                name="find_oracle_usage",
                description="Find all oracle and price feed usage in the codebase",
                input_schema={"type": "object", "properties": {}},
                handler=self._find_oracle_usage,
            ),
            Tool(
                name="analyze_price_calculation",
                description="Analyze how prices are calculated and used",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to analyze"}
                    },
                    "required": ["file_path"],
                },
                handler=self._analyze_price_calculation,
            ),
            Tool(
                name="check_oracle_freshness",
                description="Check if oracle data freshness is validated",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to check"}
                    },
                    "required": ["file_path"],
                },
                handler=self._check_oracle_freshness,
            ),
            Tool(
                name="analyze_twap_implementation",
                description="Analyze TWAP oracle implementation for manipulation risks",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to analyze"}
                    },
                    "required": ["file_path"],
                },
                handler=self._analyze_twap,
            ),
            Tool(
                name="check_decimal_handling",
                description="Check for price decimal handling issues",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to check"}
                    },
                    "required": ["file_path"],
                },
                handler=self._check_decimals,
            ),
            Tool(
                name="verify_twap_mathematically",
                description="Algebraically verify a TWAP/cumulative price implementation. Checks if the formula actually computes a time-weighted average or simplifies to just the spot price (tautology).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to the file containing the TWAP implementation"},
                        "function_name": {"type": "string", "description": "Name of the function to verify"},
                    },
                    "required": ["file_path"],
                },
                handler=self._verify_twap_mathematically,
            ),
            Tool(
                name="trace_oracle_consumers",
                description="Trace where oracle/price data flows to across all contracts. Finds all functions that consume price data from oracle functions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "oracle_function": {"type": "string", "description": "Name of the oracle function to trace (e.g., 'getPrice', 'currentPrice')"},
                    },
                    "required": ["oracle_function"],
                },
                handler=self._trace_oracle_consumers,
            ),
            Tool(
                name="report_finding",
                description="Report an oracle manipulation vulnerability",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                        "description": {"type": "string"},
                        "location": {"type": "string"},
                        "impact": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "attack_scenario": {"type": "string"},
                    },
                    "required": ["title", "severity", "description", "location"],
                },
                handler=self._report_finding,
            ),
        ]

    async def run(self) -> list[Finding]:
        """Run oracle manipulation analysis."""
        from ...core.llm import get_llm_client

        llm = get_llm_client()

        # Build context
        contracts_info = self._format_contracts_info()
        oracle_context = self._get_oracle_context()

        initial_prompt = f"""Analyze this {self.language.value} DeFi codebase for oracle manipulation vulnerabilities.

## Oracle Context
{oracle_context}

## Target
{self.state.target_path}

## Contracts/Modules
{contracts_info}

## Architecture
{self._format_architecture()}

Your analysis should:
1. Use find_oracle_usage to identify all oracle integrations
2. For each oracle usage, analyze_price_calculation to understand the flow
3. Use check_oracle_freshness to verify staleness checks
4. For TWAP oracles, use analyze_twap_implementation
5. For custom TWAP implementations, use verify_twap_mathematically to check for algebraic tautologies
6. Use trace_oracle_consumers to follow price data across contracts
7. Check for decimal handling issues with check_decimal_handling
8. Report all findings with report_finding

Focus on:
- Spot price usage without TWAP protection
- Missing or insufficient freshness checks
- Short TWAP windows (< 30 minutes is suspicious)
- Single-block price reads
- Missing circuit breakers for extreme prices
- Decimal normalization errors
- TWAP tautologies (formula simplifies to spot price despite appearing time-weighted)
- Cross-contract oracle data flow issues
"""

        response, tool_calls, _thinking = llm.run_agent_loop(
            initial_message=initial_prompt,
            system=SYSTEM_PROMPT,
            tools=self.tools,
        )

        if self.verbose:
            print(f"  Oracle Hunter completed: {len(self.findings)} findings")

        return self.findings

    def _get_oracle_context(self) -> str:
        """Get language-specific oracle context."""
        contexts = {
            Language.SOLIDITY: """
## EVM Oracle Patterns

### Chainlink Price Feeds
```solidity
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

// Vulnerable: no staleness check
(, int256 price, , , ) = priceFeed.latestRoundData();

// Secure: with staleness check
(uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) =
    priceFeed.latestRoundData();
require(updatedAt > block.timestamp - MAX_DELAY, "Stale price");
require(answeredInRound >= roundId, "Stale round");
require(price > 0, "Invalid price");
```

### Uniswap V3 TWAP
```solidity
// Vulnerable: short TWAP window
uint32 twapWindow = 60; // Only 1 minute!

// Secure: longer window
uint32 twapWindow = 1800; // 30 minutes
```

### Spot Price (DANGEROUS)
```solidity
// NEVER DO THIS - manipulable via flash loan
(uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
uint256 price = reserve1 * 1e18 / reserve0;
```
""",
            Language.RUST: """
## Solana Oracle Patterns

### Pyth Network
```rust
use pyth_sdk_solana::Price;

// Get price from Pyth
let price_account = &ctx.accounts.price_feed;
let price_data = Price::get_price_no_older_than(
    price_account,
    Clock::get()?.unix_timestamp,
    MAX_STALENESS_SECONDS,
)?;

// Check confidence interval
require!(
    price_data.conf < price_data.price / 100,  // < 1% confidence
    OracleError::PriceTooUncertain
);
```

### Switchboard
```rust
let aggregator = AggregatorAccountData::new(feed_account)?;
let result = aggregator.get_result()?;

// Check staleness
let staleness = Clock::get()?.unix_timestamp - result.timestamp;
require!(staleness < MAX_STALENESS, OracleError::StalePrice);
```

### Common Vulnerabilities
- Not checking Pyth price confidence interval
- Missing staleness checks
- Using price without exponent adjustment
""",
            Language.MOVE: """
## Move Oracle Patterns

### Pyth on Aptos/Sui
```move
use pyth::price;

public fun get_price(price_info: &PriceInfoObject): Price {
    let price = price::get_price(price_info);

    // Check staleness
    let current_time = timestamp::now_seconds();
    let price_time = price::get_timestamp(&price);
    assert!(current_time - price_time < MAX_STALENESS, E_STALE_PRICE);

    price
}
```

### Custom Oracles
```move
struct PriceFeed has key {
    price: u64,
    decimals: u8,
    last_update: u64,
}
```

### Common Vulnerabilities
- Not checking price timestamp
- Missing authority validation on price updates
- Decimal conversion errors
""",
            Language.CAIRO: """
## Cairo/StarkNet Oracle Patterns

### Pragma Oracle
```cairo
use pragma_lib::abi::{IPragmaABIDispatcher, IPragmaABIDispatcherTrait};

fn get_price(self: @ContractState, asset_id: felt252) -> u128 {
    let pragma = IPragmaABIDispatcher { contract_address: PRAGMA_ADDRESS };
    let response = pragma.get_data_median(DataType::SpotEntry(asset_id));

    // Check staleness
    let current_time = get_block_timestamp();
    assert(current_time - response.last_updated_timestamp < MAX_STALENESS, 'Stale price');

    response.price
}
```

### L1 Oracle Bridge
```cairo
// Price relayed from L1 Chainlink
#[l1_handler]
fn update_price(ref self: ContractState, from_address: felt252, price: u256) {
    assert(from_address == L1_ORACLE_RELAYER, 'Invalid relayer');
    self.price.write(price);
    self.last_update.write(get_block_timestamp());
}
```

### Common Vulnerabilities
- Not validating L1 message source
- Missing staleness checks
- Felt overflow in price calculations
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
            if hasattr(contract, 'external_calls'):
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
            notes.append(f"- External protocols: {', '.join(self.state.architecture.external_protocols)}")
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

    async def _find_oracle_usage(self) -> str:
        """Find all oracle usage patterns in the codebase."""
        import re

        patterns = self._get_oracle_patterns()
        results = []
        extensions = self._get_file_extensions()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()

                    for pattern_name, pattern in patterns.items():
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches[:5]:
                            line_num = content[:match.start()].count('\n') + 1
                            results.append({
                                "file": str(file_path.relative_to(self.state.target_path)),
                                "line": line_num,
                                "type": pattern_name,
                                "match": match.group()[:100],
                            })
                except Exception:
                    continue

        if not results:
            return "No oracle usage found in codebase."

        output = "Oracle Usage Found:\n\n"
        for r in results[:30]:
            output += f"[{r['type']}] {r['file']}:{r['line']}\n  {r['match']}\n\n"

        return output

    async def _analyze_price_calculation(self, file_path: str) -> str:
        """Analyze price calculation patterns."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        issues = []

        if self.language == Language.SOLIDITY:
            issues = self._analyze_solidity_prices(content)
        elif self.language == Language.RUST:
            issues = self._analyze_rust_prices(content)
        elif self.language == Language.MOVE:
            issues = self._analyze_move_prices(content)
        elif self.language == Language.CAIRO:
            issues = self._analyze_cairo_prices(content)

        if not issues:
            return "No price calculation issues detected."

        output = f"Price Calculation Analysis for {file_path}:\n\n"
        for issue in issues:
            output += f"- [{issue['severity']}] {issue['issue']}\n"
            output += f"  Line: {issue.get('line', 'N/A')}\n"
            output += f"  Details: {issue['details']}\n\n"

        return output

    def _analyze_solidity_prices(self, content: str) -> list[dict]:
        """Analyze Solidity price calculations."""
        import re
        issues = []

        # Check for spot price from reserves (VERY BAD)
        reserve_pattern = r"getReserves\s*\(\s*\)"
        if re.search(reserve_pattern, content):
            # Check if it's used for pricing
            if "price" in content.lower() or "rate" in content.lower():
                issues.append({
                    "severity": "CRITICAL",
                    "issue": "Spot price from AMM reserves",
                    "details": "Using getReserves() for pricing is vulnerable to flash loan manipulation",
                })

        # Check for balance-based pricing
        balance_price_pattern = r"balanceOf.*(?:price|rate|value)"
        if re.search(balance_price_pattern, content, re.IGNORECASE | re.DOTALL):
            issues.append({
                "severity": "HIGH",
                "issue": "Balance-based price calculation",
                "details": "Token balance ratio can be manipulated via flash loans",
            })

        # Check for missing Chainlink round validation
        if "latestRoundData" in content:
            if "answeredInRound" not in content:
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Missing Chainlink round validation",
                    "details": "Should check answeredInRound >= roundId",
                })

        # Check for short TWAP windows
        twap_pattern = r"(?:twap|observe|consult).*?(\d+)"
        for match in re.finditer(twap_pattern, content, re.IGNORECASE):
            window = int(match.group(1))
            if window < 600:  # Less than 10 minutes
                issues.append({
                    "severity": "HIGH",
                    "issue": f"Short TWAP window: {window} seconds",
                    "details": "TWAP windows under 10-30 minutes are manipulable",
                })

        return issues

    def _analyze_rust_prices(self, content: str) -> list[dict]:
        """Analyze Rust/Solana price calculations."""
        import re
        issues = []

        # Check for Pyth without confidence check
        if "pyth" in content.lower():
            if "conf" not in content and "confidence" not in content:
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Pyth price without confidence check",
                    "details": "Should verify price confidence interval",
                })

        # Check for missing exponent handling
        if "get_price" in content and "expo" not in content:
            issues.append({
                "severity": "MEDIUM",
                "issue": "Price used without exponent adjustment",
                "details": "Pyth prices need exponent normalization",
            })

        # Check for spot pool price
        if "get_amount_out" in content or "swap_base" in content:
            if "oracle" not in content.lower():
                issues.append({
                    "severity": "HIGH",
                    "issue": "DEX spot price usage",
                    "details": "Using pool swap rates as oracle is manipulable",
                })

        return issues

    def _analyze_move_prices(self, content: str) -> list[dict]:
        """Analyze Move price calculations."""
        import re
        issues = []

        # Check for custom oracle without staleness
        if "PriceFeed" in content or "price_feed" in content:
            if "timestamp" not in content.lower():
                issues.append({
                    "severity": "HIGH",
                    "issue": "Price feed without timestamp check",
                    "details": "Custom oracles need staleness validation",
                })

        # Check for pool-based pricing
        if "reserve" in content.lower() and "price" in content.lower():
            issues.append({
                "severity": "HIGH",
                "issue": "Reserve-based price calculation",
                "details": "Pool reserves can be manipulated via flash loans",
            })

        return issues

    def _analyze_cairo_prices(self, content: str) -> list[dict]:
        """Analyze Cairo price calculations."""
        import re
        issues = []

        # Check Pragma usage
        if "pragma" in content.lower():
            if "last_updated" not in content.lower():
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Pragma oracle without staleness check",
                    "details": "Should check last_updated_timestamp",
                })

        # Check for L1 oracle without validation
        if "l1_handler" in content and "price" in content.lower():
            if "from_address" not in content:
                issues.append({
                    "severity": "CRITICAL",
                    "issue": "L1 price handler without source validation",
                    "details": "Anyone could submit fake prices",
                })

        return issues

    async def _check_oracle_freshness(self, file_path: str) -> str:
        """Check if oracle freshness is validated."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        checks = []

        if self.language == Language.SOLIDITY:
            # Chainlink staleness
            if "latestRoundData" in content:
                has_staleness = any(check in content for check in [
                    "updatedAt",
                    "block.timestamp -",
                    "staleness",
                    "heartbeat",
                ])
                checks.append({
                    "oracle": "Chainlink",
                    "has_staleness_check": has_staleness,
                    "recommendation": "Check (block.timestamp - updatedAt) < MAX_DELAY",
                })

        elif self.language == Language.RUST:
            # Pyth staleness
            if "pyth" in content.lower():
                has_staleness = "get_price_no_older_than" in content or "unix_timestamp" in content
                checks.append({
                    "oracle": "Pyth",
                    "has_staleness_check": has_staleness,
                    "recommendation": "Use get_price_no_older_than() or check timestamp manually",
                })

        elif self.language == Language.CAIRO:
            if "pragma" in content.lower():
                has_staleness = "last_updated" in content or "timestamp" in content
                checks.append({
                    "oracle": "Pragma",
                    "has_staleness_check": has_staleness,
                    "recommendation": "Check last_updated_timestamp against block timestamp",
                })

        if not checks:
            return "No oracle usage found to check freshness."

        output = "Freshness Check Analysis:\n\n"
        for check in checks:
            status = "PASS" if check["has_staleness_check"] else "FAIL"
            output += f"[{status}] {check['oracle']}\n"
            if not check["has_staleness_check"]:
                output += f"  Missing: {check['recommendation']}\n"
            output += "\n"

        return output

    async def _analyze_twap(self, file_path: str) -> str:
        """Analyze TWAP implementation with algebraic verification."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        import re
        analysis = []

        # Look for TWAP patterns
        twap_patterns = [
            r"observe\s*\(",
            r"consult\s*\(",
            r"twap",
            r"time.?weighted",
            r"cumulative",
            r"priceCumulative",
            r"priceAccumulator",
            r"cumulativePrice",
        ]

        has_twap = any(re.search(p, content, re.IGNORECASE) for p in twap_patterns)

        if not has_twap:
            return "No TWAP implementation found in this file."

        # Check for window duration
        window_pattern = r"(?:window|period|seconds|duration)[^\d]*(\d+)"
        windows = re.findall(window_pattern, content, re.IGNORECASE)

        for window in windows:
            window_secs = int(window)
            if window_secs < 600:
                analysis.append(f"WARNING: Short TWAP window of {window_secs}s (< 10 min)")
            elif window_secs < 1800:
                analysis.append(f"CAUTION: TWAP window of {window_secs}s (< 30 min)")
            else:
                analysis.append(f"OK: TWAP window of {window_secs}s")

        # Check for single observation point
        if "observe" in content and "[0]" in content:
            analysis.append("WARNING: May be using single observation point")

        # Check for custom TWAP formulas that might be tautologies
        # Look for cumulative price difference divided by time difference
        cumulative_patterns = [
            r"(cumulative\w*Price\w*|price\w*Cumulative\w*|priceAccumulator)",
            r"(cPriceLast|priceCumulativeLast|lastCumulativePrice)",
        ]
        has_custom_twap = any(
            re.search(p, content, re.IGNORECASE) for p in cumulative_patterns
        )
        if has_custom_twap:
            analysis.append("CUSTOM TWAP detected - use verify_twap_mathematically for algebraic verification")

            # Look for potential tautology patterns:
            # (cumNew + spot*dt - cumOld) / dt  simplifies to spot (tautology!)
            tautology_pattern = r"\([^)]*cumul\w*[^)]*\+[^)]*spot\w*[^)]*\*[^)]*\w*[Tt]ime\w*[^)]*-[^)]*cumul\w*[^)]*\)\s*/\s*\w*[Tt]ime"
            if re.search(tautology_pattern, content, re.IGNORECASE):
                analysis.append("CRITICAL: Potential TWAP tautology detected! Formula may simplify to just spot price.")

        if not analysis:
            analysis.append("TWAP implementation found - manual review needed")

        return "TWAP Analysis:\n" + "\n".join(f"- {a}" for a in analysis)

    async def _verify_twap_mathematically(self, file_path: str, function_name: str = "") -> str:
        """Algebraically verify a TWAP implementation using LLM reasoning."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        import re

        # Extract the relevant function(s)
        if function_name:
            # Find specific function
            func_pattern = rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{(.*?)\n\s*\}}"
            match = re.search(func_pattern, content, re.DOTALL)
            if match:
                func_code = match.group(0)
            else:
                func_code = content  # Fall back to full file
        else:
            # Find all functions with TWAP/cumulative keywords
            twap_keywords = ["twap", "cumulative", "timeWeighted", "observe", "priceAccumulator"]
            func_code_parts = []
            for kw in twap_keywords:
                pattern = rf"function\s+\w*{kw}\w*\s*\([^)]*\)[^{{]*\{{(.*?)\n\s*\}}"
                for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
                    func_code_parts.append(match.group(0))
            func_code = "\n\n".join(func_code_parts) if func_code_parts else content[:3000]

        from ...core.llm import get_llm_client
        llm = get_llm_client()

        prompt = f"""Perform algebraic verification of this TWAP/cumulative price implementation.

## Code
```solidity
{func_code[:3000]}
```

## Algebraic Verification Steps

1. **Extract the formula**: Write out the mathematical expression being computed, using symbolic variables.

2. **Simplify step by step**: Apply algebraic simplification. Show each step.

3. **Tautology check**: Does any variable cancel out? If the formula simplifies to just the spot price, the "time-weighting" is fake. This is a CRITICAL bug.
   Example tautology: `(cumulativePriceLast + spotPrice * timeDelta - cumulativePriceLast) / timeDelta`
   Simplifies to: `spotPrice * timeDelta / timeDelta = spotPrice`
   The cumulative price terms cancel out! The result is just the spot price.

4. **Time-weighting verification**: Does the result ACTUALLY depend on historical prices? A real TWAP should use the difference of cumulative prices at two time points: `(cumPrice_now - cumPrice_past) / (time_now - time_past)`.

5. **Boundary analysis**: What happens when timeDelta = 0? When timeDelta is very large? Can division by zero occur?

6. **Manipulation resistance**: Can an attacker manipulate the result in a single block/transaction?

If you find a bug, explain:
- Exactly why the formula is wrong
- What the correct formula should be
- The security impact (can an attacker exploit this?)"""

        response = llm.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a mathematician specializing in DeFi oracle formulas. Be precise and show all algebraic steps.",
        )
        return response.content

    async def _trace_oracle_consumers(self, oracle_function: str) -> str:
        """Trace where oracle/price data flows across all contracts."""
        import re

        results = []
        extensions = self._get_file_extensions()

        for ext in extensions:
            for file_path in self.state.target_path.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text()
                    relative = str(file_path.relative_to(self.state.target_path))

                    # Find calls to the oracle function
                    call_pattern = rf"(\w+\.)?{re.escape(oracle_function)}\s*\("
                    for match in re.finditer(call_pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        # Get surrounding context (the full line + a few after)
                        lines = content.split('\n')
                        start = max(0, line_num - 2)
                        end = min(len(lines), line_num + 3)
                        context = '\n'.join(lines[start:end])

                        # Find the enclosing function
                        func_match = None
                        for fm in re.finditer(r"function\s+(\w+)", content[:match.start()]):
                            func_match = fm
                        enclosing_func = func_match.group(1) if func_match else "unknown"

                        results.append({
                            "file": relative,
                            "line": line_num,
                            "function": enclosing_func,
                            "context": context,
                        })
                except Exception:
                    continue

        if not results:
            return f"No consumers found for oracle function: {oracle_function}"

        output = f"Oracle Consumer Trace for `{oracle_function}`:\n\n"
        for r in results[:20]:
            output += f"### {r['file']}:{r['line']} (in {r['function']})\n"
            output += f"```\n{r['context']}\n```\n\n"

        return output

    async def _check_decimals(self, file_path: str) -> str:
        """Check decimal handling in price calculations."""
        try:
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = self.state.target_path / file_path
            content = full_path.read_text()
        except Exception as e:
            return f"Error: {e}"

        issues = []

        if self.language == Language.SOLIDITY:
            # Check for hardcoded decimals
            if "1e18" in content or "10**18" in content:
                if "decimals()" not in content:
                    issues.append("Hardcoded 18 decimals without checking token.decimals()")

            # Check for division before multiplication (precision loss)
            div_mul_pattern = r"/[^;]*\*"
            import re
            if re.search(div_mul_pattern, content):
                issues.append("Division before multiplication may cause precision loss")

            # Check Chainlink 8 vs 18 decimals
            if "latestRoundData" in content:
                if "1e8" not in content and "10**8" not in content:
                    if "1e18" in content:
                        issues.append("Chainlink feeds typically use 8 decimals, not 18")

        elif self.language == Language.RUST:
            # Check Pyth exponent handling
            if "pyth" in content.lower():
                if "expo" not in content and "exponent" not in content:
                    issues.append("Pyth prices have exponents that must be handled")

        if not issues:
            return "No obvious decimal handling issues found."

        return "Decimal Handling Issues:\n" + "\n".join(f"- {issue}" for issue in issues)

    def _report_finding(self, params: dict) -> str:
        """Report an oracle manipulation finding."""
        title = params["title"]
        severity = params["severity"]
        description = params["description"]
        location = params["location"]
        impact = params.get("impact", "")
        recommendation = params.get("recommendation", "")
        attack_scenario = params.get("attack_scenario", "")

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        full_description = description
        if attack_scenario:
            full_description += f"\n\n**Attack Scenario:**\n{attack_scenario}"

        finding = Finding(
            id=f"ORACLE-{len(self.findings)+1:03d}",
            title=title,
            severity=severity_map.get(severity, Severity.MEDIUM),
            vulnerability_type=VulnerabilityType.ORACLE_MANIPULATION,
            description=full_description,
            contract=location,
            impact=impact,
            recommendation=recommendation,
            confidence=0.85,
            found_by=AgentRole.VULNERABILITY_HUNTER,
        )

        self.findings.append(finding)
        self.state.add_finding(finding)

        return f"Finding reported: [{severity}] {title}"

    def _get_oracle_patterns(self) -> dict[str, str]:
        """Get oracle-related patterns for each language."""
        if self.language == Language.SOLIDITY:
            return {
                "chainlink": r"latestRoundData|AggregatorV3Interface",
                "uniswap_twap": r"observe\s*\(|consult\s*\(|IUniswapV3Pool",
                "uniswap_spot": r"getReserves\s*\(",
                "band": r"getReferenceData|IStdReference",
                "custom_oracle": r"[Oo]racle|[Pp]rice[Ff]eed",
            }
        elif self.language == Language.RUST:
            return {
                "pyth": r"pyth|Price::get|PriceUpdateV2",
                "switchboard": r"switchboard|AggregatorAccountData",
                "custom_oracle": r"oracle|price_feed|PriceFeed",
            }
        elif self.language == Language.MOVE:
            return {
                "pyth": r"pyth::price|PriceInfoObject",
                "switchboard": r"switchboard",
                "custom_oracle": r"PriceFeed|get_price|oracle",
            }
        elif self.language == Language.CAIRO:
            return {
                "pragma": r"pragma|IPragma|get_data_median",
                "custom_oracle": r"oracle|price|PriceFeed",
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
