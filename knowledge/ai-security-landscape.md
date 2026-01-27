# AI in Web3 Security - Landscape & Methodology

> Key insights from SavantChat, Kritt.ai, and Nethermind Security on AI-assisted vulnerability research.

---

## 1. AI-Assisted Hack Analysis (SavantChat - Jan 2026)

### Case Study: $3.2M WBTC Hack

- **Date**: January 25, 2026 (Block 24313234)
- **Stolen**: 36.9 WBTC (~$3.2M)
- **Root Cause**: Arbitrary external call `address(user_input).call(user_data)` without validation
- **Unique**: Unverified contract code recovered using AI decompilation

### Vulnerability Pattern: Arbitrary External Call

The victim contract (Multi-DEX Liquidity Manager) had an internal swap function where both the called address and calldata were fully user-controlled:

```
// VULNERABILITY: No validation on router address or calldata
address(params.router).call(params.data)
```

**Exploit**: Attacker passed `router = WBTC address`, `data = transferFrom(victim, hacker, amount)`. Since the victim had approved the contract, the call succeeded.

### AI Decompilation Methodology

1. **Replay** - Fork mainnet, replay attack TX with Foundry
2. **Decompile** - Load bytecode into Dedaub Decompiler
3. **Recover** - SWE agent converts decompiled pseudocode to Solidity
   - Simple to complex (constructor → view → complex functions)
   - Each method covered by unit + fuzz tests
   - Compare test results on original bytecode vs recovered code
4. **PoC** - Verify exploit works on both bytecode and recovered Solidity

### Key Insight

> "Security through obscurity no longer works. AI decompilation is fully automated, without human involvement. Attackers can scan unverified contracts at industrial scale."

| Factor | Before AI | With AI |
|--------|-----------|---------|
| Decompilation time | Days/weeks | Hours |
| Required expertise | High | Minimal |
| Human involvement | Constant | Optional |
| Cost | High | Low |

### Attack Preparation Signs

- Contract obfuscation (dynamic parameter loading)
- MEV-bot protection (state checks, reverts on changes)
- SELFDESTRUCT after execution
- Precise targeting (knew which users had large approvals)

---

## 2. Agentic Zero-Day Research (Kritt.ai)

### Architecture: Multi-Step Verification Pipeline

The system mirrors experienced security researchers:

1. **Identify** - Suspicious behavior or invariant violations
2. **Prove reachability** - Call paths, entrypoints, conditions
3. **Prove controllability** - Attacker influence on relevant state/data
4. **Determine impact** - Theft, DoS, privilege escalation
5. **Demonstrate** - PoC, simulation, minimized conditions
6. **Report** - Explanation, repro, remediation

### Results

- 10+ bugs disclosed in major blockchain projects
- Largest finding: ~$500M potential theft, $250K bounty (largest AI-assisted disclosure reported)
- Ranked #1 on Immunefi (90-day leaderboard)

### Core Principles

#### Harnesses Beat Vibes

> "Progress didn't come from clever prompts. It came from harnesses."

A harness forces the agent to:
- Generate hypotheses explicitly (not implicitly)
- Collect evidence before escalating confidence
- Use deterministic tools when possible
- Fail fast and prune dead ends
- Produce artifacts a reviewer can trust

#### CodeQL as "Determinism Injection"

> "Make as much as possible deterministic, reserve model reasoning for what can't be deterministic."

CodeQL answers reliably:
- "Does taint from this input reach that sink?"
- "Which call paths lead here?"
- "Where is this state mutated, and under what guards?"
- "Are there patterns of missing auth checks / unchecked returns / unsafe casts?"

#### Compute-Optimal Adaptive Scanning

Not every signal deserves the same compute spend:
- Some repos need shallow triage
- Others need deep multi-tool investigation
- System allocates compute adaptively based on difficulty and promise

#### SOTA-First Model Selection

Best results from frontier models:
- **Opus 4.5** via claude-code
- **GPT-5.2** (Codex variant outperformed generalist for agentic work)
- Native toolchains aligned with model's learned operating style

### Cyber vs Coding Tooling

| Coding Tools Optimize For | Cyber Tools Optimize For |
|--------------------------|-------------------------|
| Editing/applying patches | Tracing flows across trust boundaries |
| Running tests | Proving reachability + controllability |
| Refactoring and shipping | Reasoning about invariants |
| | Validating exploitability |

---

## 3. AI Arms Race in Web3 Security (Nethermind)

### Threat Model Shift

AI has lowered the technical barrier to entry for attackers:
- Automated large-scale reconnaissance across thousands of contracts
- Contagion effect: one vulnerability pattern scanned across ecosystem
- Autonomous exploit generation and simulation
- Parallelized multi-protocol attacks

### Security by Design

Security must be an adversarial process running parallel with development:

1. **Human experts** define constraints, invariants, failure conditions
2. **AI systems** generate millions of inputs via RL + coverage-guided fuzzing
3. **Human-in-the-loop** validates findings and refines scope

### AI-Augmented Audit Process

1. **Context building** - Researchers collaborate with devs, extract invariants
2. **Constraint translation** - Business logic → machine-readable constraints
3. **Automated simulation** - AI generates adversarial simulations, PoCs, fuzz tests
4. **Real-time monitoring** - Post-deployment AI monitors mainnet activity

### Real-Time Defense

- Map account relationships, identify sybil clusters
- Detect attacker-funded wallets before interaction
- Automatically intercept/block flagged transactions before execution
- Shift from reactive analysis to preemptive control

### Key Insight

> "Advantage will belong to the side that best aligns human insight with machine intelligence."

---

## Sentinel Integration Points

These research insights map to Sentinel modules:

| Concept | Sentinel Module | Status |
|---------|----------------|--------|
| Arbitrary call detection | `bug_detection` (SolidityBugDetector) | Existing |
| Entry point mapping | `skills/entry_point_analyzer` | Existing |
| CodeQL determinism injection | `skills/codeql_integration` | Existing |
| Harness-based verification | `skills/audit_workflow` | Existing |
| Invariant identification | `skills/property_based_testing` | Existing |
| AI decompilation workflow | `skills/decompilation_workflow` | New |
| Agentic harness pipeline | `skills/agentic_harness` | New |
| Token approval scanning | `skills/solcurity_checker` (D-07) | Existing |
| Taint analysis | `core/advanced/slither_deep` | Existing |
| Severity classification | `core/advanced/severity_predictor` | Existing |

---

## References

- [SavantChat - $3.2M Hack Analysis](https://savant.chat) (Jan 2026)
- [Kritt.ai - Agentic Zero-Day Research](https://kritt.ai) (Jan 2026)
- [Nethermind - AI Reshaping Web3 Security](https://nethermind.io/blog) (2026)
- [PAC-Reasoning](https://arxiv.org/abs/2412.02441)
- [Scaling Test-Time Compute](https://arxiv.org/abs/2408.03314)
