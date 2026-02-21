# Portfolio Improvement: Technical Writing & Projects

**Goal:** Build verifiable proof of production-ready blockchain engineering skills

---

## Technical Writing

### High-Impact Articles (Leverage Unique Experience)

| Article | Why It Works | Status |
|---------|--------------|--------|
| "Building Dynamic Fee Hooks: Lessons from UHI7" | Few UHI graduates have written about this publicly. Positions you as hooks expert. | [ ] |
| "Stealth Addresses Deep Dive: Implementing DKSAP" | You built this in OmniSwap. Original technical content on a hot topic. | [ ] |
| "Noir vs Circom: A Practical Comparison" | You used Noir in Nocturne. Direct experience > theory. | [ ] |
| "Integrating Aave V3 in Production: What the Docs Don't Tell You" | From your DeFiConnect work. Practical insights are rare. | [ ] |
| "Privacy Pools with Selective Disclosure: The Compliance-Privacy Balance" | Directly relevant to Midnight's approach. Shows domain expertise. | [ ] |

### Quick Wins (Easier to Write, Still Valuable)

| Article | Notes | Status |
|---------|-------|--------|
| "5 Gas Optimization Patterns I Use Daily" | Code snippets, immediate value | [ ] |
| "My Audit Checklist for DeFi Protocols" | From your knowledge base | [ ] |
| "Cross-Chain Privacy: Breaking Transaction Correlation" | From OmniSwap architecture | [ ] |

### Publishing Strategy

| Platform | Best For |
|----------|----------|
| **Mirror** | Web3 essays, ZK/privacy content |
| **Dev.to** | Code-heavy tutorials |
| **Twitter Threads** | Quick insights, build audience |

---

## Projects to Build

### Tier 1: Deploy What You Have (Highest Priority)

| Project | Action | Impact | Status |
|---------|--------|--------|--------|
| **Sentiment Hook** | Deploy to Base mainnet, write deployment post | Verifiable on-chain proof | [ ] |
| **Nocturne** | Deploy to Solana devnet first, document thoroughly | Shows ZK production readiness | [ ] |

### Tier 2: New Projects (Fill Market Gaps)

| Project | Description | Why Build It | Status |
|---------|-------------|--------------|--------|
| **uniswap-v4-hook-template** | Foundry template with BaseHook, 3 example hooks, tests, deployment scripts | Few good templates exist. UHI connection gives credibility. | [ ] |
| **aave-position-manager** | Contract that manages Aave positions (auto-repay, health factor alerts) | Practical DeFi tooling from work experience. Deployable. | [ ] |
| **zk-compliance-demo** | Minimal Noir circuit showing selective disclosure (prove balance > X without revealing exact amount) | Directly relevant to Midnight. Showcases ZK skills. | [ ] |
| **privacy-score-sdk** | TypeScript SDK that scores wallet privacy (from OmniShield logic) | Unique, useful, leverages existing work. | [ ] |

### Tier 2b: Perps & Trading Infrastructure (Gap: No Trading Systems Experience)

These projects fill the perps/trading infrastructure gap needed for roles like Jupiter, Drift, or any trading-focused protocol.

| Project | Description | Why Build It | Status |
|---------|-------------|--------------|--------|
| **solana-perps-terminal** | React trading frontend on top of Jupiter Perps. Real-time PnL, position management, order placement, funding rate display, liquidation price calculator. TradingView charts integration. | Directly builds the thing Jupiter is hiring for. Shows you can work with their stack. Ship first. | [ ] |
| **perps-engine-minimal** | Minimal perpetual futures contract from scratch (Anchor/Rust). Margin accounts, position open/close, mark vs index price, funding rate calculation, basic liquidation logic. | Proves you understand the math behind perps, not just the APIs. Deep domain signal. | [ ] |
| **perps-liquidation-bot** | Liquidation bot for Jupiter Perps or Drift. Monitor undercollateralized positions, calculate liquidation thresholds, execute on-chain. WebSocket price feeds, keeper infrastructure. | Forces you to understand funding rates, margin mechanics, and oracle pricing at production level. Interacts with real contracts. | [ ] |
| **funding-rate-arb-dashboard** | Track funding rates across Jupiter, Drift, Mango, and CEXes (Binance, Bybit). Surface arbitrage opportunities when rates diverge. Historical charts, alerts, backtesting engine. | Shows you understand the mechanics that drive perps markets. Useful tool, strong portfolio piece. | [ ] |

**Recommended build order:** solana-perps-terminal (1-2 weeks) → perps-engine-minimal (2-3 weeks). Together they tell the story: "I understand how perps engines work AND I can build production UIs on top of them."

### Tier 3: OSS Contributions (Free Credibility)

| Repo | Contribution Idea | Your Edge | Status |
|------|-------------------|-----------|--------|
| `Uniswap/v4-periphery` | Add hook integration examples or tests | UHI7 graduate | [ ] |
| `foundry-rs/foundry` | Improve error messages or add forge script examples | Heavy user | [ ] |
| `noir-lang/noir` | Add examples or fix docs | Nocturne experience | [ ] |

---

## 90-Day Action Plan

### Days 1-30

| Task | Category | Status |
|------|----------|--------|
| Deploy Sentiment Hook to Base mainnet | Deployment | [ ] |
| Write "Building Dynamic Fee Hooks" article | Writing | [ ] |
| Create `uniswap-v4-hook-template` repo | Project | [ ] |
| Set up Twitter, post 3x/week | Social | [ ] |

### Days 30-60

| Task | Category | Status |
|------|----------|--------|
| Build `zk-compliance-demo` | Project | [ ] |
| Write "Privacy Pools with Selective Disclosure" article | Writing | [ ] |
| First OSS contribution (Uniswap or Noir) | OSS | [ ] |
| Complete Damn Vulnerable DeFi | Security | [ ] |

### Days 60-90

| Task | Category | Status |
|------|----------|--------|
| Create `privacy-score-sdk` from OmniShield | Project | [ ] |
| Enter first Code4rena contest | Security | [ ] |
| Write "Integrating Aave V3 in Production" article | Writing | [ ] |
| Second OSS contribution | OSS | [ ] |
| Build `solana-perps-terminal` (Jupiter Perps frontend) | Perps | [ ] |
| Build `perps-engine-minimal` (Anchor contract) | Perps | [ ] |
| Write "Building a Perpetual Futures Engine from Scratch" article | Writing | [ ] |

---

## Success Metrics

### Writing
- [ ] 3 articles published
- [ ] 1 article with 100+ views
- [ ] Articles linked from GitHub profile

### Projects
- [ ] 1 mainnet deployment (Sentiment Hook)
- [ ] 2 new repos with proper documentation
- [ ] First external star or fork

### OSS
- [ ] First PR merged to major protocol
- [ ] Name in contributor list

### Security
- [ ] Damn Vulnerable DeFi completed
- [ ] 1 contest participated
- [ ] 1 valid finding submitted

---

## Weekly Review

Every Sunday, answer:
1. What did I ship this week?
2. What content did I create?
3. What's blocking me?
4. What's the #1 priority for next week?

---

*Created: February 2026*
*Review weekly, update status checkboxes*
