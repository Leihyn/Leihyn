# Subnet Brainstorming

Your background: DeFi integration (Aave, Uniswap, Curve, GMX), ZK/privacy (Nocturne, stealth addresses), Uniswap V4 hooks, cross-chain systems.

---

## Idea 1: DeFi Risk Intelligence Subnet

**One-liner:** Miners compete to produce the most accurate DeFi risk assessments and exploit detection.

### The Problem
A user deposits $100K into a new DeFi protocol. 72 hours later, the protocol is exploited. The warning signs were there - unusual contract behavior, abnormal fund flows, audit issues - but no one aggregated and surfaced them in time.

### Why It Fits Bittensor
- **Genuine proof of intelligence:** Miners must analyze complex on-chain data, smart contract code, and patterns to produce risk scores
- **Objectively measurable:** Risk predictions can be validated against actual exploits/rugpulls
- **High value:** DeFi security is a multi-billion dollar problem

### Miner Tasks
- Analyze smart contracts for vulnerabilities
- Monitor on-chain activity for suspicious patterns
- Produce risk scores for protocols/pools
- Generate exploit predictions

### Validator Design
- Cross-reference miner outputs with ground truth (actual exploits)
- Use delayed validation - check if risk predictions come true
- Score based on prediction accuracy, speed of detection

### Your Edge
- Deep understanding of DeFi protocols (Aave, Uniswap, Curve, GMX)
- Knowledge of common vulnerabilities from audit experience
- Can design realistic evaluation criteria

### Concerns
- Delayed ground truth makes short-term validation hard
- Risk of miners gaming with obvious-only predictions

---

## Idea 2: ZK Proof Generation Subnet

**One-liner:** Miners compete to generate ZK proofs fastest and cheapest.

### The Problem
ZK proofs are computationally expensive. A single proof can cost $0.10-$10+ and take minutes to generate. This creates centralization risk - only well-resourced provers can participate.

### Why It Fits Bittensor
- **Genuine proof of effort:** ZK proof generation is computationally intensive and verifiable
- **Objectively measurable:** Proof validity is binary (valid or not), speed is measurable
- **Growing demand:** L2s, privacy apps, and ZK rollups need proofs

### Miner Tasks
- Receive witness data
- Generate ZK proofs (Groth16, PLONK, STARK)
- Compete on speed and cost

### Validator Design
- Verify proofs are valid (cheap to verify)
- Score based on: proof validity (binary) + generation time + cost
- No subjective judgment needed

### Your Edge
- ZK background from Nocturne, privacy work
- Understand proof systems and their tradeoffs
- Can design realistic circuits for testing

### Concerns
- Requires specialized hardware (GPUs)
- May favor well-capitalized miners
- Commoditized - hard to differentiate

---

## Idea 3: MEV Detection & Prediction Subnet

**One-liner:** Miners compete to detect and predict MEV opportunities across chains.

### The Problem
MEV (Maximal Extractable Value) extracts $billions from users annually. Arbitrage, sandwiching, and liquidations happen in milliseconds. Users lack visibility into when they're being MEVed.

### Why It Fits Bittensor
- **Genuine proof of intelligence:** Detecting MEV requires understanding complex tx flows
- **Objectively measurable:** Predictions can be validated against actual mempool/block data
- **High value:** MEV protection is a growing market

### Miner Tasks
- Monitor mempools across chains
- Detect sandwich attacks in real-time
- Predict arbitrage opportunities
- Identify liquidation targets

### Validator Design
- Verify predictions against actual blocks
- Score based on: detection accuracy, speed, false positive rate
- Use historical data for evaluation

### Your Edge
- DeFi integration experience (understand how MEV targets protocols)
- Uniswap hooks background (MEV protection hooks)
- Cross-chain experience

### Concerns
- Latency-sensitive - may favor centralized miners
- MEV landscape changes rapidly
- Ethical concerns about "helping" MEV extractors

---

## Idea 4: Smart Contract Audit Subnet

**One-liner:** Miners compete to find vulnerabilities in smart contracts.

### The Problem
Smart contract audits cost $50K-$500K and take weeks. Meanwhile, new contracts deploy daily without review. The demand for security review far exceeds supply.

### Why It Fits Bittensor
- **Genuine proof of intelligence:** Finding real bugs requires deep understanding
- **Objectively measurable:** Bugs are either real or not, severity is classifiable
- **High value:** Exploits cause billions in losses annually

### Miner Tasks
- Analyze submitted contracts
- Identify vulnerabilities (with severity classification)
- Provide fix recommendations
- Compete on accuracy and coverage

### Validator Design
- Seed known-vulnerable contracts (ground truth)
- Cross-reference findings across miners
- Score based on: true positives, false positive rate, severity accuracy
- Weight by bug severity (critical > high > medium > low)

### Your Edge
- Security audit checklist knowledge
- Deep DeFi protocol understanding
- Know common vulnerability patterns

### Concerns
- Hard to evaluate novel findings (no ground truth)
- Quality variance is high
- May produce low-quality, automated outputs

---

## Idea 5: Oracle Data Verification Subnet

**One-liner:** Miners compete to verify and validate off-chain data for DeFi oracles.

### The Problem
Oracles are the Achilles heel of DeFi. Flash loan attacks, price manipulation, and stale data cause millions in losses. Current oracles rely on centralized reputation.

### Why It Fits Bittensor
- **Genuine proof of effort:** Verifying data requires querying multiple sources
- **Objectively measurable:** Data accuracy is checkable against ground truth
- **High value:** Every DeFi protocol depends on oracles

### Miner Tasks
- Aggregate price data from multiple sources
- Detect outliers and manipulation attempts
- Verify off-chain data (RWA prices, sports scores, etc.)
- Produce confidence scores

### Validator Design
- Compare miner outputs to consensus/ground truth
- Score based on: accuracy, speed, outlier detection
- Weight by economic impact of errors

### Your Edge
- Chainlink integration experience
- Understanding of oracle manipulation vectors
- Know how DeFi protocols consume oracle data

### Concerns
- Competing with established oracles (Chainlink, Pyth)
- Data sources may be centralized anyway
- Latency requirements may be challenging

---

## Idea 6: Cross-Chain Intent Resolution Subnet

**One-liner:** Miners compete to find optimal execution paths for cross-chain user intents.

### The Problem
A user wants to swap ETH on Ethereum for USDC on Arbitrum. There are dozens of possible routes: bridges, DEXs, aggregators. Finding the optimal path is computationally expensive and changes by the second.

### Why It Fits Bittensor
- **Genuine proof of intelligence:** Optimal routing requires solving complex optimization
- **Objectively measurable:** Execution quality is measurable (slippage, fees, speed)
- **High value:** Cross-chain is growing rapidly

### Miner Tasks
- Receive user intents (source chain/token → dest chain/token)
- Compute optimal execution paths
- Consider: slippage, gas, bridge fees, latency
- Compete on execution quality

### Validator Design
- Execute a subset of routes to verify quality
- Compare miner quotes to actual execution
- Score based on: quote accuracy, execution quality, speed

### Your Edge
- Cross-chain experience (Cybria Bridge, OmniSwap)
- DeFi integration (understand liquidity sources)
- Uniswap/Curve knowledge for routing

### Concerns
- Latency-sensitive
- Requires significant infrastructure
- Competing with established solvers (CoW, 1inch)

---

## Idea 7: DeFi Strategy Optimization Subnet

**One-liner:** Miners compete to produce the best yield strategies for given constraints.

### The Problem
DeFi yield optimization is complex. A user with $100K wants maximum yield with <5% drawdown risk. Evaluating thousands of strategy combinations across protocols is computationally intensive.

### Why It Fits Bittensor
- **Genuine proof of intelligence:** Strategy optimization requires understanding DeFi deeply
- **Objectively measurable:** Strategy performance is measurable
- **High value:** DeFi users want better yields

### Miner Tasks
- Receive constraint sets (capital, risk tolerance, chains)
- Produce optimal yield strategies
- Include: protocols, allocations, rebalancing triggers
- Compete on risk-adjusted returns

### Validator Design
- Backtest strategies on historical data
- Forward-test with small capital (if feasible)
- Score based on: Sharpe ratio, max drawdown, accuracy of projections

### Your Edge
- Deep knowledge of Aave, Curve, GMX, Uniswap
- Understand yield mechanics (supply rates, LP fees, staking)
- Can design realistic constraints and evaluation

### Concerns
- Backtesting != future performance
- Risk of overfitting
- Regulatory concerns (financial advice)

---

## Comparison Matrix

| Idea | Skill Leverage | Novel for Bittensor | Measurable | Realistic to Build | Market Size |
|------|---------------|---------------------|------------|-------------------|-------------|
| DeFi Risk Intelligence | High | Medium | Medium | Medium | High |
| ZK Proof Generation | High | Medium | High | Hard | Medium |
| MEV Detection | High | Medium | High | Medium | High |
| Smart Contract Audit | High | Low (similar exists) | Medium | Medium | High |
| Oracle Verification | High | Medium | High | Medium | High |
| Cross-Chain Intents | High | High | High | Hard | High |
| DeFi Strategy | High | Medium | Medium | Medium | High |

---

## Recommendation

**Top 3 to explore further:**

1. **DeFi Risk Intelligence** - Unique angle, leverages your full stack, high impact
2. **MEV Detection & Prediction** - Strong measurability, growing market, your hooks background helps
3. **Cross-Chain Intent Resolution** - Novel for Bittensor, leverages your cross-chain experience

**Questions to decide:**
1. Which problem do you feel most passionate about solving?
2. Which has the clearest path to objective validation?
3. Which would you be excited to build in Round II?
