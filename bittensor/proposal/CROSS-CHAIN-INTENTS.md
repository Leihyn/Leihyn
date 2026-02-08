# PathFinder: Cross-Chain Intent Resolution Subnet

## The Problem

A user wants to move $50,000 from ETH on Ethereum to USDC on Arbitrum. They open their favorite bridge, get quoted 0.3% slippage, and hit "swap."

Twenty minutes later, they receive $49,100. The bridge took a detour through a low-liquidity pool, MEV bots sandwiched the trade, and the user paid $400 more than necessary.

This happens every day, billions of times. Cross-chain execution is broken not because the technology doesn't exist, but because **no one is incentivized to find the optimal path**.

Bridges optimize for their own liquidity. Aggregators take kickbacks. Solvers front-run. The user always loses.

---

## The Solution

**PathFinder** is a Bittensor subnet where miners compete to produce the most accurate cross-chain execution routes, and validators verify their predictions against actual on-chain outcomes.

Miners who consistently find better paths earn more TAO. Miners who quote phantom liquidity or inflate estimates get slashed. The result: a decentralized network that surfaces the true optimal route for any cross-chain intent.

---

## 1. Incentive & Mechanism Design

### 1.1 Emission and Reward Logic

PathFinder follows Bittensor's standard emission split:

| Recipient | Share | Purpose |
|-----------|-------|---------|
| Miners | 41% | Reward accurate routing intelligence |
| Validators | 41% | Reward honest evaluation |
| Subnet Creator | 18% | Subnet development and maintenance |

**Reward calculation per miner:**

```
miner_reward = (miner_score / total_scores) * miner_emission_pool
```

Where `miner_score` is computed by validators based on prediction accuracy (detailed in Section 3).

### 1.2 Incentive Alignment

**Why miners are motivated:**
- **Direct TAO rewards:** More accurate predictions = higher share of emissions
- **Compounding advantage:** Miners who develop better routing algorithms maintain edge
- **Low barrier to entry:** No specialized hardware required, just data access and optimization skills

**Why validators are motivated:**
- **Yuma Consensus rewards:** Validators who score accurately relative to ground truth earn more
- **Stake-weighted influence:** Larger validators have more say in consensus, attracting delegators
- **Penalty avoidance:** Inconsistent scoring relative to consensus reduces validator rewards

### 1.3 Anti-Gaming Mechanisms

**Problem: Miners quoting unrealistic routes**

A miner could claim a route with 0.01% slippage that doesn't actually exist, hoping validators don't check.

**Solution: Execution Verification**

A percentage of miner-provided routes are actually executed by validators (or execution partners). Routes that fail verification or diverge significantly from quotes result in score penalties.

```
if (actual_slippage - quoted_slippage) > tolerance:
    score_penalty = (divergence / quoted_slippage) * penalty_weight
```

**Problem: Miners copying each other**

Miners could simply copy successful miners' routes.

**Solution: Commit-Reveal + Timestamps**

1. Miners commit a hash of their route before the reveal period
2. Routes are revealed and scored
3. Identical routes submitted after the first are penalized
4. Earlier submissions (by timestamp) break ties

**Problem: Validators colluding with miners**

Validators could always score their affiliated miners highly.

**Solution: Yuma Consensus + Ground Truth**

- Validator scores are weighted by agreement with consensus
- A subset of routes are verified against actual execution (ground truth)
- Validators who diverge from ground truth lose consensus weight

### 1.4 Proof of Intelligence

**Why this qualifies as genuine proof of intelligence:**

Finding optimal cross-chain routes requires:

1. **Real-time data access:** Liquidity across 100+ DEXs, bridges, and aggregators
2. **Graph optimization:** Pathfinding through thousands of possible routes
3. **Market prediction:** Anticipating slippage, gas costs, and execution likelihood
4. **Cross-chain coordination:** Understanding bridge latency, finality, and risks

This cannot be faked with random outputs. A random route generator would produce obviously suboptimal paths that validators would score poorly. Only miners who invest in data infrastructure and optimization algorithms can consistently win.

**Comparison to SN10 (Sturdy):**

| Aspect | SN10 (Yield) | PathFinder (Routing) |
|--------|--------------|---------------------|
| Miner task | Optimize DeFi yield allocations | Optimize cross-chain routes |
| Ground truth | Actual yield performance | Actual execution quality |
| Measurability | APY, drawdown | Slippage, fees, success rate |
| Intelligence required | Portfolio optimization | Graph pathfinding + market prediction |

### 1.5 High-Level Algorithm

```
EVERY EVALUATION EPOCH (configurable, e.g., 30 minutes):

1. TASK ASSIGNMENT
   │
   ├── Validator selects/generates intent batch
   │   Intent = { source_chain, source_token, dest_chain, dest_token, amount }
   │
   └── Intents broadcast to all registered miners

2. MINER SUBMISSION (within submission window)
   │
   ├── Miners compute optimal routes for each intent
   │   Route = { path[], bridges[], dexes[], estimated_output, estimated_gas, confidence }
   │
   ├── Miners submit commitment hash: H(route || salt)
   │
   └── After commitment deadline, miners reveal full routes

3. VALIDATION
   │
   ├── Validators verify route feasibility (liquidity exists, paths valid)
   │
   ├── Validators compare routes across miners
   │   - Rank by estimated_output (higher = better)
   │   - Verify gas estimates are realistic
   │
   └── (Sampling) Execute subset of top routes to verify accuracy

4. SCORING
   │
   ├── Base score = f(estimated_output_rank, gas_efficiency, confidence_calibration)
   │
   ├── Execution bonus/penalty (for sampled routes):
   │   bonus = actual_output > estimated_output ? +weight : -weight
   │
   └── Final score = base_score + execution_adjustment - gaming_penalties

5. REWARD ALLOCATION
   │
   ├── Yuma Consensus aggregates validator scores
   │
   ├── Miner rewards distributed proportional to final scores
   │
   └── Validator rewards based on consensus agreement
```

---

## 2. Miner Design

### 2.1 Miner Tasks

Miners are responsible for:

1. **Maintaining liquidity data:** Index liquidity across chains, DEXs, and bridges
2. **Computing optimal routes:** Given an intent, find the path that maximizes output
3. **Estimating execution quality:** Predict slippage, gas costs, and success probability
4. **Submitting commitments:** Prevent front-running via commit-reveal

### 2.2 Input/Output Format

**Input (Intent):**

```json
{
  "intent_id": "0x1234...abcd",
  "source": {
    "chain_id": 1,
    "token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "amount": "50000000000000000000"
  },
  "destination": {
    "chain_id": 42161,
    "token": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
  },
  "constraints": {
    "max_slippage_bps": 100,
    "max_gas_usd": 50,
    "deadline_seconds": 3600
  }
}
```

**Output (Route):**

```json
{
  "intent_id": "0x1234...abcd",
  "miner_id": "5F3sa...",
  "route": {
    "steps": [
      {
        "type": "swap",
        "chain_id": 1,
        "protocol": "uniswap_v3",
        "pool": "0x8ad5...",
        "input_token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "output_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "estimated_output": "89500000000"
      },
      {
        "type": "bridge",
        "protocol": "stargate",
        "source_chain": 1,
        "dest_chain": 42161,
        "input_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "output_token": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        "estimated_output": "89350000000"
      }
    ],
    "total_estimated_output": "89350000000",
    "total_gas_estimate_usd": "12.50",
    "estimated_duration_seconds": 180,
    "confidence_score": 0.92
  },
  "timestamp": 1738780800,
  "commitment_hash": "0xabcd..."
}
```

### 2.3 Performance Dimensions

| Dimension | Weight | Measurement | Rationale |
|-----------|--------|-------------|-----------|
| **Output Quality** | 50% | `estimated_output / best_estimated_output` | Primary optimization target |
| **Accuracy** | 25% | `1 - abs(actual - estimated) / estimated` | Penalize over-promising |
| **Gas Efficiency** | 15% | `best_gas / estimated_gas` | Prefer cheaper routes |
| **Confidence Calibration** | 10% | Brier score of confidence vs. success | Reward honest uncertainty |

**Why these weights:**
- **Output Quality (50%):** The user's primary concern is maximizing what they receive
- **Accuracy (25%):** Prevents gaming via unrealistic quotes
- **Gas Efficiency (15%):** Important but secondary to output
- **Confidence (10%):** Encourages miners to be honest about uncertainty

---

## 3. Validator Design

### 3.1 Scoring Methodology

Validators evaluate miner submissions in three phases:

**Phase 1: Feasibility Check (Binary)**

```python
def check_feasibility(route):
    for step in route.steps:
        if step.type == "swap":
            if not verify_pool_exists(step.pool):
                return False
            if not verify_liquidity_sufficient(step.pool, step.input_amount):
                return False
        elif step.type == "bridge":
            if not verify_bridge_active(step.protocol, step.source_chain, step.dest_chain):
                return False
    return True
```

Routes that fail feasibility check receive score = 0.

**Phase 2: Comparative Ranking**

For each intent, validators rank all feasible routes:

```python
def rank_routes(routes):
    # Sort by estimated output (descending)
    sorted_routes = sorted(routes, key=lambda r: r.total_estimated_output, reverse=True)

    # Assign rank scores
    for i, route in enumerate(sorted_routes):
        route.rank_score = 1.0 - (i / len(sorted_routes))

    return sorted_routes
```

**Phase 3: Execution Verification (Sampled)**

Validators (or execution partners) execute a random sample of top-ranked routes:

```python
def verify_execution(route, sample_rate=0.05):
    if random.random() > sample_rate:
        return None  # Not sampled

    actual_output = execute_route(route)
    divergence = abs(actual_output - route.estimated_output) / route.estimated_output

    if divergence < 0.02:  # Within 2%
        return +0.1  # Accuracy bonus
    elif divergence < 0.05:
        return 0  # Neutral
    else:
        return -0.2 * divergence  # Penalty proportional to divergence
```

**Final Score Calculation:**

```python
def calculate_final_score(route, execution_result):
    base_score = (
        route.rank_score * 0.50 +                    # Output quality
        route.gas_efficiency_score * 0.15 +          # Gas efficiency
        route.confidence_calibration * 0.10          # Confidence
    )

    if execution_result is not None:
        accuracy_score = 0.25 * (1 - execution_result.divergence)
        base_score += accuracy_score + execution_result.bonus
    else:
        # Estimate accuracy from historical data for this miner
        accuracy_score = 0.25 * miner_historical_accuracy
        base_score += accuracy_score

    return base_score
```

### 3.2 Evaluation Cadence

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Epoch length | 30 minutes | Balances freshness with gas costs |
| Intents per epoch | 50-100 | Sufficient sample size |
| Submission window | 5 minutes | Time for computation |
| Reveal window | 2 minutes | Prevent last-second gaming |
| Execution sample rate | 5% | Balance verification cost vs. accuracy |

**Why 30-minute epochs:**

Unlike real-time intent solvers (CoW, 1inch), PathFinder optimizes for **accuracy over speed**. Many cross-chain intents (large transfers, treasury operations, yield rebalancing) don't require sub-second execution. A 30-minute epoch allows:

1. Miners to compute thorough optimizations
2. Validators to verify feasibility
3. Execution sampling without prohibitive costs
4. Alignment with Bittensor's ~6-minute block time

### 3.3 Validator Incentive Alignment

**Problem:** Validators could score arbitrarily.

**Solution 1: Yuma Consensus**

Validator scores are weighted by agreement with other validators:

```
validator_weight = stake * consensus_agreement_score
```

Validators who deviate from consensus lose weight and earn fewer rewards.

**Solution 2: Ground Truth Anchoring**

A subset of routes are executed, providing objective ground truth. Validators whose scores diverge from execution results lose consensus weight.

**Solution 3: Stake-at-Risk**

Validators must stake TAO. Consistent deviation from consensus or ground truth results in stake slashing.

---

## 4. Business Logic & Market Rationale

### 4.1 Problem Statement

Cross-chain execution is a $50B+ annual market with fundamental inefficiencies:

**User pain points:**
- **Opaque pricing:** Users can't compare routes across bridges
- **MEV extraction:** Sandwich attacks cost users ~$500M annually
- **Failed transactions:** ~5% of cross-chain txs fail due to liquidity issues
- **Hidden fees:** Bridges and aggregators take undisclosed spreads

**Why current solutions fail:**
- **Aggregators (1inch, Li.Fi):** Optimize for their integrated protocols, not users
- **Bridges (Stargate, Across):** Only offer their own liquidity
- **Solvers (CoW Protocol):** Centralized order flow = conflict of interest

**The root cause:** No one is economically incentivized to find the true optimal route.

### 4.2 Competitive Landscape

**Within Bittensor:**

| Subnet | Focus | Overlap | Differentiation |
|--------|-------|---------|-----------------|
| SN10 (Sturdy) | Yield optimization | Both optimize DeFi outcomes | PathFinder = cross-chain routing, not allocation |
| SN106 (VoidAI) | Cross-chain liquidity | Both cross-chain | VoidAI = LP provisioning, PathFinder = routing intelligence |

**Outside Bittensor:**

| Competitor | Strengths | Weaknesses | PathFinder Advantage |
|------------|-----------|------------|---------------------|
| CoW Protocol | Large order flow | Centralized solvers | Decentralized verification |
| 1inch | Wide integration | Kickbacks from routes | No conflicts of interest |
| Li.Fi | Multi-bridge | Single provider | Competitive route discovery |
| Across | Fast bridging | Own liquidity only | Protocol-agnostic |

### 4.3 Why Bittensor?

**1. Decentralized Incentives**

Bittensor's emission model ensures miners are paid for accuracy, not order flow. There's no central party extracting MEV.

**2. Permissionless Competition**

Anyone can run a miner. This drives innovation in routing algorithms that centralized solvers can't match.

**3. Objective Verification**

Unlike subjective AI tasks, route quality is objectively measurable via on-chain execution.

**4. Network Effects**

As more miners join, route coverage increases. More validators = more reliable verification. TAO stakers = more capital securing the network.

### 4.4 Path to Sustainability

**Revenue Model:**

| Stream | Description | Timeline |
|--------|-------------|----------|
| TAO emissions | Primary revenue, proportional to subnet performance | Day 1 |
| Execution fees | Optional fee on routes executed via PathFinder | Month 3+ |
| API access | Premium access to routing intelligence | Month 6+ |
| Protocol integrations | B2B deals with wallets/aggregators | Month 12+ |

**Long-term adoption thesis:**

1. **Phase 1 (0-6 months):** Prove route quality exceeds alternatives via public benchmarks
2. **Phase 2 (6-12 months):** Integrate with wallets (MetaMask, Rainbow) as routing backend
3. **Phase 3 (12-24 months):** Become default cross-chain routing layer for DeFi protocols

**Sustainability metric:** PathFinder is sustainable when:
```
(TAO emissions * TAO price) + (execution fees) > (infrastructure costs + development)
```

Current SN10 (Sturdy) demonstrates this is achievable for DeFi-focused subnets.

---

## 5. Go-To-Market Strategy

### 5.1 Initial Target Users

| Segment | Use Case | Volume | Why They Care |
|---------|----------|--------|---------------|
| **Treasury operations** | DAO rebalancing, payroll | $10M-$100M/mo | Minimize slippage on large txs |
| **Yield farmers** | Cross-chain yield moves | $1M-$10M/mo | Speed + cost for frequent moves |
| **Protocol treasuries** | Liquidity deployment | $50M-$500M/mo | Fiduciary duty to minimize loss |
| **Aggregators** | Backend routing | $1B+/mo | Better routes = better UX |

### 5.2 Distribution Channels

**Direct (B2C):**
- PathFinder webapp for individual users
- Discord/Telegram bot for quick quotes
- Browser extension for cross-chain comparisons

**Indirect (B2B):**
- API for wallet integrations
- SDK for protocol developers
- Partnerships with existing aggregators

**Community:**
- Bittensor Discord presence
- DeFi Twitter engagement
- Educational content on cross-chain optimization

### 5.3 Bootstrapping Strategy

**For miners:**

| Incentive | Description | Timeline |
|-----------|-------------|----------|
| Early miner bonus | 1.5x scoring weight for first 30 days | Launch |
| Data partnerships | Free access to liquidity data APIs | Launch |
| Reference implementation | Open-source baseline miner | Launch |
| Miner documentation | Comprehensive guides + examples | Launch |

**For validators:**

| Incentive | Description | Timeline |
|-----------|-------------|----------|
| Validator grants | TAO grants for early validators | Launch |
| Execution partnerships | Subsidized execution verification | Launch |
| Validator toolkit | Scoring infrastructure + monitoring | Launch |

**For users:**

| Incentive | Description | Timeline |
|-----------|-------------|----------|
| Best price guarantee | Refund if better route found elsewhere | Month 1 |
| Execution tracking | Transparent route monitoring | Month 1 |
| Community rewards | TAO rewards for feedback | Month 1-3 |

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USERS / INTEGRATORS                      │
│  (Wallets, Aggregators, Protocols, Direct Users)                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Submit Intents
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        PATHFINDER SUBNET                         │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │   VALIDATORS  │◀───│    BITTENSOR  │───▶│    MINERS     │   │
│  │               │    │    NETWORK    │    │               │   │
│  │ • Score routes│    │               │    │ • Index liq.  │   │
│  │ • Verify exec │    │ • Yuma        │    │ • Compute     │   │
│  │ • Rank miners │    │   Consensus   │    │   routes      │   │
│  │               │    │ • Emissions   │    │ • Submit      │   │
│  └───────────────┘    └───────────────┘    └───────────────┘   │
│           │                   │                    │            │
│           │                   │                    │            │
│           ▼                   ▼                    ▼            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   DATA LAYER                             │   │
│  │  • Liquidity across chains (DEXs, bridges)               │   │
│  │  • Gas prices and network conditions                     │   │
│  │  • Historical execution data                             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Execute Routes
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EXTERNAL CHAINS                             │
│  Ethereum │ Arbitrum │ Optimism │ Base │ Polygon │ Solana │ ... │
└─────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: Supported Chains and Protocols (Initial)

**Chains (Phase 1):**
- Ethereum Mainnet
- Arbitrum One
- Optimism
- Base
- Polygon PoS

**DEXs:**
- Uniswap V3/V4
- Curve
- Balancer
- SushiSwap
- GMX (for perpetuals routing)

**Bridges:**
- Stargate
- Across
- Hop
- Synapse
- Connext

**Aggregators (for comparison):**
- 1inch
- 0x
- Paraswap

---

## Appendix B: Risk Factors

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Low miner participation | Medium | High | Early miner incentives, reference implementation |
| Execution verification costs | Medium | Medium | Sampling rate tuning, execution partnerships |
| Bridge failures | Low | High | Multi-bridge routes, failure detection |
| MEV on verification txs | Low | Medium | Private mempools, MEV protection |
| Regulatory uncertainty | Low | Medium | No custody, information-only service |

---

## Appendix C: Team

[To be filled based on your actual team/background]

**Relevant Experience:**
- Cross-chain system development (Cybria Bridge, OmniSwap)
- DeFi protocol integration (Aave, Uniswap, Curve, GMX)
- MEV research and protection (Uniswap V4 hooks)
- Privacy and stealth address systems

---

## Summary

PathFinder brings decentralized, incentive-aligned intelligence to cross-chain execution. By rewarding miners for accuracy and punishing gaming, we create a network that consistently surfaces better routes than centralized alternatives.

**Key differentiators:**
1. **No conflicts of interest:** Miners are paid for accuracy, not order flow
2. **Permissionless competition:** Anyone can run a miner with better algorithms
3. **Objective verification:** Route quality is measurable via on-chain execution
4. **Bittensor alignment:** Fits the "proof of intelligence" thesis perfectly

**Why now:**
- Cross-chain volume is exploding (10x growth in 2 years)
- Current solutions have fundamental conflicts of interest
- Bittensor provides the ideal incentive infrastructure
- dTAO makes new subnets viable without bootstrap problems
