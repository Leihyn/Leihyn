# Sentinel: DeFi Liquidation Intelligence Subnet

## The Problem

A whale deposits $10M into Aave. Market drops 15%. Their health factor hits 1.02.

Liquidators are circling, but timing is everything. Liquidate too early - the position recovers and you wasted gas. Liquidate too late - someone else gets the profit.

Meanwhile, the borrower has no warning. No alert that they're 30 minutes from losing 10% of their collateral to liquidation penalties.

**$2.4 billion** was liquidated across DeFi in 2024. The liquidators who won were the ones who predicted *when* positions would cross the threshold - not just *if*.

This prediction capability exists, but it's locked inside proprietary liquidation bots. There's no decentralized market for liquidation intelligence.

---

## The Solution

**Sentinel** is a Bittensor subnet where miners compete to predict DeFi liquidations before they happen.

Miners analyze on-chain positions, market conditions, and protocol mechanics to forecast:
- Which positions will be liquidated
- When they'll cross the liquidation threshold
- How much will be liquidated

Validators verify predictions against actual liquidation events. Miners who predict accurately earn TAO. Miners who cry wolf get penalized.

**The result:** A decentralized liquidation intelligence layer that serves:
- **Liquidators:** Better timing = more profit
- **Borrowers:** Early warnings to add collateral
- **Protocols:** Risk monitoring and analytics
- **Researchers:** Market behavior data

---

## 1. Incentive & Mechanism Design

### 1.1 Emission and Reward Logic

Sentinel follows Bittensor's standard emission split:

| Recipient | Share | Purpose |
|-----------|-------|---------|
| Miners | 41% | Reward accurate predictions |
| Validators | 41% | Reward honest verification |
| Subnet Creator | 18% | Subnet development |

**Reward calculation:**

```
miner_reward = (miner_score / total_scores) * miner_emission_pool
```

Where `miner_score` is computed from prediction accuracy over the evaluation window.

### 1.2 Incentive Alignment

**Why miners are motivated:**
- **Direct TAO rewards:** More accurate predictions = higher emissions share
- **Compounding edge:** Better models/data sources = sustained advantage
- **Low barrier:** No specialized hardware - just RPC access and analytics

**Why validators are motivated:**
- **Yuma Consensus:** Validators who score accurately earn more
- **Objective ground truth:** Liquidations are on-chain events - no subjectivity
- **Stake protection:** Inaccurate scoring loses consensus weight

### 1.3 Anti-Gaming Mechanisms

**Problem: Predicting obvious liquidations**

A miner could only predict positions already at health factor 1.001 - guaranteed to liquidate but not useful.

**Solution: Prediction Window Requirements**

Predictions must be made with minimum lead time:
- Minimum 1 hour before liquidation event
- Scoring weighted by lead time (earlier = more points)

```
lead_time_multiplier = min(hours_before_event / 6, 2.0)
```

Predicting 6+ hours early gets 2x score. Predicting 1 hour early gets ~0.17x.

**Problem: Predicting everything**

A miner could predict every position will be liquidated, guaranteeing some hits.

**Solution: Precision Penalty**

```
precision = true_positives / (true_positives + false_positives)
final_score = raw_score * precision^2
```

Predicting 100 liquidations when only 10 happen = 10% precision = 1% of raw score.

**Problem: Copying successful miners**

A miner could wait for others' predictions and copy them.

**Solution: Commit-Reveal + Timestamps**

1. Miners commit hash of predictions before reveal
2. Earlier timestamps win ties
3. Identical predictions penalize the later submitter

### 1.4 Proof of Intelligence

**Why this qualifies as genuine proof of intelligence:**

Predicting liquidations requires understanding:

1. **Protocol mechanics:** Liquidation thresholds, penalties, oracle update frequencies
2. **Market dynamics:** Price volatility, correlation between assets
3. **On-chain behavior:** Whale movements, collateral additions, debt repayments
4. **Timing:** When oracles update, when liquidators are active

A random prediction generator would have near-zero precision. Only miners who build sophisticated models can consistently predict liquidations with useful lead time.

**Comparison to existing subnets:**

| Aspect | SN10 (Sturdy) | Sentinel |
|--------|---------------|----------|
| Task | Optimize yield allocation | Predict liquidation events |
| Ground truth | Actual yield performance | Actual liquidation events |
| Measurability | APY, Sharpe ratio | Precision, recall, lead time |
| Intelligence | Portfolio optimization | Event prediction + timing |

### 1.5 High-Level Algorithm

```
EVERY EVALUATION EPOCH (1 hour):

1. POSITION SNAPSHOT
   │
   ├── Validator captures current state of monitored protocols
   │   - Aave V3: All positions with HF < 1.5
   │   - Compound V3: All positions with borrow > 80% of limit
   │   - MakerDAO: All vaults with CR < 200%
   │
   └── Snapshot broadcast to miners with timestamp

2. MINER PREDICTION (within 10-minute window)
   │
   ├── Miners analyze positions and market conditions
   │
   ├── Submit predictions:
   │   Prediction = { position_id, will_liquidate: bool,
   │                  time_window: [min, max], confidence: 0-1 }
   │
   └── Commit hash, then reveal

3. OBSERVATION WINDOW (6 hours)
   │
   └── Network monitors for actual liquidation events

4. VALIDATION
   │
   ├── Match predictions to actual liquidations
   │   - True positive: Predicted liquidation happened in window
   │   - False positive: Predicted but didn't happen
   │   - False negative: Happened but wasn't predicted
   │
   └── Calculate scores per miner

5. SCORING
   │
   ├── Base score = weighted F1 score
   │   precision = TP / (TP + FP)
   │   recall = TP / (TP + FN)
   │   F1 = 2 * (precision * recall) / (precision + recall)
   │
   ├── Lead time bonus = multiplier based on how early prediction was
   │
   ├── Confidence calibration = Brier score
   │
   └── Final score = F1 * lead_time_bonus * calibration_factor

6. REWARD ALLOCATION
   │
   ├── Yuma Consensus aggregates validator scores
   │
   └── TAO distributed proportional to final scores
```

---

## 2. Miner Design

### 2.1 Miner Tasks

Miners are responsible for:

1. **Monitoring positions:** Track health factors across supported protocols
2. **Analyzing market conditions:** Price feeds, volatility, correlation
3. **Building prediction models:** ML, heuristics, or hybrid approaches
4. **Submitting predictions:** With confidence scores and time windows

### 2.2 Input/Output Format

**Input (Position Snapshot from Validator):**

```json
{
  "epoch_id": "2026-02-05-14:00",
  "timestamp": 1738764000,
  "positions": [
    {
      "protocol": "aave_v3",
      "chain": "ethereum",
      "user": "0x1234...abcd",
      "collateral": [
        {"token": "WETH", "amount": "100.5", "usd_value": "250000"}
      ],
      "debt": [
        {"token": "USDC", "amount": "180000", "usd_value": "180000"}
      ],
      "health_factor": "1.25",
      "liquidation_threshold": "0.825"
    },
    // ... more positions
  ],
  "market_data": {
    "eth_price": 2487.50,
    "eth_24h_volatility": 0.045,
    "gas_price_gwei": 25
  }
}
```

**Output (Miner Predictions):**

```json
{
  "epoch_id": "2026-02-05-14:00",
  "miner_id": "5F3sa...",
  "predictions": [
    {
      "position_id": "aave_v3_ethereum_0x1234...abcd",
      "will_liquidate": true,
      "time_window": {
        "earliest": "2026-02-05T16:00:00Z",
        "latest": "2026-02-05T20:00:00Z"
      },
      "predicted_trigger_price": {"ETH": 2150.00},
      "predicted_liquidation_amount_usd": 45000,
      "confidence": 0.75
    },
    {
      "position_id": "aave_v3_ethereum_0x5678...efgh",
      "will_liquidate": false,
      "confidence": 0.90
    }
  ],
  "commitment_hash": "0xabcd...",
  "timestamp": 1738764300
}
```

### 2.3 Performance Dimensions

| Dimension | Weight | Measurement | Rationale |
|-----------|--------|-------------|-----------|
| **Precision** | 35% | TP / (TP + FP) | Don't cry wolf |
| **Recall** | 25% | TP / (TP + FN) | Don't miss liquidations |
| **Lead Time** | 25% | Hours before event | Earlier = more useful |
| **Calibration** | 15% | Brier score on confidence | Honest uncertainty |

**Why these weights:**

- **Precision (35%):** False positives waste user attention and liquidator resources
- **Recall (25%):** Missing liquidations is bad but less harmful than false alarms
- **Lead Time (25%):** The whole point is early warning - obvious predictions aren't valuable
- **Calibration (15%):** Confidence scores should be meaningful

---

## 3. Validator Design

### 3.1 Scoring Methodology

Validators evaluate predictions in three phases:

**Phase 1: Commitment Verification**

```python
def verify_commitment(prediction, commitment_hash, reveal_timestamp):
    expected_hash = keccak256(prediction + miner_salt)
    if expected_hash != commitment_hash:
        return 0  # Invalid commitment
    if reveal_timestamp > commitment_deadline:
        return 0  # Late reveal
    return 1
```

**Phase 2: Outcome Matching (after observation window)**

```python
def match_outcomes(predictions, actual_liquidations):
    results = []
    for pred in predictions:
        position_id = pred.position_id

        # Find if this position was liquidated
        actual = find_liquidation(actual_liquidations, position_id)

        if pred.will_liquidate and actual:
            # True positive - check timing
            if pred.time_window.earliest <= actual.timestamp <= pred.time_window.latest:
                results.append(('TP', pred, actual))
            else:
                results.append(('TP_TIMING_MISS', pred, actual))
        elif pred.will_liquidate and not actual:
            results.append(('FP', pred, None))
        elif not pred.will_liquidate and actual:
            results.append(('FN', pred, actual))
        else:
            results.append(('TN', pred, None))

    return results
```

**Phase 3: Score Calculation**

```python
def calculate_score(results, prediction_timestamp):
    tp = sum(1 for r in results if r[0] == 'TP')
    fp = sum(1 for r in results if r[0] == 'FP')
    fn = sum(1 for r in results if r[0] == 'FN')

    # Precision and recall
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    # F1 score
    if precision + recall > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = 0

    # Lead time bonus (average hours before event for TPs)
    lead_times = []
    for r in results:
        if r[0] == 'TP':
            hours_before = (r[2].timestamp - prediction_timestamp) / 3600
            lead_times.append(hours_before)

    avg_lead_time = mean(lead_times) if lead_times else 0
    lead_time_bonus = min(avg_lead_time / 6, 2.0)  # Cap at 2x for 6+ hours

    # Confidence calibration (Brier score)
    brier = calculate_brier_score(results)
    calibration_factor = 1 - brier  # Lower Brier = better

    # Final score
    final = (
        f1 * 0.60 * lead_time_bonus +  # Precision + Recall weighted by lead time
        calibration_factor * 0.15
    )

    return final
```

### 3.2 Evaluation Cadence

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Epoch length | 1 hour | Frequent enough for timely predictions |
| Prediction window | 10 minutes | Time for miners to analyze |
| Observation window | 6 hours | Enough time for predictions to resolve |
| Overlap | Rolling | New epoch starts while previous observes |

**Timeline visualization:**

```
Hour 0    Hour 1    Hour 2    Hour 3    Hour 4    Hour 5    Hour 6    Hour 7
├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Epoch 1 │         │         │         │         │         │         │
│ Predict │◀─────── Observation Window ─────────▶│ Score   │         │
│         │ Epoch 2 │         │         │         │         │         │
│         │ Predict │◀─────── Observation Window ─────────▶│ Score   │
│         │         │ Epoch 3 │         │         │         │         │
│         │         │ Predict │◀─────── Observation Window ─────────▶│
```

### 3.3 Validator Incentive Alignment

**Objective ground truth eliminates subjectivity:**

Unlike tasks where validators must judge "quality," liquidation events are binary on-chain facts:
- Transaction hash proves liquidation happened
- Block timestamp proves when
- Position ID links to prediction

**Validators simply verify facts, not judge quality.**

**Yuma Consensus handles edge cases:**

If validators disagree on scoring (e.g., different liquidation data sources), Yuma Consensus rewards validators who align with majority.

---

## 4. Business Logic & Market Rationale

### 4.1 Problem Statement

DeFi lending is a **$30B+ market** with structural information asymmetry:

**For borrowers:**
- No warning before liquidation
- Lose 5-15% in liquidation penalties
- Can't monitor positions 24/7

**For liquidators:**
- Timing is everything
- Too early = position recovers, wasted gas
- Too late = someone else profits
- Need predictive edge, not just monitoring

**For protocols:**
- Want healthy liquidation markets
- Bad UX drives users away
- Need risk visibility

**Current solutions:**

| Solution | Problem |
|----------|---------|
| DeFi Saver | Reactive, not predictive |
| Liquidation bots | Proprietary, zero-sum |
| Block explorers | Raw data, no intelligence |
| Risk dashboards | Snapshots, not predictions |

### 4.2 Competitive Landscape

**Within Bittensor:**

| Subnet | Focus | Overlap | Differentiation |
|--------|-------|---------|-----------------|
| SN10 (Sturdy) | Yield optimization | Both DeFi | Sturdy = allocation, Sentinel = prediction |
| None | Liquidation prediction | - | Novel subnet category |

**Outside Bittensor:**

| Competitor | What They Do | Gap |
|------------|--------------|-----|
| Gauntlet | Risk modeling for protocols | Not predictive, not decentralized |
| Chaos Labs | Risk simulation | B2B only, not real-time |
| DeFi Saver | Automated protection | Reactive, not predictive |
| Eigenphi | MEV/liquidation analytics | Historical, not predictive |

**Sentinel's positioning:** First decentralized, predictive liquidation intelligence layer.

### 4.3 Why Bittensor?

**1. Prediction markets need decentralization**

Centralized prediction = single point of manipulation. Bittensor's distributed miners ensure no single entity controls predictions.

**2. Objective verification**

Liquidations are on-chain facts. This fits Bittensor's model perfectly - validators verify against ground truth, not subjective judgment.

**3. Continuous improvement incentive**

TAO rewards create ongoing pressure to improve prediction accuracy. Better models = more rewards = more investment in models.

**4. Cold start solved**

dTAO emissions bootstrap the network. Miners are paid from day 1, even before users adopt.

### 4.4 Path to Sustainability

**Revenue streams:**

| Stream | Description | Timeline |
|--------|-------------|----------|
| TAO emissions | Primary revenue | Day 1 |
| API subscriptions | Premium prediction feeds | Month 3+ |
| Alert services | Push notifications for at-risk positions | Month 3+ |
| Protocol partnerships | Risk monitoring for lending protocols | Month 6+ |
| Liquidator partnerships | Priority access to predictions | Month 6+ |

**Unit economics:**

A liquidator who profits $1000/day from better timing would easily pay $100/month for prediction access. With 100 liquidators = $10K/month in subscription revenue alone.

**Long-term thesis:**

Sentinel becomes the default risk intelligence layer for DeFi:
1. Every lending protocol integrates Sentinel alerts
2. Every liquidator subscribes to Sentinel feeds
3. Every borrower gets warnings before liquidation

---

## 5. Go-To-Market Strategy

### 5.1 Initial Target Users

| Segment | Use Case | Value Prop |
|---------|----------|------------|
| **Liquidators** | Timing optimization | Better predictions = more profit |
| **Borrowers** | Risk alerts | Early warning to add collateral |
| **Protocol DAOs** | Risk monitoring | Dashboard for protocol health |
| **Researchers** | Market analysis | Liquidation prediction data |

### 5.2 Distribution Channels

**Direct (B2C):**
- Telegram/Discord bot for alerts
- Web dashboard for monitoring
- Browser extension for DeFi apps

**Indirect (B2B):**
- API for liquidator integration
- SDK for protocol integration
- Data feeds for analytics platforms

**Community:**
- Bittensor Discord
- DeFi Twitter
- Aave/Compound governance forums

### 5.3 Bootstrapping Strategy

**For miners:**

| Incentive | Description |
|-----------|-------------|
| Reference miner | Open-source baseline implementation |
| Historical data | Free training dataset of past liquidations |
| Early bonus | 1.5x scoring for first 30 days |
| Documentation | Comprehensive guides for model building |

**For validators:**

| Incentive | Description |
|-----------|-------------|
| Validator toolkit | Scoring infrastructure + monitoring |
| TAO grants | Grants for early validators |
| Low requirements | Minimal hardware needed |

**For users:**

| Incentive | Description |
|-----------|-------------|
| Free tier | Basic alerts at no cost |
| Accuracy metrics | Public leaderboard of miner performance |
| Open data | Historical predictions freely available |

---

## 6. Technical Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CONSUMERS                                │
│  Liquidators │ Borrowers │ Protocols │ Analytics                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Query Predictions
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SENTINEL SUBNET                            │
│                                                                  │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │   VALIDATORS  │◀───│   BITTENSOR   │───▶│    MINERS     │   │
│  │               │    │    NETWORK    │    │               │   │
│  │ • Snapshot    │    │               │    │ • Monitor     │   │
│  │   positions   │    │ • Yuma        │    │   positions   │   │
│  │ • Verify      │    │   Consensus   │    │ • Predict     │   │
│  │   outcomes    │    │ • Emissions   │    │   liquidations│   │
│  │ • Score       │    │               │    │ • Submit      │   │
│  │   miners      │    │               │    │   forecasts   │   │
│  └───────────────┘    └───────────────┘    └───────────────┘   │
│           │                                        │            │
│           ▼                                        ▼            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    DATA LAYER                            │   │
│  │  • Position data (Aave, Compound, Maker)                 │   │
│  │  • Price feeds (Chainlink, Pyth, on-chain)              │   │
│  │  • Historical liquidations                               │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Monitor Events
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DEFI PROTOCOLS                              │
│  Aave V3 │ Compound V3 │ MakerDAO │ Morpho │ Spark              │
│  (Ethereum, Arbitrum, Optimism, Base, Polygon)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Supported Protocols (Phase 1)

**Lending Protocols:**

| Protocol | Chains | Liquidation Threshold | Notes |
|----------|--------|----------------------|-------|
| Aave V3 | ETH, ARB, OP, BASE | Variable by asset | Primary focus |
| Compound V3 | ETH, ARB, BASE | Per-market | Secondary |
| MakerDAO | ETH | 150% CR typical | CDP model |

**Why start here:**
- Aave V3 has most liquidation volume
- Well-documented APIs and events
- Your existing expertise

**Phase 2 additions:**
- Morpho
- Spark
- Radiant
- Venus (BNB Chain)

---

## 8. Reference Miner Architecture

To lower barriers for Round II, here's a reference miner design:

```python
class SentinelMiner:
    def __init__(self):
        self.position_monitor = PositionMonitor()  # Tracks on-chain positions
        self.price_predictor = PricePredictor()    # Simple volatility model
        self.liquidation_model = LiquidationModel() # Prediction logic

    async def on_epoch(self, snapshot: PositionSnapshot) -> List[Prediction]:
        predictions = []

        for position in snapshot.positions:
            # Skip healthy positions
            if position.health_factor > 1.5:
                continue

            # Predict price movement
            price_scenarios = self.price_predictor.forecast(
                asset=position.collateral_asset,
                hours=6,
                num_scenarios=100
            )

            # Calculate liquidation probability
            liq_probability = 0
            liq_times = []

            for scenario in price_scenarios:
                hf_over_time = self.calculate_health_factor(position, scenario)
                if min(hf_over_time) < 1.0:
                    liq_probability += 1 / len(price_scenarios)
                    liq_times.append(self.find_liquidation_time(hf_over_time))

            # Only predict if probability > threshold
            if liq_probability > 0.3:
                predictions.append(Prediction(
                    position_id=position.id,
                    will_liquidate=True,
                    time_window=self.calculate_window(liq_times),
                    confidence=liq_probability
                ))
            else:
                predictions.append(Prediction(
                    position_id=position.id,
                    will_liquidate=False,
                    confidence=1 - liq_probability
                ))

        return predictions
```

**Improvement vectors for competitive miners:**
- Better price prediction (ML models, sentiment analysis)
- Whale wallet tracking (detect collateral movements)
- Gas price prediction (affects liquidator behavior)
- Cross-protocol correlation (cascading liquidations)

---

## 9. Round II Implementation Plan

| Week | Milestone | Deliverable |
|------|-----------|-------------|
| 1 | Core infrastructure | Position monitoring, event indexing |
| 2 | Miner implementation | Reference miner with basic model |
| 3 | Validator implementation | Scoring logic, Yuma integration |
| 4 | Testing + polish | Testnet deployment, documentation |

**Minimum viable testnet:**
- 1 protocol (Aave V3 on Ethereum)
- 5 miners (including reference)
- 2 validators
- 24-hour observation window
- Basic scoring (precision + recall)

---

## 10. Risk Factors

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Low liquidation volume | Medium | Medium | Expand to more protocols/chains |
| Miner collusion | Low | Medium | Commit-reveal, Yuma Consensus |
| Oracle manipulation | Low | High | Multiple price sources |
| Model homogeneity | Medium | Low | Different scoring periods |
| Regulatory concerns | Low | Low | Information only, no execution |

---

## Summary

Sentinel brings decentralized prediction intelligence to DeFi liquidations.

**Key differentiators:**
1. **Novel subnet category:** No existing Bittensor subnet does liquidation prediction
2. **Objective ground truth:** Liquidations are on-chain facts, not subjective judgments
3. **Clear proof of intelligence:** Accurate prediction requires deep protocol + market understanding
4. **High feasibility:** 100% on-chain data, no external infrastructure required
5. **Real market need:** Liquidators, borrowers, and protocols all benefit

**Why this wins:**
- Directly applicable to $30B+ lending market
- Crystal clear validation mechanism
- Buildable in 4 weeks for Round II
- Leverages your Aave/DeFi expertise

**The pitch:** Every DeFi liquidation represents both a risk and an opportunity. Sentinel ensures the right people get warned, and the best predictors get rewarded.
