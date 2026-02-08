# Vigil Pitch Deck (10 Pages)

---

## Page 1: Title

**Vigil**

*Decentralized Liquidation Prediction*

Bittensor Subnet Proposal

---

## Page 2: The Problem

**$2.4 billion liquidated in DeFi last year.**

Borrowers had no warning.
Liquidators with private bots won everything.

```
User deposits $100K collateral
     ↓
Market drops 20%
     ↓
Health factor crosses 1.0
     ↓
Liquidated. $10K penalty. No warning.
```

**The prediction intelligence exists.**
**It's just locked in private bots.**

---

## Page 3: The Solution

**Vigil: Miners compete to predict liquidations.**

```
Miners predict     →    Validators verify    →    Accurate miners
which positions         against on-chain          earn TAO
will liquidate          liquidation events
```

**Decentralized liquidation intelligence.**

Anyone can access it.
Best predictors earn the most.

---

## Page 4: How It Works

**Every hour:**

1. Validators snapshot at-risk positions
2. Miners predict: which will liquidate?
3. 6-hour observation window
4. Match predictions to reality
5. Score miners (rolling 24-hour aggregation)
6. TAO distributed

**Scoring:**

| Dimension | Weight | Anti-Gaming |
|-----------|--------|-------------|
| Precision | 40% | Prevents "predict everything" |
| Recall | 30% | Prevents "predict nothing" |
| Lead Time | 20% | Requires 50%+ precision first |
| Calibration | 10% | 3-bin system for noisy data |

---

## Page 5: Key Mechanism Innovations

**Danger Zone Partial Credit**

Predicted liquidation + position hit HF < 1.02 but was rescued = 0.5 credit

Fairer scoring. More data points.

**Rolling 24-Hour Aggregation**

5-10 liquidations/day = noisy per-epoch scoring.
24-hour window = 50-200+ data points = statistical significance.

**Lead Time Threshold**

Wild early guesses to farm bonus?
Lead time bonus only activates at 50%+ precision.

---

## Page 6: Why It's Verifiable

**Liquidations are on-chain facts.**

| Data | Source |
|------|--------|
| Did it liquidate? | Transaction hash |
| When? | Block timestamp |
| Danger zone hit? | HF history |

**No subjectivity. No disputes.**

Validators verify facts, not judge quality.

---

## Page 7: Business Model

**Who pays?**

| Customer | Product | Why They Pay |
|----------|---------|--------------|
| Borrowers | Alerts | Avoid 5-15% penalty |
| Liquidators | API | Better timing |
| Protocols | Dashboard | Risk monitoring |

**Why don't miners just liquidate themselves?**

Prediction ≠ Execution.

| Prediction | Liquidation |
|------------|-------------|
| Analysis skills | Capital ($100K+) |
| Data infrastructure | MEV infrastructure |
| Steady TAO income | Variable profits |

**Vigil commoditizes prediction. Liquidators compete on execution.**

---

## Page 8: Differentiation

**vs SN10 (Sturdy):**

| Sturdy | Vigil |
|--------|----------|
| Maximize yield (offense) | Predict risk (defense) |
| Continuous optimization | Discrete event prediction |
| Performance over weeks | Outcome within hours |

**vs Outside Bittensor:**

| Competitor | Gap |
|------------|-----|
| DeFi Saver | Reactive, not predictive |
| Gauntlet | Centralized, B2B only |
| Private bots | Proprietary |

**Vigil = first decentralized, predictive liquidation intelligence.**

---

## Page 9: Round II Plan

**4 weeks. Protocol-agnostic architecture. Aave + Compound + Morpho = 65% of lending market.**

| Week | Deliverable |
|------|-------------|
| 1 | Adapter interface + Aave V3 adapter |
| 2 | Compound V3 adapter + Morpho adapter |
| 3 | Validator scoring (protocol-agnostic) + danger zone |
| 4 | Testing + documentation |

**Protocol Adapter Interface:**

Each protocol defines: prediction window, risk metric, liquidation events.
Scoring logic is protocol-agnostic. Add new protocols by implementing one interface.

```
Round II:     Aave (6h) + Compound (6h) + Morpho (6h)
Future:       Maker (24h window, auction-start prediction)
```

**Historical Replay Mode:**

Testnet has no liquidations?
→ Use mainnet data from 30 days ago
→ Score against known outcomes

---

## Page 10: Summary

**Vigil** = Decentralized liquidation prediction.

**Problem:** $2.4B liquidated, no warning.

**Solution:** Miners predict, validators verify, TAO rewards accuracy.

**Key innovations:**
- Protocol-agnostic adapter architecture (Aave + Compound + Morpho = 65% market)
- Danger zone partial credit for rescued positions
- Rolling 24-hour aggregation for statistical significance
- Historical replay mode for testnet validation

**Why Bittensor:** Proof of intelligence + objective verification.

**Why now:** Novel use case. No existing subnet.

---

**Links:**
- Full Proposal: [link]
- Video: [link]
- Twitter: [link]
