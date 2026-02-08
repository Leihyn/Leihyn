# Sentinel Pitch Deck (10 Pages)

---

## Page 1: Title

**Sentinel**

*Decentralized Liquidation Intelligence*

A Bittensor Subnet Proposal

[Your name / Team]

---

## Page 2: The Problem

**DeFi liquidations are a $2.4B blind spot.**

A whale deposits $10M into Aave.
Market drops 15%.
Health factor hits 1.02.

**Two people are about to lose:**

1. **The borrower** - No warning. Loses 10% to liquidation penalty.
2. **The slow liquidator** - Someone else gets there first.

**The only winners:** Liquidators with proprietary prediction systems.

| Who Loses | Annual Cost |
|-----------|-------------|
| Borrowers (penalties) | ~$200M |
| Slow liquidators (missed profits) | ~$500M |
| Protocols (bad UX, user churn) | Unquantified |

*Prediction intelligence exists, but it's locked in private bots.*

---

## Page 3: The Solution

**Sentinel: Competition for the best predictions.**

Miners compete to predict which DeFi positions will be liquidated - and when.

Validators verify predictions against actual on-chain liquidations.

Better predictions = more TAO.

```
Position Data → Miners Predict → Liquidation Happens → Score Against Reality
```

**Result:** A decentralized network that surfaces liquidation risk before it happens.

---

## Page 4: How It Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ VALIDATORS  │────▶│   MINERS    │────▶│GROUND TRUTH │
│             │     │             │     │             │
│ Broadcast   │     │ Analyze     │     │ Actual      │
│ position    │     │ positions,  │     │ liquidation │
│ snapshots   │     │ predict     │     │ events      │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────────────────────┐
                    │   SCORE = f(predictions,    │
                    │              actual events) │
                    └─────────────────────────────┘
```

**Every hour:**
1. Validators snapshot at-risk positions
2. Miners submit predictions (which will liquidate, when)
3. 6-hour observation window
4. Compare predictions to actual liquidations
5. Score: precision, recall, lead time, confidence calibration
6. TAO distributed to accurate miners

---

## Page 5: Why It's Verifiable

**Liquidations are on-chain facts.**

Unlike subjective AI tasks, every prediction has a binary outcome:

| Prediction | Outcome | Score Impact |
|------------|---------|--------------|
| "Will liquidate in 4 hours" | Liquidated in 3 hours | True positive + timing bonus |
| "Will liquidate in 4 hours" | Not liquidated | False positive - penalty |
| "Won't liquidate" | Liquidated | False negative - penalty |
| "Won't liquidate" | Not liquidated | True negative |

**No subjective judgment. No gaming. Just accuracy.**

---

## Page 6: Scoring Mechanism

**Precision + Recall + Lead Time + Calibration**

| Dimension | Weight | Why It Matters |
|-----------|--------|----------------|
| Precision | 35% | Don't cry wolf |
| Recall | 25% | Don't miss liquidations |
| Lead Time | 25% | Earlier = more useful |
| Calibration | 15% | Confidence should be honest |

**Anti-gaming:**

- **Minimum lead time:** Must predict 1+ hour before event
- **Precision penalty:** Predicting everything = low precision = low score
- **Commit-reveal:** Can't copy other miners
- **Timestamps:** Earlier predictions win ties

---

## Page 7: Market Opportunity

**DeFi lending: $30B+ TVL**

| Protocol | TVL | Liquidation Volume (2024) |
|----------|-----|---------------------------|
| Aave V3 | $12B | $800M+ |
| Compound | $3B | $200M+ |
| MakerDAO | $8B | $300M+ |
| Others | $7B+ | $400M+ |

**Three paying customers:**

1. **Liquidators** - Pay for timing edge
2. **Borrowers** - Pay for early warnings
3. **Protocols** - Pay for risk monitoring

**Conservative estimate:** 100 liquidators × $100/month = $10K MRR baseline

---

## Page 8: Competitive Landscape

```
                        PREDICTIVE
                             │
                             │  ← Sentinel
                             │
    ┌────────────────────────┼────────────────────────┐
    │                        │                        │
CENTRALIZED ─────────────────┼───────────────────── DECENTRALIZED
    │                        │                        │
    │   Gauntlet, Chaos Labs │                        │
    │   (B2B risk models)    │                        │
    │                        │                        │
    └────────────────────────┼────────────────────────┘
                             │
                             │  DeFi Saver, Instadapp
                        REACTIVE
```

**Our positioning:** Predictive + Decentralized

No one else occupies this quadrant.

---

## Page 9: Feasibility

**Why this is buildable in 4 weeks (Round II):**

| Requirement | Status |
|-------------|--------|
| Data access | 100% on-chain - just need RPC |
| Ground truth | Binary - liquidation happened or not |
| Infrastructure | Minimal - no external APIs needed |
| Hardware | Standard servers - no GPUs |
| Expertise fit | Direct Aave/lending protocol experience |

**Week-by-week plan:**

| Week | Deliverable |
|------|-------------|
| 1 | Position monitoring + event indexing |
| 2 | Reference miner implementation |
| 3 | Validator scoring logic |
| 4 | Testnet deployment + docs |

---

## Page 10: The Ask

**Building the liquidation intelligence layer for DeFi.**

Sentinel turns prediction from a zero-sum game into a decentralized market.

**What we're building toward:**
- Every borrower gets warned before liquidation
- Every liquidator competes on prediction, not just speed
- Every protocol has real-time risk visibility

**Next steps:**
1. Round I: Finalize mechanism design (this proposal)
2. Round II: Testnet implementation
3. Mainnet: Scale to all major lending protocols

---

**Contact:**
[Your contact info]

**Links:**
- Full Proposal: [link]
- Video Walkthrough: [link]
- Twitter: [handle]
