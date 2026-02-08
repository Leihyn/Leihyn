# Vigil Talk Track (7 min)

Print this or have it on your phone while recording.

---

## HOOK (30 sec) — Slide 2

- "$2.4 billion liquidated in DeFi last year"
- Borrowers had NO warning
- Liquidators with private bots won everything
- The intelligence exists — locked in private systems
- "I'm introducing Vigil"

---

## WHAT VIGIL DOES (45 sec) — Slide 4

- Miners PREDICT which positions will liquidate
- Validators VERIFY against on-chain events
- Accurate predictions earn TAO
- "Where does TAO come from? Network emissions — like Bitcoin mining rewards"
- Result: decentralized liquidation intelligence

---

## HOW IT WORKS (1.5 min) — Slide 5

**The flow:**
- Every hour, new epoch
- Validators snapshot at-risk positions (HF between 1.0 and 1.5)
- Miners have 10 minutes to analyze and submit
- Observation window starts AFTER predictions lock
- 6 hours later, check what happened

**Scoring (point to table):**
- Precision 40% — "of your predictions, how many were right?"
- Recall 30% — "of liquidations that happened, how many did you catch?"
- Lead time 20% — earlier = better, BUT needs 50%+ precision first
- Calibration 10% — does your confidence match reality?

**Key point:** Scores aggregated over rolling 24 hours for statistical significance

---

## KEY INNOVATIONS (1.5 min) — Slide 6

**Danger zone partial credit:**
- Miner predicts liquidation
- User adds collateral, saves position
- Was miner wrong? Not if HF dropped below 1.02
- Half credit for danger zone hits
- "Fairer scoring, more data points"

**HF history tracking:**
- Health Factor = liquidation risk metric
- We track it over time via archive nodes
- Can prove position entered danger zone

**Rolling 24h aggregation:**
- Only 5-10 liquidations per day
- Per-epoch scoring too noisy
- 24-hour window = 50-200 data points

---

## WHY VERIFIABLE (45 sec) — Slide 7

- Liquidations are ON-CHAIN FACTS
- Did it liquidate? → transaction hash
- When? → block timestamp
- Danger zone hit? → HF history from archive node
- "No subjectivity. No disputes. Validators verify facts, not judge quality."

---

## BUSINESS MODEL (30 sec) — Slide 8

**Who pays:**
- Borrowers → alerts (avoid 5-15% penalty)
- Liquidators → API (better timing)
- Protocols → dashboards (risk monitoring)

**Quick answer to "why don't miners just liquidate themselves?"**
- Prediction ≠ Execution
- Different skills, different capital requirements
- Vigil commoditizes prediction

---

## ROUND II PLAN (1 min) — Slide 10

**Scope:** Aave + Compound + Morpho = 65% of lending market

**Why not Maker?** Auction-based liquidations, different model. Architecture supports it, documented for post-hackathon.

**4 weeks:**
- Week 1: Adapter interface + Aave adapter
- Week 2: Compound + Morpho adapters
- Week 3: Validator scoring (protocol-agnostic)
- Week 4: Testing + historical replay

**Historical replay:** Testnet has no liquidations? Use mainnet data from 30 days ago. Proves mechanism works.

---

## CLOSE (30 sec) — Slide 11

- Vigil = decentralized liquidation prediction
- Miners compete on accuracy
- Validators verify on-chain facts
- Novel use case — no subnet does this
- Objectively verifiable
- Buildable in 4 weeks

"Thanks for watching. Full proposal linked below."

---

## RECORDING REMINDERS

- Speak SLOWLY (feels slow, sounds normal)
- Pause between sections
- If you mess up, pause, restart that sentence
- Water nearby
- Notifications OFF
