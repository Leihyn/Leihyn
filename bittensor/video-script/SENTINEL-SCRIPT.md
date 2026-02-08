# Sentinel Video Script (5-8 min)

## Before Recording

- [ ] Pitch deck slides ready
- [ ] Architecture diagram exported
- [ ] Scoring example prepared
- [ ] Screen recording software
- [ ] Quiet environment

---

## The Hook (40 sec)

**[Show: Liquidation stats or visualization]**

> "Two point four billion dollars. That's how much was liquidated across DeFi last year.
>
> When a position gets liquidated, two people lose. The borrower loses ten percent to penalties - often with zero warning. And the slow liquidator loses to whoever got there first.
>
> The only winners are liquidators with proprietary prediction systems. They know which positions will liquidate before anyone else.
>
> That prediction intelligence exists. But it's locked inside private bots.
>
> Today I'm introducing Sentinel - a Bittensor subnet that decentralizes liquidation prediction."

---

## What We're Building (1 min)

**[Show: Solution overview slide]**

> "Sentinel is simple: miners compete to predict which DeFi positions will be liquidated, and when.
>
> Validators verify those predictions against actual on-chain liquidation events.
>
> If you predict accurately, you earn TAO. If you cry wolf, you get penalized.
>
> The result is a decentralized network that surfaces liquidation risk before it happens.
>
> This serves three groups: Liquidators get better timing. Borrowers get early warnings. Protocols get risk visibility."

---

## How It Works (2 min)

**[Show: Flow diagram]**

> "Let me walk through the mechanism."

### The Epoch Cycle

> "Every hour, a new prediction epoch begins.
>
> First, validators snapshot all at-risk positions across Aave, Compound, and Maker. These are positions with health factors below one-point-five - close enough to liquidation to be worth predicting.
>
> Miners then have ten minutes to analyze these positions and submit predictions. For each position, they predict: will it be liquidated? If yes, when? And how confident are they?
>
> Predictions are committed as hashes first - this prevents copying. Then revealed."

### The Observation Window

> "After predictions are submitted, there's a six-hour observation window.
>
> During this time, the network watches for actual liquidation events. When a position gets liquidated, we record the transaction hash, the timestamp, and the amount.
>
> After six hours, we compare predictions to reality."

### Scoring

**[Show: Scoring breakdown]**

> "Scoring has four components.
>
> Precision - thirty-five percent. This measures: of the liquidations you predicted, how many actually happened? If you predict everything will liquidate, your precision will be low.
>
> Recall - twenty-five percent. This measures: of the liquidations that happened, how many did you predict? Missing liquidations hurts your score.
>
> Lead time - twenty-five percent. Earlier predictions are more valuable. Predicting a liquidation six hours early gets a two-x bonus. Predicting one hour early gets almost no bonus.
>
> Calibration - fifteen percent. If you say you're seventy percent confident, you should be right seventy percent of the time. This rewards honest uncertainty."

---

## Why This Works on Bittensor (1 min)

**[Show: Verification slide]**

> "Here's why Sentinel is a perfect fit for Bittensor.
>
> Liquidations are on-chain facts. There's no subjectivity. Either a position was liquidated or it wasn't. Either it happened when you predicted or it didn't.
>
> This means validators don't need to judge quality - they just verify facts. The transaction hash proves the liquidation happened. The block timestamp proves when.
>
> Compare this to something like image generation, where 'quality' is subjective. Sentinel has objective ground truth, which makes the incentive mechanism much cleaner.
>
> The only way to earn TAO is to actually predict liquidations accurately. You can't game it."

---

## Anti-Gaming (45 sec)

**[Show: Anti-gaming mechanisms]**

> "Three mechanisms prevent gaming.
>
> One: Minimum lead time. Predictions must come at least one hour before the event. You can't just watch for positions at health factor one-point-zero-zero-one and call it a prediction.
>
> Two: Precision penalty. If you predict that every position will liquidate, sure, you'll catch all the actual liquidations. But your precision will be terrible, and your score will tank.
>
> Three: Commit-reveal. Miners commit a hash of their predictions before revealing. You can't wait to see what other miners predicted and copy them."

---

## Feasibility (1 min)

**[Show: Feasibility checklist]**

> "Let me address feasibility directly, because this matters for Round II.
>
> Data access: Everything Sentinel needs is on-chain. Position data, price feeds, liquidation events - all accessible via standard RPCs. No external APIs, no proprietary data sources.
>
> Ground truth: Binary and verifiable. The liquidation either happened or it didn't. No ambiguity.
>
> Infrastructure: Validators and miners need standard servers. No GPUs required. This is about prediction models, not compute power.
>
> Expertise fit: I have direct experience with Aave and lending protocol integration. This is my domain.
>
> I can build a working testnet implementation in four weeks. Week one: position monitoring. Week two: reference miner. Week three: validator scoring. Week four: deployment and testing."

---

## The Close (30 sec)

**[Show: Summary slide]**

> "Sentinel decentralizes liquidation intelligence.
>
> Miners compete on prediction accuracy. Validators verify against on-chain facts. Users get early warnings and better information.
>
> No proprietary advantages. No information asymmetry. Just the best predictions, rewarded with TAO.
>
> Thanks for watching. The full proposal and pitch deck are linked below. I'm excited to build this and I hope you'll follow along."

**[Show: Contact info + links]**

---

## Recording Notes

- Total target: 6-7 minutes
- Keep energy up - this is a pitch, not a lecture
- Use the scoring example to make it concrete
- Emphasize feasibility - judges care about Round II
- Practice the anti-gaming section - it's crucial for credibility
